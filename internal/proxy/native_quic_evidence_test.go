package proxy

import (
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/require"
)

// Test-only key export and datagram capture, following PacketSafari's isolated
// tlsfixture contract. No listener, logging or secret export in production.
type quicEvidence struct {
	mu            sync.Mutex
	packets, keys *os.File
}

func (e *quicEvidence) packet(payload []byte, outbound bool) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	// DLT_RAW IPv4 with an optional UDP checksum (zero). Synthetic addresses
	// describe the two ends of the authenticated datagram channel.
	b := make([]byte, 28+len(payload))
	b[0] = 0x45
	b[8] = 64
	b[9] = 17
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	copy(b[12:16], []byte{127, 0, 0, 1})
	copy(b[16:20], []byte{127, 0, 0, 2})
	source, destination := uint16(45000), uint16(443)
	if !outbound {
		source, destination = destination, source
		b[15], b[19] = b[19], b[15]
	}
	var checksum uint32
	for i := 0; i < 20; i += 2 {
		checksum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	for checksum>>16 != 0 {
		checksum = (checksum & 65535) + (checksum >> 16)
	}
	binary.BigEndian.PutUint16(b[10:12], ^uint16(checksum))
	binary.BigEndian.PutUint16(b[20:22], source)
	binary.BigEndian.PutUint16(b[22:24], destination)
	binary.BigEndian.PutUint16(b[24:26], uint16(8+len(payload)))
	copy(b[28:], payload)
	now := time.Now()
	header := []uint32{uint32(now.Unix()), uint32(now.Nanosecond() / 1000), uint32(len(b)), uint32(len(b))}
	if err := binary.Write(e.packets, binary.LittleEndian, header); err != nil {
		return err
	}
	_, err := e.packets.Write(b)
	return err
}

type evidencePacketConn struct {
	net.PacketConn
	evidence *quicEvidence
}

func (c *evidencePacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, a, err := c.PacketConn.ReadFrom(b)
	if err == nil {
		err = c.evidence.packet(b[:n], false)
	}
	return n, a, err
}
func (c *evidencePacketConn) WriteTo(b []byte, a net.Addr) (int, error) {
	if err := c.evidence.packet(b, true); err != nil {
		return 0, err
	}
	return c.PacketConn.WriteTo(b, a)
}

func TestNativeQUICPacketEvidence(t *testing.T) {
	dir := os.Getenv("NOSY_QUIC_EVIDENCE_DIR")
	if dir == "" {
		t.Skip("explicit isolated packet evidence directory required")
	}
	require.NoError(t, os.MkdirAll(dir, 0700))
	packets, err := os.OpenFile(filepath.Join(dir, "inspection.pcap"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	require.NoError(t, err)
	keys, err := os.OpenFile(filepath.Join(dir, "test.keys"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, packets.Close()); require.NoError(t, keys.Close()) })
	require.NoError(t, binary.Write(packets, binary.LittleEndian, []uint32{0xa1b2c3d4, 0x00040002, 0, 0, 65535, 101}))
	_, addr, target, roots, _ := quicFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "HTTP/3.0", r.Proto)
		_, _ = io.WriteString(w, "verified HTTP/3 application data")
	}))
	client := quicClientEvidence(t, addr, target, strings.Repeat("e", 64), roots, quic.Version1, &quicEvidence{packets: packets, keys: keys})
	res, err := client.Get("https://localhost/proof")
	require.NoError(t, err)
	b, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	require.NoError(t, res.Body.Close())
	require.Equal(t, "verified HTTP/3 application data", string(b))
	require.NoError(t, packets.Sync())
	require.NoError(t, keys.Sync())
	if tshark := os.Getenv("NOSY_TEST_TSHARK"); tshark != "" {
		args := []string{"-r", filepath.Join(dir, "inspection.pcap"), "-Y", "http3.headers.method || http3.headers.status", "-T", "fields", "-e", "http3.headers.method", "-e", "http3.headers.path", "-e", "http3.headers.status"}
		opaque, err := exec.Command(tshark, args...).Output()
		require.NoError(t, err)
		require.Empty(t, strings.TrimSpace(string(opaque)))
		args = append(args, "-o", "tls.keylog_file:"+filepath.Join(dir, "test.keys"))
		decoded, err := exec.Command(tshark, args...).Output()
		require.NoError(t, err)
		require.Contains(t, string(decoded), "GET\t/proof")
		require.Contains(t, string(decoded), "200")
		ids, err := exec.Command(tshark, "-r", filepath.Join(dir, "inspection.pcap"), "-Y", "ip.src == 127.0.0.1 && quic.dcid", "-T", "fields", "-e", "quic.dcid").Output()
		require.NoError(t, err)
		unique := map[string]bool{}
		for _, id := range strings.FieldsFunc(string(ids), func(r rune) bool { return r == ',' || r == '\n' || r == '\r' }) {
			unique[id] = true
		}
		require.GreaterOrEqual(t, len(unique), 2, "Initial to server-issued CID transition must survive forwarding")
		t.Log("independent packet proof: no HTTP/3 headers without keys; GET /proof and status 200 with isolated keys")
	}
}
