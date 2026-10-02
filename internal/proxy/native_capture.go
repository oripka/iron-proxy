package proxy

// Targeted capture records one client-facing TLS stream. Packet boundaries,
// addresses and TCP acknowledgements are reconstructed, never wire evidence.
import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

const captureLimit = 16 << 20

type captureTarget struct {
	App        string `json:"app"`
	Endpoint   string `json:"endpoint"`
	ServerName string `json:"serverName"`
}
type captureStatus struct {
	ID     string `json:"id"`
	State  string `json:"state"`
	Reason string `json:"reason"`
	Flow   string `json:"flow"`
	Bytes  int    `json:"bytes"`
	Keys   int    `json:"keys"`
}
type nativeCapture struct {
	exporting bool
	mu        sync.Mutex
	target    captureTarget
	status    captureStatus
	data      bytes.Buffer
	keys      bytes.Buffer
	seq       [2]uint32
	timer     *time.Timer
}

func (c *nativeCapture) finishLocked(reason string) {
	if c.status.State == "armed" || c.status.State == "capturing" {
		c.status.State = "ready"
		c.status.Reason = reason
		if c.timer != nil {
			c.timer.Stop()
		}
		id := c.status.ID
		c.timer = time.AfterFunc(5*time.Minute, func() {
			c.mu.Lock()
			defer c.mu.Unlock()
			if c.status.ID == id {
				c.clearLocked()
			}
		})
	}
}
func (c *nativeCapture) clearLocked() {
	if c.timer != nil {
		c.timer.Stop()
		c.timer = nil
	}
	clear(c.data.Bytes())
	clear(c.keys.Bytes())
	c.data = bytes.Buffer{}
	c.keys = bytes.Buffer{}
	c.status = captureStatus{}
	c.target = captureTarget{}
}
func (c *nativeCapture) control(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	defer c.mu.Unlock()
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	if r.Method == "POST" && r.URL.Path == "/nosy/capture" {
		if c.status.ID != "" {
			http.Error(w, "discard previous capture first", 409)
			return
		}
		var target captureTarget
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024))
		dec.DisallowUnknownFields()
		if dec.Decode(&target) != nil || dec.Decode(new(any)) != io.EOF {
			http.Error(w, "invalid target", 400)
			return
		}
		app, err := hex.DecodeString(target.App)
		ip, port, e := net.SplitHostPort(target.Endpoint)
		if err != nil || len(app) != 32 || e != nil || net.ParseIP(ip) == nil || port != "443" || len(target.ServerName) > 253 {
			http.Error(w, "invalid target", 400)
			return
		}
		var id [16]byte
		if _, err := rand.Read(id[:]); err != nil {
			http.Error(w, "capture unavailable", 500)
			return
		}
		c.target = target
		c.status = captureStatus{ID: hex.EncodeToString(id[:]), State: "armed"}
		c.seq = [2]uint32{1, 1}
		captureID := c.status.ID
		c.timer = time.AfterFunc(time.Minute, func() {
			c.mu.Lock()
			defer c.mu.Unlock()
			if c.status.ID == captureID {
				c.finishLocked("No matching connection within 60 seconds")
			}
		})
	} else {
		if c.status.ID == "" || r.URL.Query().Get("id") != c.status.ID {
			http.Error(w, "capture unavailable", 404)
			return
		}
		switch {
		case r.Method == "GET" && r.URL.Path == "/nosy/capture":
		case r.Method == "POST" && r.URL.Path == "/nosy/capture/stop":
			c.finishLocked("Stopped by user")
		case r.Method == "DELETE" && r.URL.Path == "/nosy/capture":
			c.clearLocked()
		case r.Method == "GET" && r.URL.Path == "/nosy/capture/export":
			if c.exporting {
				http.Error(w, "export already in progress", 409)
				return
			}
			if c.status.State != "ready" || c.keys.Len() == 0 || c.data.Len() == 0 {
				http.Error(w, "no decryptable stream available", 409)
				return
			}
			// Copy under the lock, then release before writing to a potentially slow client.
			var output bytes.Buffer
			// Place secrets before packets so single-pass readers can decrypt.
			raw := c.data.Bytes()
			headerEnd := int(binary.LittleEndian.Uint32(raw[4:]))
			output.Write(raw[:headerEnd])
			body := make([]byte, 8)
			binary.LittleEndian.PutUint32(body, 0x544c534b)
			binary.LittleEndian.PutUint32(body[4:], uint32(c.keys.Len()))
			body = append(body, c.keys.Bytes()...)
			output.Write(captureBlock(10, body))
			output.Write(raw[headerEnd:])
			w.Header().Set("Content-Type", "application/octet-stream")
			c.exporting = true
			c.mu.Unlock()
			_, err := w.Write(output.Bytes())
			clear(output.Bytes())
			c.mu.Lock()
			c.exporting = false
			if err != nil {
				return
			} // HTTP client cancellation; retained capture can be retried.
			return
		default:
			http.Error(w, "unsupported capture operation", 405)
			return
		}
	}
	if err := json.NewEncoder(w).Encode(c.status); err != nil {
		return
	} // Client disconnected.
}
func (c *nativeCapture) begin(app, endpoint, name, flow string) *captureStream {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.status.State != "armed" || c.target.App != app || c.target.Endpoint != endpoint || (c.target.ServerName != "" && c.target.ServerName != name) {
		return nil
	}
	c.timer.Stop()
	c.data.Grow(captureLimit)
	c.keys.Grow(65536)
	c.status.State = "capturing"
	c.status.Flow = flow
	id := c.status.ID
	c.timer = time.AfterFunc(2*time.Minute, func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.status.ID == id {
			c.finishLocked("Two-minute capture limit reached")
		}
	})
	header := make([]byte, 16)
	binary.LittleEndian.PutUint32(header, 0x1a2b3c4d)
	binary.LittleEndian.PutUint16(header[4:], 1)
	binary.LittleEndian.PutUint64(header[8:], ^uint64(0))
	note, err := json.Marshal(map[string]string{"format": "Nosy reconstructed client-facing TLS stream", "limitations": "Synthetic IP addresses, TCP acknowledgements, packet boundaries and timing; not original wire packets. Contains TLS secrets.", "flow": flow, "originalEndpoint": endpoint, "serverName": name})
	if err == nil { // String-only metadata has no unsupported JSON values.
		option := make([]byte, 4)
		binary.LittleEndian.PutUint16(option, 1)
		binary.LittleEndian.PutUint16(option[2:], uint16(len(note)))
		header = append(header, option...)
		header = append(header, note...)
		for len(header)%4 != 0 {
			header = append(header, 0)
		}
		header = append(header, 0, 0, 0, 0)
	}
	c.data.Write(captureBlock(0x0a0d0d0a, header))
	iface := make([]byte, 8)
	binary.LittleEndian.PutUint16(iface, 101)
	binary.LittleEndian.PutUint32(iface[4:], 65535)
	c.data.Write(captureBlock(1, iface))
	// Synthetic handshake establishes direction and sequence numbers for Wireshark.
	c.packetLocked(0, nil, 2)
	c.packetLocked(1, nil, 18)
	c.packetLocked(0, nil, 16)
	return &captureStream{owner: c, id: id}
}

type captureStream struct {
	owner *nativeCapture
	id    string
}

func (s *captureStream) finish() {
	if s == nil {
		return
	}
	c := s.owner
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.status.ID == s.id {
		c.finishLocked("Connection ended")
	}
}
func (s *captureStream) Write(p []byte) (int, error) { // tls.Config.KeyLogWriter; capture failure must not break traffic.
	c := s.owner
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.status.ID == s.id && c.status.State == "capturing" {
		if c.keys.Len()+len(p) > 65536 {
			c.finishLocked("TLS key limit reached")
		} else {
			c.keys.Write(p)
			c.status.Keys++
		}
	}
	return len(p), nil
}
func (s *captureStream) record(direction int, p []byte) {
	if s == nil {
		return
	}
	c := s.owner
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.status.ID != s.id || c.status.State != "capturing" {
		return
	}
	for len(p) > 0 {
		n := min(len(p), 16384)
		if c.data.Len()+n+80 > captureLimit {
			c.finishLocked("16 MiB capture limit reached")
			return
		}
		c.packetLocked(direction, p[:n], 24)
		p = p[n:]
	}
	c.status.Bytes = c.data.Len()
}

type captureConn struct {
	net.Conn
	capture *captureStream
}

func (c *captureConn) Read(p []byte) (int, error) {
	n, e := c.Conn.Read(p)
	c.capture.record(0, p[:n])
	return n, e
}
func (c *captureConn) Write(p []byte) (int, error) {
	n, e := c.Conn.Write(p)
	c.capture.record(1, p[:n])
	return n, e
}
func captureBlock(kind uint32, body []byte) []byte {
	size := 12 + (len(body)+3)&^3
	out := make([]byte, size)
	binary.LittleEndian.PutUint32(out, kind)
	binary.LittleEndian.PutUint32(out[4:], uint32(size))
	copy(out[8:], body)
	binary.LittleEndian.PutUint32(out[size-4:], uint32(size))
	return out
}
func checksum(p []byte) uint16 {
	var sum uint32
	for len(p) > 1 {
		sum += uint32(binary.BigEndian.Uint16(p))
		p = p[2:]
	}
	if len(p) > 0 {
		sum += uint32(p[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 65535) + (sum >> 16)
	}
	return ^uint16(sum)
}
func (c *nativeCapture) packetLocked(d int, p []byte, flags byte) {
	packet := make([]byte, 40+len(p))
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:], uint16(len(packet)))
	packet[8] = 64
	packet[9] = 6
	copy(packet[12:], []byte{192, 0, 2, 1})
	copy(packet[16:], []byte{192, 0, 2, 2})
	src, dst := uint16(49152), uint16(443)
	if d == 1 {
		copy(packet[12:], []byte{192, 0, 2, 2})
		copy(packet[16:], []byte{192, 0, 2, 1})
		src, dst = dst, src
	}
	binary.BigEndian.PutUint16(packet[10:], checksum(packet[:20]))
	binary.BigEndian.PutUint16(packet[20:], src)
	binary.BigEndian.PutUint16(packet[22:], dst)
	seq := c.seq[d]
	if flags&2 != 0 {
		seq = 0
	}
	binary.BigEndian.PutUint32(packet[24:], seq)
	if flags&16 != 0 {
		binary.BigEndian.PutUint32(packet[28:], c.seq[1-d])
	}
	packet[32] = 0x50
	packet[33] = flags
	binary.BigEndian.PutUint16(packet[34:], 65535)
	copy(packet[40:], p)
	pseudo := make([]byte, 12)
	copy(pseudo, packet[12:20])
	pseudo[9] = 6
	binary.BigEndian.PutUint16(pseudo[10:], uint16(len(packet)-20))
	pseudo = append(pseudo, packet[20:]...)
	binary.BigEndian.PutUint16(packet[36:], checksum(pseudo))
	c.seq[d] += uint32(len(p))
	body := make([]byte, 20)
	now := uint64(time.Now().UnixMicro())
	binary.LittleEndian.PutUint32(body[4:], uint32(now>>32))
	binary.LittleEndian.PutUint32(body[8:], uint32(now))
	binary.LittleEndian.PutUint32(body[12:], uint32(len(packet)))
	binary.LittleEndian.PutUint32(body[16:], uint32(len(packet)))
	body = append(body, packet...)
	c.data.Write(captureBlock(6, body))
	c.status.Bytes = c.data.Len()
}

var _ io.Writer = (*captureStream)(nil)
