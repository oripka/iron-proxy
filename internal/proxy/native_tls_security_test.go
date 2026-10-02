package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type securityLog struct {
	sync.Mutex
	bytes.Buffer
}

func (b *securityLog) Write(p []byte) (int, error) {
	b.Lock()
	defer b.Unlock()
	return b.Buffer.Write(p)
}
func (b *securityLog) events(t *testing.T) []map[string]any {
	t.Helper()
	b.Lock()
	defer b.Unlock()
	var events []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(b.Buffer.String()), "\n") {
		if line == "" {
			continue
		}
		var event map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &event))
		if event["msg"] == "native_tls_security" {
			events = append(events, event)
		}
	}
	return events
}
func TestNativeTLSSecurityBoundsAndSuccessfulEvidence(t *testing.T) {
	log := &securityLog{}
	report := nativeTLSReporter(slog.New(slog.NewJSONHandler(log, nil)), "flow", "revision", "session")
	report("client", tls.ConnectionState{})
	require.Empty(t, log.events(t))
	var wg sync.WaitGroup
	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			report("client", tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13, CipherSuite: tls.TLS_AES_128_GCM_SHA256, CurveID: tls.X25519MLKEM768, NegotiatedProtocol: "h2"})
		}()
	}
	wg.Wait()
	require.Len(t, log.events(t), 1)
	for i := 0; i < 30; i++ {
		report("upstream", tls.ConnectionState{HandshakeComplete: true, Version: tls.VersionTLS13, CurveID: tls.CurveID(i), NegotiatedProtocol: "private-protocol"})
	}
	events := log.events(t)
	require.Len(t, events, 10)
	require.Equal(t, true, events[9]["truncated"])
	require.Equal(t, "other", events[1]["tls"].(map[string]any)["alpn"])
	require.NotContains(t, log.Buffer.String(), "private-protocol")
}
func TestNativeTLSSecurityReportsBothActualHandshakeLegs(t *testing.T) {
	p, addr, target, pool, _ := nativeFixture(t, true)
	log := &securityLog{}
	p.logger = slog.New(slog.NewJSONHandler(log, nil))
	conn, err := nativeConnectVersion(t, addr, target, strings.Repeat("b", 64), pool, "localhost", "X-Nosy-Policy-Revision: revision\r\n")
	require.NoError(t, err)
	_, err = fmt.Fprint(conn, "GET /test HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
	require.NoError(t, err)
	// Read through close so both successful handshakes have completed.
	_, err = io.ReadAll(bufio.NewReader(conn))
	require.NoError(t, err)
	require.NoError(t, conn.Close())
	require.Eventually(t, func() bool { return len(log.events(t)) == 2 }, time.Second, 10*time.Millisecond)
	events := log.events(t)
	require.Equal(t, "client", events[0]["leg"])
	require.Equal(t, "upstream", events[1]["leg"])
	for _, event := range events {
		require.Equal(t, "revision", event["policy_revision"])
		state := event["tls"].(map[string]any)
		require.Equal(t, float64(tls.VersionTLS13), state["version"])
		require.Equal(t, float64(tls.X25519MLKEM768), state["group"])
	}
	require.Equal(t, "ECDSA", events[1]["tls"].(map[string]any)["peer_key"])
}
