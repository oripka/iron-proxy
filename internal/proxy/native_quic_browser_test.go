package proxy

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// An isolated browser talks real UDP HTTP/3 to a test-only adapter implementing
// the provider's framing. This does NOT qualify Apple's signed interception or
// change machine trust, browser profiles, installed apps or network policy.
func TestNativeQUICBrowser(t *testing.T) {
	binary := os.Getenv("NOSY_TEST_CHROMIUM")
	if binary == "" {
		t.Skip("explicit isolated Chromium executable required")
	}
	var mu sync.Mutex
	var protocols []string
	p, addr, target, _, _ := quicFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		protocols = append(protocols, r.Proto)
		mu.Unlock()
		if r.URL.Path == "/upload" {
			b, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			_, _ = w.Write(b)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, `<!doctype html><body>pending<script>Promise.all(Array.from({length:8},(_,i)=>fetch('/upload',{method:'POST',body:'stream-'+i}).then(r=>r.text()))).then(v=>document.body.textContent='verified browser HTTP/3 '+v.join(','))</script></body>`)
	}))
	_, port, err := net.SplitHostPort(target)
	require.NoError(t, err)
	udp, err := net.ListenPacket("udp6", net.JoinHostPort("::1", port))
	require.NoError(t, err)
	channel, code := quicChannel(t, addr, target, strings.Repeat("f", 64))
	require.Equal(t, 200, code)
	var peer net.Addr
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 65507)
		for {
			n, a, err := udp.ReadFrom(buf)
			if err != nil {
				return
			}
			mu.Lock()
			if peer == nil {
				peer = a
			}
			matches := peer.String() == a.String()
			mu.Unlock()
			if !matches {
				continue
			}
			if _, err = channel.WriteTo(buf[:n], nil); err != nil {
				return
			}
		}
	}()
	returned := make(chan struct{})
	go func() {
		defer close(returned)
		buf := make([]byte, 65507)
		for {
			n, _, err := channel.ReadFrom(buf)
			if err != nil {
				return
			}
			mu.Lock()
			a := peer
			mu.Unlock()
			if a != nil {
				if _, err = udp.WriteTo(buf[:n], a); err != nil {
					return
				}
			}
		}
	}()
	t.Cleanup(func() { _ = udp.Close(); _ = channel.Close(); <-done; <-returned })
	cert, err := p.certCache.GetOrCreate("localhost")
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	require.NoError(t, err)
	hash := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, binary, "--headless", "--no-first-run", "--disable-background-networking", "--disable-component-update", "--disable-sync", "--no-proxy-server", "--user-data-dir="+t.TempDir(), "--host-resolver-rules=MAP localhost [::1], MAP * ~NOTFOUND", "--origin-to-force-quic-on=localhost:"+port, "--ignore-certificate-errors-spki-list="+base64.StdEncoding.EncodeToString(hash[:]), "--virtual-time-budget=3000", "--dump-dom", "https://localhost:"+port+"/proof")
	output, err := command.CombinedOutput()
	require.NoError(t, err, string(output))
	require.Contains(t, string(output), "verified browser HTTP/3 stream-0,stream-1,stream-2,stream-3,stream-4,stream-5,stream-6,stream-7")
	mu.Lock()
	defer mu.Unlock()
	require.GreaterOrEqual(t, len(protocols), 9)
	for _, protocol := range protocols {
		require.Equal(t, "HTTP/3.0", protocol)
	}
}
