package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
)

func TestRemoveResponseConnectionHeaders(t *testing.T) {
	h := http.Header{}
	h.Set("Connection", "keep-alive, X-Conn-Scoped")
	h.Set("Keep-Alive", "timeout=5")
	h.Set("Proxy-Connection", "keep-alive")
	h.Add("Connection", "X-Second-Scoped")
	h.Set("Transfer-Encoding", "chunked")
	h.Set("Upgrade", "h2,h2c")
	h.Set("X-Conn-Scoped", "1")
	h.Set("X-Second-Scoped", "1")
	h.Set("Trailer", "Grpc-Status")
	h.Set("Proxy-Authenticate", `Basic realm="proxy"`)
	h.Set("Content-Type", "text/plain")

	removeResponseConnectionHeaders(h)

	for _, name := range []string{"Connection", "Keep-Alive", "Proxy-Connection", "Transfer-Encoding", "Upgrade", "X-Conn-Scoped", "X-Second-Scoped"} {
		require.Empty(t, h.Get(name), name)
	}
	require.Equal(t, `Basic realm="proxy"`, h.Get("Proxy-Authenticate"))
	require.Equal(t, "text/plain", h.Get("Content-Type"))
	require.Equal(t, "Grpc-Status", h.Get("Trailer"))
}

func TestCopyUpstreamResponseHeadersKeepsProxySetHeaders(t *testing.T) {
	dst := http.Header{}
	dst.Set("Connection", "close")
	upstream := http.Header{}
	upstream.Set("Connection", "keep-alive")
	upstream.Set("Keep-Alive", "timeout=5")
	upstream.Set("Content-Type", "text/event-stream")

	copyUpstreamResponseHeaders(dst, upstream)

	require.Equal(t, []string{"close"}, dst.Values("Connection"))
	require.Empty(t, dst.Get("Keep-Alive"))
	require.Equal(t, "text/event-stream", dst.Get("Content-Type"))
	require.Equal(t, "keep-alive", upstream.Get("Connection"), "upstream header must not be mutated")
}

// TestIntegration_HTTPListenerCONNECT_HTTP2 covers CONNECT on the plain HTTP
// proxy listener (what HTTPS_PROXY clients use): the MITM leg must offer h2,
// and upstream connection headers such as Keep-Alive, which are illegal in
// HTTP/2, must not be forwarded.
func TestIntegration_HTTPListenerCONNECT_HTTP2(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Keep-Alive", "timeout=5")
		w.Header().Set("X-Upstream-Proto", r.Proto)
		_, _ = fmt.Fprint(w, "h2 via http listener")
	}))
	upstream.EnableHTTP2 = true
	upstream.StartTLS()
	defer upstream.Close()
	upstreamAddr := upstream.Listener.Addr().String()

	const allowedHost = "allowed.example.com"
	p, _, caPool := startTunnelIntegrationProxy(t, []string{allowedHost}, logger)
	p.transport = &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		ForceAttemptHTTP2: true,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, upstreamAddr)
		},
	}

	httpLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() { _ = p.httpServer.Serve(httpLn) }()
	t.Cleanup(func() { _ = p.httpServer.Close() })
	proxyAddr := httpLn.Addr().String()

	client := &http.Client{
		Transport: &http2.Transport{
			TLSClientConfig: &tls.Config{RootCAs: caPool, ServerName: allowedHost, NextProtos: []string{"h2"}},
			DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
				conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
				if err != nil {
					return nil, err
				}
				if _, err := fmt.Fprintf(conn, "CONNECT %s:443 HTTP/1.1\r\nHost: %s:443\r\n\r\n", allowedHost, allowedHost); err != nil {
					_ = conn.Close()
					return nil, err
				}
				resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
				if err != nil {
					_ = conn.Close()
					return nil, err
				}
				if resp.StatusCode != http.StatusOK {
					_ = conn.Close()
					return nil, fmt.Errorf("CONNECT failed: %d", resp.StatusCode)
				}
				tlsConn := tls.Client(conn, cfg)
				if err := tlsConn.HandshakeContext(ctx); err != nil {
					_ = conn.Close()
					return nil, err
				}
				return tlsConn, nil
			},
		},
	}
	defer client.CloseIdleConnections()

	resp, err := client.Get(fmt.Sprintf("https://%s/test", allowedHost))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, 2, resp.ProtoMajor)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, "h2 via http listener", string(body))
	require.Empty(t, resp.Header.Get("Keep-Alive"))
}
