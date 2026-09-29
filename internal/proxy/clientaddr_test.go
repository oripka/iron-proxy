package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/ironsh/iron-proxy/internal/transform"
)

type seenRequest struct {
	method     string
	remoteAddr string
	tunneled   bool
}

// remoteAddrRecorder records req.RemoteAddr for every request it sees. It
// admits CONNECT preflights and rejects everything else, so no upstream is
// ever dialed.
type remoteAddrRecorder struct {
	mu   sync.Mutex
	seen []seenRequest
}

func (r *remoteAddrRecorder) Name() string { return "remote-addr-recorder" }

func (r *remoteAddrRecorder) TransformRequest(_ context.Context, tctx *transform.TransformContext, req *http.Request) (*transform.TransformResult, error) {
	r.mu.Lock()
	r.seen = append(r.seen, seenRequest{method: req.Method, remoteAddr: req.RemoteAddr, tunneled: tctx.Tunnel != nil})
	r.mu.Unlock()
	if req.Method == http.MethodConnect {
		return &transform.TransformResult{Action: transform.ActionContinue}, nil
	}
	return &transform.TransformResult{Action: transform.ActionReject}, nil
}

func (r *remoteAddrRecorder) TransformResponse(_ context.Context, _ *transform.TransformContext, _ *http.Request, _ *http.Response) (*transform.TransformResult, error) {
	return &transform.TransformResult{Action: transform.ActionContinue}, nil
}

func (r *remoteAddrRecorder) snapshot() []seenRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]seenRequest(nil), r.seen...)
}

func socks5Connect(t *testing.T, conn net.Conn, host string, port uint16) {
	t.Helper()
	_, err := conn.Write([]byte{0x05, 0x01, 0x00})
	require.NoError(t, err)
	authResp := make([]byte, 2)
	_, err = io.ReadFull(conn, authResp)
	require.NoError(t, err)
	require.Equal(t, []byte{0x05, 0x00}, authResp)

	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, host...)
	req = binary.BigEndian.AppendUint16(req, port)
	_, err = conn.Write(req)
	require.NoError(t, err)
	reply := make([]byte, 10)
	_, err = io.ReadFull(conn, reply)
	require.NoError(t, err)
	require.Equal(t, byte(0x00), reply[1])
}

func httpConnect(t *testing.T, conn net.Conn, target string) *bufio.Reader {
	t.Helper()
	_, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	require.NoError(t, err)
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	return br
}

// innerTLSGet completes a MITM TLS handshake on conn and sends one GET.
func innerTLSGet(t *testing.T, conn net.Conn, host string, pool *x509.CertPool) {
	t.Helper()
	tlsConn := tls.Client(conn, &tls.Config{RootCAs: pool, ServerName: host})
	require.NoError(t, tlsConn.Handshake())
	plainGet(t, tlsConn, bufio.NewReader(tlsConn), "https://"+host+"/x", host)
}

// plainGet writes a GET for rawURL on w and expects the recorder's 403.
func plainGet(t *testing.T, w io.Writer, br *bufio.Reader, rawURL, host string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	require.NoError(t, err)
	req.Host = host
	require.NoError(t, req.Write(w))
	resp, err := http.ReadResponse(br, req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusForbidden, resp.StatusCode)
}

// TestClientRemoteAddrReachesTransforms pins that every request path hands
// transforms the downstream client socket address, never the proxy's own.
func TestClientRemoteAddrReachesTransforms(t *testing.T) {
	const host = "client-addr.example.com"

	cases := []struct {
		name         string
		httpListener bool // dial the plain HTTP listener instead of the tunnel listener
		exchange     func(t *testing.T, conn net.Conn, pool *x509.CertPool)
		wantConnect  bool
	}{
		{
			name:         "forward proxy on http listener",
			httpListener: true,
			exchange: func(t *testing.T, conn net.Conn, _ *x509.CertPool) {
				// Absolute-form request line, as a forward-proxy client sends it.
				_, err := fmt.Fprintf(conn, "GET http://%s/x HTTP/1.1\r\nHost: %s\r\n\r\n", host, host)
				require.NoError(t, err)
				resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
				require.NoError(t, err)
				require.Equal(t, http.StatusForbidden, resp.StatusCode)
			},
		},
		{
			name: "forward proxy on tunnel listener",
			exchange: func(t *testing.T, conn net.Conn, _ *x509.CertPool) {
				_, err := fmt.Fprintf(conn, "GET http://%s/x HTTP/1.1\r\nHost: %s\r\n\r\n", host, host)
				require.NoError(t, err)
				resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
				require.NoError(t, err)
				require.Equal(t, http.StatusForbidden, resp.StatusCode)
			},
		},
		{
			name:         "CONNECT MITM on http listener",
			httpListener: true,
			wantConnect:  true,
			exchange: func(t *testing.T, conn net.Conn, pool *x509.CertPool) {
				br := httpConnect(t, conn, host+":443")
				innerTLSGet(t, &bufferedConn{Conn: conn, reader: br}, host, pool)
			},
		},
		{
			name:        "CONNECT MITM on tunnel listener",
			wantConnect: true,
			exchange: func(t *testing.T, conn net.Conn, pool *x509.CertPool) {
				br := httpConnect(t, conn, host+":443")
				innerTLSGet(t, &bufferedConn{Conn: conn, reader: br}, host, pool)
			},
		},
		{
			name:        "CONNECT plain HTTP on tunnel listener",
			wantConnect: true,
			exchange: func(t *testing.T, conn net.Conn, _ *x509.CertPool) {
				br := httpConnect(t, conn, host+":80")
				plainGet(t, conn, br, "http://"+host+"/x", host)
			},
		},
		{
			name:        "SOCKS5 MITM",
			wantConnect: true,
			exchange: func(t *testing.T, conn net.Conn, pool *x509.CertPool) {
				socks5Connect(t, conn, host, 443)
				innerTLSGet(t, conn, host, pool)
			},
		},
		{
			name:        "SOCKS5 plain HTTP",
			wantConnect: true,
			exchange: func(t *testing.T, conn net.Conn, _ *x509.CertPool) {
				socks5Connect(t, conn, host, 80)
				plainGet(t, conn, bufio.NewReader(conn), "http://"+host+"/x", host)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			recorder := &remoteAddrRecorder{}
			p, tunnelAddr, pool := startTunnelProxy(t, []transform.Transformer{recorder})

			addr := tunnelAddr
			if tc.httpListener {
				ln, err := net.Listen("tcp", "127.0.0.1:0")
				require.NoError(t, err)
				go func() { _ = p.httpServer.Serve(ln) }()
				t.Cleanup(func() { _ = p.httpServer.Close() })
				addr = ln.Addr().String()
			}

			conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
			require.NoError(t, err)
			defer conn.Close()
			require.NoError(t, conn.SetDeadline(time.Now().Add(10*time.Second)))

			tc.exchange(t, conn, pool)

			want := conn.LocalAddr().String()
			seen := recorder.snapshot()
			sawConnect, sawInner := false, false
			for _, s := range seen {
				require.Equal(t, want, s.remoteAddr, "method %s", s.method)
				if s.method == http.MethodConnect {
					sawConnect = true
				} else {
					sawInner = true
					require.Equal(t, tc.wantConnect, s.tunneled)
				}
			}
			require.Equal(t, tc.wantConnect, sawConnect)
			require.True(t, sawInner)
		})
	}
}
