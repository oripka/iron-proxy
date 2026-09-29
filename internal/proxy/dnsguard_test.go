package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/ironsh/iron-proxy/internal/certcache"
	"github.com/ironsh/iron-proxy/internal/dnsguard"
	"github.com/ironsh/iron-proxy/internal/transform"
	"github.com/ironsh/iron-proxy/internal/transform/allowlist"
)

// TestUpstreamDenyGuard_HTTP confirms the HTTP/HTTPS transport's dialer
// rejects upstream connections whose resolved address falls inside a denied
// CIDR. The allowlist is permissive ("*"), so the only thing that can stop
// the request is the dial-time guard.
func TestUpstreamDenyGuard_HTTP(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "from upstream")
	}))
	defer upstream.Close()
	upstreamURL, err := url.Parse(upstream.URL)
	require.NoError(t, err)

	build := func(t *testing.T, denyCIDRs []string) (proxyHTTPAddr string, audits func() []transform.PipelineResult) {
		t.Helper()
		al, err := allowlist.New([]string{"*"}, nil)
		require.NoError(t, err)
		pipeline := transform.NewPipeline([]transform.Transformer{al}, transform.BodyLimits{}, logger)

		var mu sync.Mutex
		var results []transform.PipelineResult
		pipeline.SetAuditFunc(func(r *transform.PipelineResult) {
			mu.Lock()
			results = append(results, *r)
			mu.Unlock()
		})

		guard, err := dnsguard.New(denyCIDRs)
		require.NoError(t, err)

		p := New(Options{
			HTTPAddr: "127.0.0.1:0",
			Pipeline: transform.NewPipelineHolder(pipeline),
			Guard:    guard,
			Logger:   logger,
		})

		ln, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		go func() { _ = p.httpServer.Serve(ln) }()
		t.Cleanup(func() { _ = p.httpServer.Close() })

		return ln.Addr().String(), func() []transform.PipelineResult {
			mu.Lock()
			defer mu.Unlock()
			out := make([]transform.PipelineResult, len(results))
			copy(out, results)
			return out
		}
	}

	t.Run("denied loopback returns 502", func(t *testing.T) {
		proxyAddr, _ := build(t, []string{"127.0.0.0/8"})
		client := &http.Client{
			Transport: &http.Transport{
				Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: proxyAddr}),
			},
			Timeout: 5 * time.Second,
		}

		resp, err := client.Get(upstream.URL + "/test")
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusBadGateway, resp.StatusCode)
	})

	t.Run("empty deny list permits", func(t *testing.T) {
		proxyAddr, _ := build(t, nil)
		client := &http.Client{
			Transport: &http.Transport{
				Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: proxyAddr}),
			},
			Timeout: 5 * time.Second,
		}

		resp, err := client.Get(upstream.URL + "/test")
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)
		body, _ := io.ReadAll(resp.Body)
		require.Equal(t, "from upstream", string(body))
	})

	t.Run("guard records audit with err", func(t *testing.T) {
		proxyAddr, audits := build(t, []string{"127.0.0.0/8"})
		client := &http.Client{
			Transport: &http.Transport{
				Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: proxyAddr}),
			},
			Timeout: 5 * time.Second,
		}

		resp, err := client.Get(upstream.URL + "/test")
		require.NoError(t, err)
		defer resp.Body.Close()

		records := audits()
		require.Len(t, records, 1)
		require.NotNil(t, records[0].Err)
		require.True(t, dnsguard.IsDenyError(records[0].Err))
	})

	// Sanity: confirm we actually hit the dial path. The upstream listener
	// must be on loopback for the deny test to be meaningful.
	require.Equal(t, "127.0.0.1", upstreamURL.Hostname())
}

// TestUpstreamDenyGuard_SNIPassthrough confirms the sni-only dial path also
// honors the guard.
func TestUpstreamDenyGuard_SNIPassthrough(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	upstreamAddr, _ := startEchoTLSServer(t)
	_, upstreamPort, err := net.SplitHostPort(upstreamAddr)
	require.NoError(t, err)

	al, err := allowlist.New([]string{"*"}, nil)
	require.NoError(t, err)
	pipeline := transform.NewPipeline([]transform.Transformer{al}, transform.BodyLimits{}, logger)

	guard, err := dnsguard.New([]string{"127.0.0.0/8"})
	require.NoError(t, err)

	p := New(Options{
		HTTPSAddr: "127.0.0.1:0",
		TLSMode:   "sni-only",
		Pipeline:  transform.NewPipelineHolder(pipeline),
		Guard:     guard,
		Logger:    logger,
	})
	p.sniUpstreamPort = upstreamPort

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go p.handleSNIPassthrough(conn)
		}
	}()

	// Connect raw TCP, send a TLS ClientHello with SNI=localhost. The dialer
	// will resolve localhost → 127.0.0.1 and the guard will refuse.
	conn, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	defer conn.Close()

	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         "localhost",
		InsecureSkipVerify: true,
	})
	defer tlsConn.Close()

	// Handshake should fail because the proxy refuses to dial upstream and
	// closes the connection.
	require.Error(t, tlsConn.HandshakeContext(context.Background()))
}

// TestUpstreamDenyGuard_AllPaths pins that every upstream dial path — plain
// HTTP forward, CONNECT/SOCKS5 MITM, plain HTTP inside tunnels, WebSocket
// upgrades, and sni-only passthrough reached through a tunnel — is refused by
// upstream_deny_cidrs. The allowlist admits everything, so only the dial-time
// guard can stop these requests; each case asserts the audit entry carries a
// *dnsguard.DenyError.
func TestUpstreamDenyGuard_AllPaths(t *testing.T) {
	httpUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "from upstream")
	}))
	defer httpUpstream.Close()
	httpTarget := httpUpstream.Listener.Addr().String()
	_, httpPortStr, err := net.SplitHostPort(httpTarget)
	require.NoError(t, err)
	var httpPort uint16
	_, err = fmt.Sscanf(httpPortStr, "%d", &httpPort)
	require.NoError(t, err)

	tlsUpstream, _ := startEchoTLSServer(t)
	_, tlsUpstreamPort, err := net.SplitHostPort(tlsUpstream)
	require.NoError(t, err)

	expectStatus := func(t *testing.T, w io.Writer, br *bufio.Reader, req *http.Request, want int) {
		t.Helper()
		require.NoError(t, req.Write(w))
		resp, err := http.ReadResponse(br, req)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, want, resp.StatusCode)
	}
	get := func(t *testing.T, rawURL string) *http.Request {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, rawURL, nil)
		require.NoError(t, err)
		return req
	}
	wsUpgrade := func(t *testing.T, rawURL string) *http.Request {
		t.Helper()
		req := get(t, rawURL)
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Upgrade", "websocket")
		req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
		req.Header.Set("Sec-WebSocket-Version", "13")
		return req
	}
	mitm := func(t *testing.T, conn net.Conn, pool *x509.CertPool) *tls.Conn {
		t.Helper()
		tlsConn := tls.Client(conn, &tls.Config{RootCAs: pool, ServerName: "localhost"})
		require.NoError(t, tlsConn.Handshake())
		return tlsConn
	}

	cases := []struct {
		name         string
		sniOnly      bool
		httpListener bool
		exchange     func(t *testing.T, conn net.Conn, pool *x509.CertPool)
	}{
		{
			name:         "HTTP forward",
			httpListener: true,
			exchange: func(t *testing.T, conn net.Conn, _ *x509.CertPool) {
				expectStatus(t, conn, bufio.NewReader(conn), get(t, "http://"+httpTarget+"/"), http.StatusBadGateway)
			},
		},
		{
			name:         "CONNECT MITM on http listener",
			httpListener: true,
			exchange: func(t *testing.T, conn net.Conn, pool *x509.CertPool) {
				br := httpConnect(t, conn, "localhost:443")
				tlsConn := mitm(t, &bufferedConn{Conn: conn, reader: br}, pool)
				expectStatus(t, tlsConn, bufio.NewReader(tlsConn), get(t, "https://localhost/"), http.StatusBadGateway)
			},
		},
		{
			name: "CONNECT MITM on tunnel listener",
			exchange: func(t *testing.T, conn net.Conn, pool *x509.CertPool) {
				br := httpConnect(t, conn, "localhost:443")
				tlsConn := mitm(t, &bufferedConn{Conn: conn, reader: br}, pool)
				expectStatus(t, tlsConn, bufio.NewReader(tlsConn), get(t, "https://localhost/"), http.StatusBadGateway)
			},
		},
		{
			name: "CONNECT plain HTTP",
			exchange: func(t *testing.T, conn net.Conn, _ *x509.CertPool) {
				br := httpConnect(t, conn, httpTarget)
				expectStatus(t, conn, br, get(t, "http://"+httpTarget+"/"), http.StatusBadGateway)
			},
		},
		{
			name: "SOCKS5 MITM",
			exchange: func(t *testing.T, conn net.Conn, pool *x509.CertPool) {
				socks5Connect(t, conn, "localhost", 443)
				tlsConn := mitm(t, conn, pool)
				expectStatus(t, tlsConn, bufio.NewReader(tlsConn), get(t, "https://localhost/"), http.StatusBadGateway)
			},
		},
		{
			name: "SOCKS5 plain HTTP",
			exchange: func(t *testing.T, conn net.Conn, _ *x509.CertPool) {
				socks5Connect(t, conn, "127.0.0.1", httpPort)
				expectStatus(t, conn, bufio.NewReader(conn), get(t, "http://"+httpTarget+"/"), http.StatusBadGateway)
			},
		},
		{
			name:         "WebSocket via forward proxy",
			httpListener: true,
			exchange: func(t *testing.T, conn net.Conn, _ *x509.CertPool) {
				expectStatus(t, conn, bufio.NewReader(conn), wsUpgrade(t, "http://"+httpTarget+"/ws"), http.StatusBadGateway)
			},
		},
		{
			name: "WebSocket via CONNECT",
			exchange: func(t *testing.T, conn net.Conn, _ *x509.CertPool) {
				br := httpConnect(t, conn, httpTarget)
				expectStatus(t, conn, br, wsUpgrade(t, "http://"+httpTarget+"/ws"), http.StatusBadGateway)
			},
		},
		{
			name: "WebSocket via SOCKS5",
			exchange: func(t *testing.T, conn net.Conn, _ *x509.CertPool) {
				socks5Connect(t, conn, "127.0.0.1", httpPort)
				expectStatus(t, conn, bufio.NewReader(conn), wsUpgrade(t, "http://"+httpTarget+"/ws"), http.StatusBadGateway)
			},
		},
		{
			name: "secure WebSocket via CONNECT MITM",
			exchange: func(t *testing.T, conn net.Conn, pool *x509.CertPool) {
				br := httpConnect(t, conn, "localhost:443")
				tlsConn := mitm(t, &bufferedConn{Conn: conn, reader: br}, pool)
				expectStatus(t, tlsConn, bufio.NewReader(tlsConn), wsUpgrade(t, "https://localhost/ws"), http.StatusBadGateway)
			},
		},
		{
			name:    "sni-only passthrough via CONNECT",
			sniOnly: true,
			exchange: func(t *testing.T, conn net.Conn, _ *x509.CertPool) {
				br := httpConnect(t, conn, "localhost:443")
				tlsConn := tls.Client(&bufferedConn{Conn: conn, reader: br}, &tls.Config{ServerName: "localhost", InsecureSkipVerify: true})
				require.Error(t, tlsConn.Handshake())
			},
		},
		{
			name:    "sni-only passthrough via SOCKS5",
			sniOnly: true,
			exchange: func(t *testing.T, conn net.Conn, _ *x509.CertPool) {
				socks5Connect(t, conn, "localhost", 443)
				tlsConn := tls.Client(conn, &tls.Config{ServerName: "localhost", InsecureSkipVerify: true})
				require.Error(t, tlsConn.Handshake())
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
			al, err := allowlist.New([]string{"*"}, []string{"0.0.0.0/0", "::/0"})
			require.NoError(t, err)
			pipeline := transform.NewPipeline([]transform.Transformer{al}, transform.BodyLimits{}, logger)
			var mu sync.Mutex
			var records []transform.PipelineResult
			pipeline.SetAuditFunc(func(r *transform.PipelineResult) {
				mu.Lock()
				defer mu.Unlock()
				records = append(records, *r)
			})

			guard, err := dnsguard.New([]string{"127.0.0.0/8", "::1/128"})
			require.NoError(t, err)
			caCert, caKey := generateTestCA(t)
			cache, err := certcache.NewFromCA(caCert, caKey, 100, 72*time.Hour)
			require.NoError(t, err)
			pool := x509.NewCertPool()
			pool.AddCert(caCert)

			opts := Options{
				HTTPAddr:   "127.0.0.1:0",
				TunnelAddr: "127.0.0.1:0",
				CertCache:  cache,
				Pipeline:   transform.NewPipelineHolder(pipeline),
				Guard:      guard,
				Logger:     logger,
			}
			if tc.sniOnly {
				opts.TLSMode = "sni-only"
			}
			p := New(opts)
			// Without the guard the sni-only dial would reach the live TLS upstream.
			p.sniUpstreamPort = tlsUpstreamPort

			addr := startTunnelListener(t, p)
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

			require.Eventually(t, func() bool {
				mu.Lock()
				defer mu.Unlock()
				for _, r := range records {
					if dnsguard.IsDenyError(r.Err) {
						return true
					}
				}
				return false
			}, 5*time.Second, 10*time.Millisecond, "no audit entry carried an upstream deny error")
		})
	}
}
