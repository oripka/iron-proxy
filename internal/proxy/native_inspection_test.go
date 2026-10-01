package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/ironsh/iron-proxy/internal/certcache"
	"github.com/ironsh/iron-proxy/internal/dnsguard"
	"github.com/ironsh/iron-proxy/internal/transform"
	"github.com/ironsh/iron-proxy/internal/transform/allowlist"
	"github.com/stretchr/testify/require"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func nativeFixture(t *testing.T, strict bool) (*Proxy, string, string, *x509.CertPool, *x509.CertPool) {
	t.Helper()
	target, upstreamPool := startEchoTLSServer(t)
	ca, key := generateTestCA(t)
	cache, err := certcache.NewFromCA(ca, key, 16, time.Hour)
	require.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	allow, err := allowlist.New([]string{"localhost"}, []string{"127.0.0.0/8"})
	require.NoError(t, err)
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	pipeline := transform.NewPipeline([]transform.Transformer{allow}, transform.BodyLimits{}, logger)
	p := New(Options{HTTPAddr: "127.0.0.1:0", CertCache: cache, Pipeline: transform.NewPipelineHolder(pipeline), Logger: logger})
	p.transport.TLSClientConfig.RootCAs = upstreamPool
	_, port, err := net.SplitHostPort(target)
	require.NoError(t, err)
	require.NoError(t, p.enableNativeInspection(strings.Repeat("a", 64), strict, port))
	server := httptest.NewServer(p.httpServer.Handler)
	t.Cleanup(func() { p.shutdownCancel(); server.Close(); p.transport.CloseIdleConnections() })
	return p, server.Listener.Addr().String(), target, pool, upstreamPool
}

func nativeConnect(t *testing.T, addr, target, app string, pool *x509.CertPool) (*tls.Conn, error) {
	t.Helper()
	return nativeConnectName(t, addr, target, app, pool, "localhost")
}
func nativeConnectName(t *testing.T, addr, target, app string, pool *x509.CertPool, name string) (*tls.Conn, error) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	require.NoError(t, err)
	require.NoError(t, conn.SetDeadline(time.Now().Add(3*time.Second)))
	_, err = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Bearer %s\r\nX-Nosy-App: %s\r\nX-PacketSafari-Flow-ID: provider:flow-test\r\n\r\n", target, target, strings.Repeat("a", 64), app)
	require.NoError(t, err)
	reader := bufio.NewReader(conn)
	res, err := http.ReadResponse(reader, &http.Request{Method: "CONNECT"})
	require.NoError(t, err)
	require.Equal(t, 200, res.StatusCode)
	tlsConn := tls.Client(&bufferedConn{Conn: conn, reader: reader}, &tls.Config{RootCAs: pool, ServerName: name})
	err = tlsConn.HandshakeContext(context.Background())
	if err != nil {
		require.NoError(t, conn.Close())
	}
	return tlsConn, err
}

func TestNativeInspectionTLSAndFallback(t *testing.T) {
	for _, strict := range []bool{false, true} {
		t.Run(fmt.Sprint(strict), func(t *testing.T) {
			_, addr, target, proxyPool, upstreamPool := nativeFixture(t, strict)
			app := strings.Repeat("b", 64)
			good, err := nativeConnect(t, addr, target, app, proxyPool)
			require.NoError(t, err)
			_, err = fmt.Fprint(good, "GET /verified HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
			require.NoError(t, err)
			response, err := http.ReadResponse(bufio.NewReader(good), nil)
			require.NoError(t, err)
			body, err := io.ReadAll(response.Body)
			require.NoError(t, err)
			require.NoError(t, response.Body.Close())
			require.NoError(t, good.Close())
			require.Equal(t, 200, response.StatusCode)
			require.Contains(t, string(body), "verified")
			_, err = nativeConnect(t, addr, target, app, upstreamPool)
			require.Error(t, err)
			// Completion of the rejection travels back to the server asynchronously.
			require.Eventually(t, func() bool {
				next, e := nativeConnect(t, addr, target, app, upstreamPool)
				if e == nil {
					require.NoError(t, next.Close())
					return !strict
				}
				return strict
			}, time.Second, 20*time.Millisecond)
			// Another process never inherits that compatibility exception.
			_, err = nativeConnect(t, addr, target, strings.Repeat("c", 64), upstreamPool)
			require.Error(t, err)
		})
	}
}

func TestNativeInspectionRejectsUnauthenticatedAndUnboundedTargets(t *testing.T) {
	p, _, target, _, _ := nativeFixture(t, false)
	cases := []struct {
		name, token, target, app string
		code                     int
	}{
		{"no authority", "", target, strings.Repeat("b", 64), 407},
		{"hostname not admitted", strings.Repeat("a", 64), "evil.example:443", strings.Repeat("b", 64), 400},
		{"bad identity", strings.Repeat("a", 64), target, "bad", 400},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest("CONNECT", "http://example", nil)
			request.Host = tc.target
			request.Header.Set("Proxy-Authorization", "Bearer "+tc.token)
			request.Header.Set("X-Nosy-App", tc.app)
			request.Header.Set("X-PacketSafari-Flow-ID", "test")
			response := httptest.NewRecorder()
			p.httpServer.Handler.ServeHTTP(response, request)
			require.Equal(t, tc.code, response.Code)
		})
	}
}

func TestNativeInspectionKeepsUpstreamIPDeny(t *testing.T) {
	p, addr, target, pool, _ := nativeFixture(t, false)
	guard, err := dnsguard.New([]string{"127.0.0.0/8"})
	require.NoError(t, err)
	p.guard = guard
	client, err := nativeConnect(t, addr, target, strings.Repeat("b", 64), pool)
	require.NoError(t, err)
	_, err = fmt.Fprint(client, "GET /blocked HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
	require.NoError(t, err)
	response, err := http.ReadResponse(bufio.NewReader(client), nil)
	require.NoError(t, err)
	require.GreaterOrEqual(t, response.StatusCode, 400)
	require.NoError(t, response.Body.Close())
	require.NoError(t, client.Close())
}

func TestNativeInspectionKeepsConnectPolicyDeny(t *testing.T) {
	p, _, target, _, _ := nativeFixture(t, false)
	gate, err := allowlist.New([]string{"unrelated.invalid"}, nil)
	require.NoError(t, err)
	p.pipeline = transform.NewPipelineHolder(transform.NewPipeline([]transform.Transformer{gate}, transform.BodyLimits{}, p.logger))
	request := httptest.NewRequest("CONNECT", "http://example", nil)
	request.Host = target
	request.Header.Set("Proxy-Authorization", "Bearer "+strings.Repeat("a", 64))
	request.Header.Set("X-Nosy-App", strings.Repeat("b", 64))
	request.Header.Set("X-PacketSafari-Flow-ID", "provider:flow")
	response := httptest.NewRecorder()
	p.httpServer.Handler.ServeHTTP(response, request)
	require.Equal(t, 403, response.Code)
}

func TestNativeInspectionFailureCacheIsBoundedAndExpires(t *testing.T) {
	state := &nativeInspection{failures: make(map[string]time.Time)}
	for i := 0; i < 5000; i++ {
		state.remember(fmt.Sprint(i))
	}
	require.Len(t, state.failures, 4096)
	state.failures["0"] = time.Now().Add(-time.Second)
	state.nextPrune = time.Time{}
	state.remember("new")
	require.Len(t, state.failures, 4096)
	require.NotContains(t, state.failures, "0")
	require.Contains(t, state.failures, "new")
}

func TestNativeInspectionMissingSNIFollowsFallbackPolicy(t *testing.T) {
	for _, strict := range []bool{false, true} {
		t.Run(fmt.Sprint(strict), func(t *testing.T) {
			_, addr, target, _, upstreamPool := nativeFixture(t, strict)
			// Go omits SNI for an IP literal; the real upstream cert covers it.
			conn, err := nativeConnectName(t, addr, target, strings.Repeat("b", 64), upstreamPool, "127.0.0.1")
			if strict {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.NoError(t, conn.Close())
			}
		})
	}
}
