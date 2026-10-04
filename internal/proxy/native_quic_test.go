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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ironsh/iron-proxy/internal/certcache"
	"github.com/ironsh/iron-proxy/internal/transform"
	"github.com/ironsh/iron-proxy/internal/transform/allowlist"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/stretchr/testify/require"
)

// Like PacketSafari's tlsfixture/quic, this uses real quic-go HTTP/3 endpoints
// and disposable CAs. Unlike its permissive fixture client, trust is verified.
func quicFixture(t *testing.T, handler http.Handler, audit ...transform.AuditFunc) (*Proxy, string, string, *x509.CertPool, *x509.CertPool) {
	t.Helper()
	upstreamCA, upstreamKey := generateTestCA(t)
	upstreamCache, err := certcache.NewFromCA(upstreamCA, upstreamKey, 16, time.Hour)
	require.NoError(t, err)
	cert, err := upstreamCache.GetOrCreate("localhost")
	require.NoError(t, err)
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	upstream := &http3.Server{TLSConfig: &tls.Config{Certificates: []tls.Certificate{*cert}}, Handler: handler}
	go func() { _ = upstream.Serve(udp) }()
	t.Cleanup(func() { _ = upstream.Close(); _ = udp.Close() })
	upstreamPool := x509.NewCertPool()
	upstreamPool.AddCert(upstreamCA)
	ca, key := generateTestCA(t)
	cache, err := certcache.NewFromCA(ca, key, 16, time.Hour)
	require.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	allow, err := allowlist.New([]string{"localhost"}, []string{"127.0.0.0/8"})
	require.NoError(t, err)
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	pipeline := transform.NewPipeline([]transform.Transformer{allow}, transform.BodyLimits{}, logger)
	pipeline.SetAuditFunc(func(result *transform.PipelineResult) {
		for _, emit := range audit {
			emit(result)
		}
		if result.Err != nil {
			t.Logf("fixture upstream failure: %v", result.Err)
		}
	})
	p := New(Options{HTTPAddr: "127.0.0.1:0", CertCache: cache, Pipeline: transform.NewPipelineHolder(pipeline), Logger: logger})
	p.transport.TLSClientConfig.RootCAs = upstreamPool
	p.EnableNativeQUIC()
	_, port, err := net.SplitHostPort(udp.LocalAddr().String())
	require.NoError(t, err)
	require.NoError(t, p.enableNativeInspection(strings.Repeat("a", 64), true, port))
	server := httptest.NewServer(p.httpServer.Handler)
	t.Cleanup(func() { p.shutdownCancel(); server.Close(); p.transport.CloseIdleConnections() })
	return p, server.Listener.Addr().String(), udp.LocalAddr().String(), pool, upstreamPool
}

func quicChannel(t *testing.T, addr, target, app string) (*nativePacketConn, int) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	require.NoError(t, err)
	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
	_, err = fmt.Fprintf(conn, "POST /nosy/quic HTTP/1.1\r\nHost: localhost\r\nProxy-Authorization: Bearer %s\r\nX-Nosy-App: %s\r\nX-Nosy-Capture-App: %s\r\nX-Nosy-Destination: %s\r\nX-Nosy-Hostname: localhost\r\nX-PacketSafari-Flow-ID: provider:quic\r\nX-Nosy-Policy-Revision: test\r\nContent-Length: 0\r\n\r\n", strings.Repeat("a", 64), app, strings.Repeat("b", 64), target)
	require.NoError(t, err)
	reader := bufio.NewReader(conn)
	res, err := http.ReadResponse(reader, &http.Request{Method: "POST"})
	require.NoError(t, err)
	if res.StatusCode != 200 {
		_ = res.Body.Close()
		_ = conn.Close()
		return nil, res.StatusCode
	}
	require.NoError(t, conn.SetDeadline(time.Time{}))
	return &nativePacketConn{Conn: conn, reader: reader}, 200
}

func quicClient(t *testing.T, addr, target, app string, roots *x509.CertPool, version quic.Version) *http.Client {
	return quicClientEvidence(t, addr, target, app, roots, version, nil)
}
func quicClientEvidence(t *testing.T, addr, target, app string, roots *x509.CertPool, version quic.Version, evidence *quicEvidence) *http.Client {
	t.Helper()
	transport := &http3.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "localhost"}, QUICConfig: &quic.Config{Versions: []quic.Version{version}, HandshakeIdleTimeout: time.Second},
		Dial: func(ctx context.Context, _ string, config *tls.Config, qc *quic.Config) (*quic.Conn, error) {
			packets, code := quicChannel(t, addr, target, app)
			if code != 200 {
				return nil, fmt.Errorf("admission %d", code)
			}
			t.Cleanup(func() { _ = packets.Close() })
			var wire net.PacketConn = packets
			if evidence != nil {
				config.KeyLogWriter = evidence.keys
				wire = &evidencePacketConn{PacketConn: packets, evidence: evidence}
			}
			return quic.Dial(ctx, wire, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2}, config, qc)
		}}
	t.Cleanup(func() { _ = transport.Close() })
	return &http.Client{Transport: transport, Timeout: 5 * time.Second}
}

func TestNativeQUICInspection(t *testing.T) {
	for _, version := range []quic.Version{quic.Version1, quic.Version2} {
		t.Run(version.String(), func(t *testing.T) {
			_, addr, target, roots, _ := quicFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.Equal(t, "HTTP/3.0", r.Proto)
				w.Header().Set("Trailer", "X-Result")
				b, err := io.ReadAll(r.Body)
				require.NoError(t, err)
				require.Equal(t, "client-finished", r.Trailer.Get("X-Client"))
				w.Header().Set("X-Method", r.Method)
				_, _ = w.Write(b)
				w.Header().Set("X-Result", "complete")
			}))
			client := quicClient(t, addr, target, strings.Repeat("c", 64), roots, version)
			var wg sync.WaitGroup
			for i := 0; i < 8; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					req, err := http.NewRequest("POST", "https://localhost/stream", strings.NewReader(strings.Repeat("data", 32768)))
					require.NoError(t, err)
					req.Trailer = http.Header{"X-Client": []string{"client-finished"}}
					res, err := client.Do(req)
					require.NoError(t, err)
					defer res.Body.Close()
					b, err := io.ReadAll(res.Body)
					require.NoError(t, err)
					require.Equal(t, 200, res.StatusCode, string(b))
					require.Equal(t, "HTTP/3.0", res.Proto)
					require.Len(t, b, 131072)
					require.Equal(t, "POST", res.Header.Get("X-Method"))
					require.Equal(t, "complete", res.Trailer.Get("X-Result"))
				}()
			}
			wg.Wait()
		})
	}
}

func TestNativeQUICCertificateCompatibility(t *testing.T) {
	p, addr, target, _, upstreamRoots := quicFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("opaque retry")) }))
	app := strings.Repeat("c", 64)
	first := quicClient(t, addr, target, app, upstreamRoots, quic.Version1)
	_, err := first.Get("https://localhost/")
	require.Error(t, err)
	time.Sleep(100 * time.Millisecond)
	second := quicClient(t, addr, target, app, upstreamRoots, quic.Version1)
	res, err := second.Get("https://localhost/")
	require.NoError(t, err)
	b, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	require.NoError(t, res.Body.Close())
	require.Equal(t, "opaque retry", string(b))
	unrelated := quicClient(t, addr, target, strings.Repeat("d", 64), upstreamRoots, quic.Version1)
	_, err = unrelated.Get("https://localhost/")
	require.Error(t, err)
	allow, err := allowlist.New([]string{"localhost"}, []string{"127.0.0.0/8"})
	require.NoError(t, err)
	p.pipeline.Store(transform.NewPipeline([]transform.Transformer{allow, &tunnelInfoTransform{seen: make(chan *transform.TunnelInfo, 1)}}, transform.BodyLimits{}, p.logger))
	mandatory := quicClient(t, addr, target, app, upstreamRoots, quic.Version1)
	_, err = mandatory.Get("https://localhost/")
	require.Error(t, err, "existing exception must not bypass HTTP-aware policy")
	deny, err := allowlist.New([]string{"unrelated.invalid"}, nil)
	require.NoError(t, err)
	p.pipeline.Store(transform.NewPipeline([]transform.Transformer{deny}, transform.BodyLimits{}, p.logger))
	_, code := quicChannel(t, addr, target, app)
	require.Equal(t, 403, code)
}

func TestNativeQUICResetCompatibility(t *testing.T) {
	_, addr, target, _, upstreamRoots := quicFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") }))
	app := strings.Repeat("a", 64)
	first := quicClient(t, addr, target, app, upstreamRoots, quic.Version1)
	_, err := first.Get("https://localhost/")
	require.Error(t, err)
	time.Sleep(50 * time.Millisecond)
	retry := quicClient(t, addr, target, app, upstreamRoots, quic.Version1)
	response, err := retry.Get("https://localhost/")
	require.NoError(t, err)
	require.NoError(t, response.Body.Close())
	request, err := http.NewRequest("POST", "http://"+addr+"/nosy/compatibility/reset", nil)
	require.NoError(t, err)
	unauthorized, err := http.DefaultClient.Do(request)
	require.NoError(t, err)
	require.Equal(t, 407, unauthorized.StatusCode)
	require.NoError(t, unauthorized.Body.Close())
	request.Header.Set("Proxy-Authorization", "Bearer "+strings.Repeat("a", 64))
	reset, err := http.DefaultClient.Do(request)
	require.NoError(t, err)
	require.Equal(t, 204, reset.StatusCode)
	require.NoError(t, reset.Body.Close())
	after := quicClient(t, addr, target, app, upstreamRoots, quic.Version1)
	_, err = after.Get("https://localhost/")
	require.Error(t, err)
}

func TestNativeQUICCertificateAlertClassification(t *testing.T) {
	require.True(t, nativeQUICCertificateRejection(&quic.TransportError{Remote: true, ErrorCode: 0x12a}))
	for _, err := range []error{io.EOF, context.DeadlineExceeded, &quic.TransportError{Remote: false, ErrorCode: 0x12a}, &quic.TransportError{Remote: true, ErrorCode: 1}} {
		require.False(t, nativeQUICCertificateRejection(err))
	}
}

func TestNativeQUICCancellationAndUpstreamTrust(t *testing.T) {
	started, stopped := make(chan struct{}), make(chan struct{})
	p, addr, target, roots, _ := quicFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
		close(stopped)
	}))
	client := quicClient(t, addr, target, strings.Repeat("a", 64), roots, quic.Version1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", "https://localhost/wait", nil)
	require.NoError(t, err)
	finished := make(chan error, 1)
	go func() {
		res, e := client.Do(req)
		if res != nil {
			_ = res.Body.Close()
		}
		finished <- e
	}()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("upstream did not start")
	}
	cancel()
	require.Error(t, <-finished)
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("cancellation did not reach upstream")
	}
	// A different connection with an unusable upstream root must fail, not tunnel.
	p.transport.TLSClientConfig.RootCAs = x509.NewCertPool()
	failed := quicClient(t, addr, target, strings.Repeat("b", 64), roots, quic.Version1)
	res, err := failed.Get("https://localhost/")
	require.NoError(t, err)
	require.Equal(t, 502, res.StatusCode)
	require.NoError(t, res.Body.Close())
}

func TestNativeQUICAuthorityAndResourceLimits(t *testing.T) {
	_, addr, target, roots, _ := quicFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("mismatched authority reached upstream") }))
	client := quicClient(t, addr, target, strings.Repeat("a", 64), roots, quic.Version1)
	request, err := http.NewRequest("GET", "https://localhost/", nil)
	require.NoError(t, err)
	request.Host = "unrelated.invalid"
	res, err := client.Do(request)
	require.NoError(t, err)
	require.Equal(t, 421, res.StatusCode)
	require.NoError(t, res.Body.Close())
	require.NoError(t, client.Transport.(*http3.Transport).Close())
	time.Sleep(50 * time.Millisecond)
	var held []*nativePacketConn
	for i := 0; i < 64; i++ {
		c, code := quicChannel(t, addr, target, strings.Repeat("b", 64))
		require.Equal(t, 200, code)
		held = append(held, c)
	}
	_, code := quicChannel(t, addr, target, strings.Repeat("b", 64))
	require.Equal(t, 503, code)
	for _, c := range held {
		require.NoError(t, c.Close())
	}
	time.Sleep(50 * time.Millisecond)
	c, code := quicChannel(t, addr, target, strings.Repeat("b", 64))
	require.Equal(t, 200, code)
	require.NoError(t, c.Close())
}

func TestNativeQUICMalformedNeverTrainsException(t *testing.T) {
	_, addr, target, _, upstreamRoots := quicFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("malformed flow reached upstream") }))
	app := strings.Repeat("a", 64)
	c, code := quicChannel(t, addr, target, app)
	require.Equal(t, 200, code)
	_, err := c.WriteTo([]byte("not QUIC"), nil)
	require.NoError(t, err)
	_ = c.Close()
	next := quicClient(t, addr, target, app, upstreamRoots, quic.Version1)
	_, err = next.Get("https://localhost/")
	require.Error(t, err)
}
