package proxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/certcache"
	"github.com/ironsh/iron-proxy/internal/transform"
	_ "github.com/ironsh/iron-proxy/internal/transform/allowlist"
	_ "github.com/ironsh/iron-proxy/internal/transform/secrets"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func generateTestCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert, key
}

func startProxy(t *testing.T) (*Proxy, string, string, *x509.CertPool) {
	return startProxyWithPipeline(t, transform.NewPipeline(nil, testLogger()))
}

func startProxyWithPipeline(t *testing.T, pipeline *transform.Pipeline) (*Proxy, string, string, *x509.CertPool) {
	t.Helper()

	caCert, caKey := generateTestCA(t)
	cache, err := certcache.NewFromCA(caCert, caKey, 100, 72*time.Hour)
	require.NoError(t, err)

	p := New("127.0.0.1:0", "127.0.0.1:0", cache, pipeline, testLogger())

	// Start HTTP listener manually to get random port
	httpLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	httpAddr := httpLn.Addr().String()

	// Start HTTPS listener manually
	httpsLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	tlsLn := tls.NewListener(httpsLn, p.httpsServer.TLSConfig)
	httpsAddr := httpsLn.Addr().String()

	go func() { _ = p.httpServer.Serve(httpLn) }()
	go func() { _ = p.httpsServer.Serve(tlsLn) }()

	t.Cleanup(func() {
		_ = p.httpServer.Close()
		_ = p.httpsServer.Close()
	})

	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	return p, httpAddr, httpsAddr, pool
}

func buildPipeline(t *testing.T, configYAML string) *transform.Pipeline {
	t.Helper()

	var cfg struct {
		Transforms []struct {
			Name   string    `yaml:"name"`
			Config yaml.Node `yaml:"config"`
		} `yaml:"transforms"`
	}
	require.NoError(t, yaml.Unmarshal([]byte(configYAML), &cfg))

	var transformers []transform.Transformer
	for _, tc := range cfg.Transforms {
		factory, err := transform.Lookup(tc.Name)
		require.NoError(t, err)
		instance, err := factory(tc.Config)
		require.NoError(t, err)
		transformers = append(transformers, instance)
	}
	return transform.NewPipeline(transformers, testLogger())
}

func TestHTTPProxy(t *testing.T) {
	// Start an upstream HTTP server
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Test", "upstream")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "hello from upstream")
	}))
	defer upstream.Close()

	_, httpAddr, _, _ := startProxy(t)

	// Send request through the proxy, targeting the upstream
	req, err := http.NewRequest("GET", fmt.Sprintf("http://%s/test", httpAddr), nil)
	require.NoError(t, err)
	req.Host = upstream.Listener.Addr().String()

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "upstream", resp.Header.Get("X-Test"))

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, "hello from upstream", string(body))
}

func TestHTTPProxy_PostBody(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, "echo: %s", body)
	}))
	defer upstream.Close()

	_, httpAddr, _, _ := startProxy(t)

	req, err := http.NewRequest("POST", fmt.Sprintf("http://%s/echo", httpAddr),
		strings.NewReader("request body"))
	require.NoError(t, err)
	req.Host = upstream.Listener.Addr().String()

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, "echo: request body", string(body))
}

func TestHTTPSProxy(t *testing.T) {
	// Start an upstream HTTPS server
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "hello from tls upstream")
	}))
	defer upstream.Close()

	_, _, httpsAddr, caPool := startProxy(t)

	// We need to route the request to the proxy but with the upstream's Host.
	// The proxy will make a TLS connection to the upstream.
	// For this test, we need the proxy's upstream transport to trust the
	// upstream's self-signed cert. Override it temporarily.
	// Use a fake hostname so Go's TLS actually sends SNI (it won't for IPs).
	const fakeHost = "test.example.com"
	upstreamAddr := upstream.Listener.Addr().String()

	origTransport := upstreamTransport
	upstreamTransport = &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		// Route fakeHost to the actual upstream
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, upstreamAddr)
		},
	}
	defer func() { upstreamTransport = origTransport }()

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    caPool,
				ServerName: fakeHost,
			},
			// Route the fake hostname to the proxy's actual address
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, httpsAddr)
			},
		},
	}

	req, err := http.NewRequest("GET", fmt.Sprintf("https://%s/test", fakeHost), nil)
	require.NoError(t, err)
	// Host defaults to fakeHost — matches SNI

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, "hello from tls upstream", string(body))
}

func TestHTTPSProxy_SNIHostMismatch(t *testing.T) {
	_, _, httpsAddr, caPool := startProxy(t)

	// SNI says "sni.example.com" but Host says "other.example.com"
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    caPool,
				ServerName: "sni.example.com",
			},
		},
	}

	req, err := http.NewRequest("GET", fmt.Sprintf("https://%s/test", httpsAddr), nil)
	require.NoError(t, err)
	req.Host = "other.example.com"

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestExplicitHTTPSProxy_CONNECT(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "hello from explicit connect")
	}))
	defer upstream.Close()

	_, httpAddr, _, caPool := startProxy(t)

	const fakeHost = "connect.example.com"
	upstreamAddr := upstream.Listener.Addr().String()

	origTransport := upstreamTransport
	upstreamTransport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, upstreamAddr)
		},
	}
	defer func() { upstreamTransport = origTransport }()

	proxyURL, err := url.Parse("http://" + httpAddr)
	require.NoError(t, err)

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				RootCAs: caPool,
			},
		},
	}

	resp, err := client.Get("https://" + fakeHost + "/through-connect")
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Equal(t, "hello from explicit connect", string(body))
}

func TestExplicitHTTPSProxy_CONNECT_RewritesSecrets(t *testing.T) {
	const (
		fakeHost   = "api.openai.com"
		proxyToken = "proxy-openai-abc123"
		realSecret = "sk-real-value"
	)
	t.Setenv("OPENAI_API_KEY", realSecret)

	pipeline := buildPipeline(t, `
transforms:
  - name: allowlist
    config:
      domains:
        - "api.openai.com"
  - name: secrets
    config:
      source: env
      secrets:
        - var: OPENAI_API_KEY
          proxy_value: "proxy-openai-abc123"
          match_headers: ["Authorization"]
          hosts:
            - name: "api.openai.com"
`)

	var gotAuth string
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "rewritten")
	}))
	defer upstream.Close()

	_, httpAddr, _, caPool := startProxyWithPipeline(t, pipeline)
	upstreamAddr := upstream.Listener.Addr().String()

	origTransport := upstreamTransport
	upstreamTransport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, upstreamAddr)
		},
	}
	defer func() { upstreamTransport = origTransport }()

	proxyURL, err := url.Parse("http://" + httpAddr)
	require.NoError(t, err)

	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				RootCAs: caPool,
			},
		},
	}

	req, err := http.NewRequest("GET", "https://"+fakeHost+"/v1/models", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+proxyToken)

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "Bearer "+realSecret, gotAuth)
}

func TestHTTPProxy_UpstreamError(t *testing.T) {
	_, httpAddr, _, _ := startProxy(t)

	// Request to a host that won't connect
	req, err := http.NewRequest("GET", fmt.Sprintf("http://%s/test", httpAddr), nil)
	require.NoError(t, err)
	req.Host = "127.0.0.1:1" // nothing listening

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusBadGateway, resp.StatusCode)
}

func TestHTTPProxy_HeadersCopied(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Echo back a request header as a response header
		w.Header().Set("X-Echo", r.Header.Get("X-Custom"))
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	_, httpAddr, _, _ := startProxy(t)

	req, err := http.NewRequest("GET", fmt.Sprintf("http://%s/test", httpAddr), nil)
	require.NoError(t, err)
	req.Host = upstream.Listener.Addr().String()
	req.Header.Set("X-Custom", "test-value")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "test-value", resp.Header.Get("X-Echo"))
}

func TestHTTPProxy_WebSocketUpgrade(t *testing.T) {
	// Start a raw TCP server that speaks the WebSocket upgrade handshake
	upstreamLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer upstreamLn.Close()

	go func() {
		conn, err := upstreamLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Read the upgrade request
		buf := make([]byte, 4096)
		n, _ := conn.Read(buf)
		_ = n

		// Send upgrade response
		resp := "HTTP/1.1 101 Switching Protocols\r\n" +
			"Upgrade: websocket\r\n" +
			"Connection: Upgrade\r\n\r\n"
		_, _ = conn.Write([]byte(resp))

		// Echo loop: read and write back
		for {
			n, err := conn.Read(buf)
			if err != nil {
				break
			}
			_, _ = conn.Write(buf[:n])
		}
	}()

	_, httpAddr, _, _ := startProxy(t)

	// Dial the proxy as a raw TCP client
	conn, err := net.DialTimeout("tcp", httpAddr, 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	// Send WebSocket upgrade request through the proxy
	upgradeReq := fmt.Sprintf("GET /ws HTTP/1.1\r\n"+
		"Host: %s\r\n"+
		"Upgrade: websocket\r\n"+
		"Connection: Upgrade\r\n"+
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"+
		"Sec-WebSocket-Version: 13\r\n\r\n",
		upstreamLn.Addr().String())
	_, err = conn.Write([]byte(upgradeReq))
	require.NoError(t, err)

	// Read the 101 response
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	require.NoError(t, err)
	response := string(buf[:n])
	require.Contains(t, response, "101")
	require.Contains(t, response, "Upgrade")

	// Send data and expect echo
	_, err = conn.Write([]byte("hello websocket"))
	require.NoError(t, err)

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err = conn.Read(buf)
	require.NoError(t, err)
	require.Equal(t, "hello websocket", string(buf[:n]))
}

func TestHTTPProxy_SSEStreaming(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)

		flusher, ok := w.(http.Flusher)
		if !ok {
			return
		}

		events := []string{
			"data: event1\n\n",
			"data: event2\n\n",
			"data: event3\n\n",
		}
		for _, event := range events {
			_, _ = fmt.Fprint(w, event)
			flusher.Flush()
		}
	}))
	defer upstream.Close()

	_, httpAddr, _, _ := startProxy(t)

	req, err := http.NewRequest("GET", fmt.Sprintf("http://%s/events", httpAddr), nil)
	require.NoError(t, err)
	req.Host = upstream.Listener.Addr().String()

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.Equal(t, "text/event-stream", resp.Header.Get("Content-Type"))

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.Contains(t, string(body), "data: event1")
	require.Contains(t, string(body), "data: event2")
	require.Contains(t, string(body), "data: event3")
}
