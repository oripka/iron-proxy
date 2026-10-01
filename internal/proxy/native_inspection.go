package proxy

// Native inspection is a dedicated, authenticated listener. The native firewall
// admits the original app/endpoint before issuing CONNECT. Every dial remains
// pinned to that admitted IP:port; HTTP Host/SNI cannot pivot the destination.
import (
	"bufio"
	"bytes"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ironsh/iron-proxy/internal/transform"
)

type nativeInspection struct {
	token      string
	failClosed bool
	slots      chan struct{}
	mu         sync.Mutex
	failures   map[string]time.Time
	nextPrune  time.Time
}

// Prune at most once per minute, not once per rejected handshake at capacity.
func (s *nativeInspection) remember(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	if len(s.failures) >= 4096 && now.After(s.nextPrune) {
		for key, until := range s.failures {
			if now.After(until) {
				delete(s.failures, key)
			}
		}
		s.nextPrune = now.Add(time.Minute)
	}
	if _, exists := s.failures[key]; exists || len(s.failures) < 4096 {
		s.failures[key] = now.Add(10 * time.Minute)
	}
}

// EnableNativeInspection must be called before ListenAndServe. No ordinary
// proxy, secret-injection or watched-run listener uses this fallback path.
func (p *Proxy) EnableNativeInspection(token string, failClosed bool) error {
	return p.enableNativeInspection(token, failClosed, "443")
}

func (p *Proxy) EnableNativeInspectionV2(token string) error {
	return p.enableNativeInspection(token, true, "443", true)
}

func (p *Proxy) enableNativeInspection(token string, failClosed bool, admittedPort string, requireV2 ...bool) error {
	host, _, err := net.SplitHostPort(p.httpServer.Addr)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() || len(token) != 64 || p.certCache == nil || p.httpsAddr != "" || p.tunnelAddr != "" {
		return fmt.Errorf("native inspection requires a dedicated loopback HTTP listener, a CA, and a 64-character token")
	}
	if _, err := hex.DecodeString(token); err != nil {
		return fmt.Errorf("invalid native inspection token")
	}
	state := &nativeInspection{token: token, failClosed: failClosed, slots: make(chan struct{}, 512), failures: make(map[string]time.Time)}
	p.httpServer.ReadHeaderTimeout = 10 * time.Second
	p.httpServer.MaxHeaderBytes = 16 * 1024
	p.httpServer.IdleTimeout = 30 * time.Second
	var connections atomic.Int32
	p.httpServer.ConnState = func(c net.Conn, s http.ConnState) {
		if s == http.StateNew && connections.Add(1) > 512 {
			c.Close()
		}
		if s == http.StateClosed || s == http.StateHijacked {
			connections.Add(-1)
		}
	}
	requestSlots := make(chan struct{}, 512)
	p.httpServer.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("Proxy-Authorization")), []byte("Bearer "+state.token)) != 1 {
			http.Error(w, "unauthorized", 407)
			return
		}
		if r.Method != http.MethodConnect {
			http.Error(w, "CONNECT required", 405)
			return
		}
		ip, port, err := net.SplitHostPort(r.Host)
		app, flow := r.Header.Get("X-Nosy-App"), r.Header.Get("X-PacketSafari-Flow-ID")
		revision, session := r.Header.Get("X-Nosy-Policy-Revision"), r.Header.Get("X-Nosy-Inspection-Session")
		v2 := r.Header.Get("X-Nosy-Inspection-Version") == "2"
		if (len(requireV2) > 0 && requireV2[0] && !v2) || (v2 && (!nativeReference(revision, 64) || !nativeReference(session, 64))) {
			http.Error(w, "native inspection v2 provenance required", 400)
			return
		}
		if err != nil || net.ParseIP(ip) == nil || port != admittedPort || len(app) != 64 || len(flow) == 0 || len(flow) > 100 {
			http.Error(w, "invalid admitted endpoint", 400)
			return
		}
		if _, err := hex.DecodeString(app); err != nil {
			http.Error(w, "invalid app identity", 400)
			return
		}
		for _, c := range flow {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == ':') {
				http.Error(w, "invalid flow identity", 400)
				return
			}
		}
		select {
		case state.slots <- struct{}{}:
			defer func() { <-state.slots }()
		default:
			http.Error(w, "inspection capacity reached", 503)
			return
		}
		// The pipeline still gates every CONNECT and every decrypted HTTP request.
		headers := r.Header.Clone()
		headers.Del("Proxy-Authorization")
		headers.Del("X-Nosy-App")
		headers.Del("X-PacketSafari-Flow-ID")
		headers.Del("X-Nosy-Policy-Revision")
		headers.Del("X-Nosy-Inspection-Session")
		headers.Del("X-Nosy-Inspection-Version")
		var info *transform.TunnelInfo
		if !v2 {
			allowed, rejected, admitted := p.tunnelTransformCheck(r.RemoteAddr, r.Host, headers)
			if !allowed {
				if rejected != nil && rejected.Body != nil {
					rejected.Body.Close()
				}
				http.Error(w, "destination denied", 403)
				return
			}
			info = admitted
		}
		report := func(outcome string) {
			p.logger.Info("native_inspection", slog.String("flow_id", flow), slog.String("inspection", outcome), slog.String("policy_revision", revision), slog.String("inspection_session", session))
		}
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "CONNECT unavailable", 500)
			return
		}
		conn, buf, err := hj.Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		if _, err = buf.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			return
		}
		if err = buf.Flush(); err != nil {
			return
		}
		// Parent cancellation closes hijacked streams, including idle connections.
		done := make(chan struct{})
		defer close(done)
		go func() {
			select {
			case <-p.shutdownCtx.Done():
				conn.Close()
			case <-done:
			}
		}()
		client := &bufferedConn{Conn: conn, reader: buf.Reader}
		sni, peeked, err := peekSNI(client, 10*time.Second)
		if err != nil || (v2 && sni == "") {
			report("unsupported")
			return
		}
		if v2 {
			allowed, rejected, admitted := p.tunnelTransformCheck(r.RemoteAddr, net.JoinHostPort(sni, port), headers)
			if !allowed {
				if rejected != nil && rejected.Body != nil {
					rejected.Body.Close()
				}
				report("inspection_required")
				return
			}
			info = admitted
		}
		client = &bufferedConn{Conn: client, reader: bufio.NewReader(io.MultiReader(bytes.NewReader(peeked), client))}
		key := app + "|" + r.Host + "|" + strings.ToLower(sni)
		state.mu.Lock()
		until := state.failures[key]
		state.mu.Unlock()
		opaque := sni == "" || time.Now().Before(until)
		if opaque && state.failClosed {
			report("inspection_required")

			return
		}
		dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second, Control: p.guard.DialControl}
		if opaque {
			upstream, err := dialer.DialContext(p.shutdownCtx, "tcp", r.Host)
			if err != nil {
				report("opaque")
				return
			}
			defer upstream.Close()
			report("bypassed")
			copied := make(chan struct{})
			go func() {
				_, _ = io.Copy(upstream, client)
				if tcp, ok := upstream.(*net.TCPConn); ok {
					_ = tcp.CloseWrite()
				}
				close(copied)
			}()
			_, _ = io.Copy(client, upstream)
			conn.Close()
			upstream.Close()
			<-copied
			return
		}
		tlsConn := tls.Server(client, &tls.Config{GetCertificate: p.getCertificate, MinVersion: tls.VersionTLS12, NextProtos: []string{"h2", "http/1.1"}})
		ctx, cancel := context.WithTimeout(p.shutdownCtx, 10*time.Second)
		err = tlsConn.HandshakeContext(ctx)
		cancel()
		if err != nil {
			// Only client certificate rejection qualifies for compatibility fallback.
			// EOF, timeouts and upstream failures never train a bypass.
			text := err.Error()
			rejected := strings.Contains(text, "remote error: tls:") && (strings.Contains(text, "certificate") || strings.Contains(text, "unknown certificate authority"))
			if rejected {
				state.remember(key)
				if state.failClosed {
					report("inspection_required")
				} else {
					report("trust_failed")
				}
			} else {
				report("opaque")
			}
			return
		}
		defer tlsConn.Close()
		// Each active tunnel owns one small transport, reusing upstream connections
		// for its HTTP/1 keep-alives and HTTP/2 streams. No cross-app connection pool.
		transport := p.transport.Clone()
		transport.MaxConnsPerHost = 4
		transport.MaxIdleConns = 4
		transport.MaxIdleConnsPerHost = 4
		transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp", r.Host)
		}
		transport.Proxy = nil
		defer transport.CloseIdleConnections()
		scoped := *p
		scoped.transport = transport
		var reported sync.Once
		var requestSequence atomic.Uint64
		if err := serveOneHTTPConn(tlsConn, http.HandlerFunc(func(w http.ResponseWriter, inner *http.Request) {
			select {
			case requestSlots <- struct{}{}:
				defer func() { <-requestSlots }()
			default:
				http.Error(w, "inspection request capacity reached", 503)
				return
			}
			requestID := fmt.Sprintf("%s:%d", flow, requestSequence.Add(1))
			observed := &nativeResponseWriter{ResponseWriter: w, status: 200}
			defer func() {
				outcome := "response-only" // HTTP status alone is not a policy verdict.
				p.logger.Info("native_http_request", slog.String("flow_id", flow), slog.String("policy_revision", revision),
					slog.String("inspection_session", session), slog.String("request_id", requestID),
					slog.String("method", inner.Method), slog.String("host", inner.Host), slog.String("path", inner.URL.EscapedPath()),
					slog.Int("status_code", observed.status), slog.String("outcome", outcome))
			}()
			w = observed
			// These are authenticated tunnel metadata, never request headers.
			for _, key := range []string{"Proxy-Authorization", "X-Nosy-App", "X-PacketSafari-Flow-ID", "X-Nosy-Policy-Revision", "X-Nosy-Inspection-Session", "X-Nosy-Inspection-Version"} {
				inner.Header.Del(key)
			}
			reported.Do(func() { report("reported_decrypted") })
			// Upgrades use a separate dial path in the generic proxy. Do not allow
			// that path to escape the native endpoint pinning contract.
			if inner.Header.Get("Upgrade") != "" || inner.Method == http.MethodConnect {
				state.remember(key)
				http.Error(w, "upgrade unsupported by native inspection", 501)
				if state.failClosed {
					report("inspection_required")
				} else {
					report("unsupported")
				}
				return
			}
			requestInfo := cloneTunnelInfo(info)
			if requestInfo == nil {
				requestInfo = &transform.TunnelInfo{Target: r.Host}
			}
			requestInfo.Native = &transform.NativeFlowInfo{FlowID: flow, PolicyRevision: revision, InspectionSession: session, RequestID: requestID}
			scoped.handleHTTP(w, inner, requestInfo)
		})); err != nil {
			p.logger.Debug("native inspection connection ended", slog.String("flow_id", flow))
		}
	})
	return nil
}

// References are metadata, never executable header fragments.
func nativeReference(value string, max int) bool {
	if len(value) == 0 || len(value) > max {
		return false
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == ':') {
			return false
		}
	}
	return true
}

type nativeResponseWriter struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (w *nativeResponseWriter) WriteHeader(status int) {
	if !w.wrote {
		w.status = status
		w.wrote = true
		w.ResponseWriter.WriteHeader(status)
	}
}
func (w *nativeResponseWriter) Write(b []byte) (int, error) {
	if !w.wrote {
		w.WriteHeader(200)
	}
	return w.ResponseWriter.Write(b)
}
func (w *nativeResponseWriter) Flush() {
	if !w.wrote {
		w.WriteHeader(200)
	}
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
func (w *nativeResponseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
