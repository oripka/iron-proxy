package proxy

// The extension authenticates and admits each app/destination before opening
// this channel. Each channel is one UDP flow, not a general UDP relay socket.
import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ironsh/iron-proxy/internal/transform"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

const nativeDatagramLimit = 65507

func (p *Proxy) EnableNativeQUIC() { p.nativeQUIC = true }

func nativeHostname(value string) (string, bool) {
	value = strings.TrimSuffix(strings.ToLower(value), ".")
	if len(value) == 0 || len(value) > 253 || net.ParseIP(value) != nil {
		return "", false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", false
			}
		}
	}
	return value, true
}

func nativeHexIdentity(value string) bool {
	b, err := hex.DecodeString(value)
	return err == nil && len(b) == 32
}

func nativeQUICConfig() *quic.Config {
	return &quic.Config{
		Versions:             []quic.Version{quic.Version1, quic.Version2},
		HandshakeIdleTimeout: 3 * time.Second, MaxIdleTimeout: 30 * time.Second,
		InitialStreamReceiveWindow: 64 << 10, MaxStreamReceiveWindow: 256 << 10,
		InitialConnectionReceiveWindow: 256 << 10, MaxConnectionReceiveWindow: 1 << 20,
		MaxIncomingStreams: 32, MaxIncomingUniStreams: 8, Allow0RTT: false,
		EnableDatagrams: false, DisablePathMTUDiscovery: true,
	}
}

// Only peer TLS certificate alerts qualify. Local certificate verification,
// timeouts, EOF and arbitrary QUIC errors never train a compatibility exception.
func nativeQUICCertificateRejection(err error) bool {
	var transport *quic.TransportError
	if !errors.As(err, &transport) || !transport.Remote {
		return false
	}
	switch transport.ErrorCode {
	case 0x100 + 42, 0x100 + 43, 0x100 + 44, 0x100 + 45, 0x100 + 46, 0x100 + 48:
		return true
	default:
		return false
	}
}

func (p *Proxy) handleNativeQUIC(w http.ResponseWriter, r *http.Request, state *nativeInspection, admittedPort string, slots, requests chan struct{}) {
	address := r.Header.Get("X-Nosy-Destination")
	ip, port, err := net.SplitHostPort(address)
	host, hostnameOK := nativeHostname(r.Header.Get("X-Nosy-Hostname"))
	app, signedApp := r.Header.Get("X-Nosy-App"), r.Header.Get("X-Nosy-Capture-App")
	flow, revision := r.Header.Get("X-PacketSafari-Flow-ID"), r.Header.Get("X-Nosy-Policy-Revision")
	if r.Method != http.MethodPost || err != nil || net.ParseIP(ip) == nil || port != admittedPort ||
		!nativeHexIdentity(app) || !nativeHexIdentity(signedApp) || !nativeReference(flow, 100) || !nativeReference(revision, 64) {
		http.Error(w, "invalid admitted datagram flow", http.StatusBadRequest)
		return
	}
	report := func(outcome string) {
		reason := outcome
		if strings.HasPrefix(outcome, "unsupported_") {
			outcome = "unsupported"
		}
		if outcome == "trust_failed" {
			reason = "client_certificate_rejection"
		}
		if outcome == "handshake_timeout" || outcome == "transport_error" || outcome == "resource_limited" || outcome == "upstream_error" {
			outcome = "opaque"
		}
		p.logger.Info("native_inspection", slog.String("flow_id", flow), slog.String("policy_revision", revision),
			slog.String("inspection", outcome), slog.String("transport", "quic"), slog.String("reason", reason))
	}
	if !hostnameOK {
		report("unsupported_hostname")
		http.Error(w, "hostname unavailable", http.StatusUnprocessableEntity)
		return
	}
	select {
	case slots <- struct{}{}:
		defer func() { <-slots }()
	default:
		report("resource_limited")
		http.Error(w, "inspection capacity reached", 503)
		return
	}
	// Both the original destination and hostname must pass policy before any dial.
	allowed, denied, _ := p.tunnelTransformCheck(r.RemoteAddr, address, http.Header{})
	if denied != nil && denied.Body != nil {
		defer denied.Body.Close()
	}
	if !allowed {
		report("denied")
		http.Error(w, "destination denied", 403)
		return
	}
	allowed, denied, info := p.tunnelTransformCheck(r.RemoteAddr, net.JoinHostPort(host, port), http.Header{})
	if denied != nil && denied.Body != nil {
		defer denied.Body.Close()
	}
	if !allowed {
		report("denied")
		http.Error(w, "hostname denied", 403)
		return
	}
	parsed, err := netip.ParseAddr(ip)
	if err != nil || p.guard.IsDenied(parsed) {
		report("denied")
		http.Error(w, "destination denied", 403)
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "datagram channel unavailable", 500)
		return
	}
	conn, buffered, err := hijacker.Hijack()
	if err != nil {
		report("transport_error")
		return
	}
	defer conn.Close()
	if _, err := buffered.WriteString("HTTP/1.1 200 OK\r\n\r\n"); err != nil {
		report("transport_error")
		return
	}
	if err := buffered.Flush(); err != nil {
		report("transport_error")
		return
	}
	ctx, cancel := context.WithTimeout(p.shutdownCtx, 10*time.Minute)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	packets := &nativePacketConn{Conn: conn, reader: buffered.Reader}
	key := "quic|" + app + "|" + signedApp + "|" + address + "|" + host
	state.mu.Lock()
	until := state.failures[key]
	state.mu.Unlock()
	if time.Now().Before(until) && p.pipeline.Load().AllowsOpaqueConnections() {
		// No QUIC transport has consumed or emitted any packet on this attempt.
		// The authenticated hostname and exact endpoint must match the exception.
		report("certificate_compatibility")
		p.relayNativeUDP(ctx, packets, address, report)
		return
	}
	first := make([]byte, nativeDatagramLimit)
	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		report("transport_error")
		return
	}
	n, _, err := packets.ReadFrom(first)
	if err != nil {
		report("transport_error")
		return
	}
	// Admission is intentionally narrower than arbitrary UDP/443. quic-go still
	// authenticates/parses the packet; this only rejects obviously ineligible data.
	if n < 1200 || first[0]&0xc0 != 0xc0 {
		report("unsupported_transport")
		return
	}
	version := binary.BigEndian.Uint32(first[1:5])
	if version != 1 && version != 0x6b3343cf {
		report("unsupported_version")
		return
	}
	initialType := byte(0)
	if version == 0x6b3343cf {
		initialType = 1
	}
	if (first[0]>>4)&3 != initialType {
		report("unsupported_transport")
		return
	}
	packets.first = first[:n]
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		report("transport_error")
		return
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{http3.NextProtoH3}, SessionTicketsDisabled: true,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			name, ok := nativeHostname(hello.ServerName)
			if !ok || name != host {
				return nil, fmt.Errorf("native QUIC hostname mismatch")
			}
			return p.getCertificate(hello)
		}}
	configuration := nativeQUICConfig()
	var admitted atomic.Bool
	configuration.GetConfigForClient = func(*quic.ClientInfo) (*quic.Config, error) {
		if !admitted.CompareAndSwap(false, true) {
			return nil, fmt.Errorf("one QUIC connection per admitted flow")
		}
		return nil, nil
	}
	listener, err := quic.ListenEarly(packets, tlsConfig, configuration)
	if err != nil {
		report("transport_error")
		return
	}
	defer listener.Close()
	handshake, cancelHandshake := context.WithTimeout(ctx, 7*time.Second)
	defer cancelHandshake()
	client, err := listener.Accept(handshake)
	if err != nil {
		report("unsupported_handshake")
		return
	}
	defer client.CloseWithError(0, "session ended")
	select {
	case <-client.HandshakeComplete():
	case <-client.Context().Done():
		if nativeQUICCertificateRejection(context.Cause(client.Context())) {
			if p.pipeline.Load().AllowsOpaqueConnections() {
				state.remember(key)
			}
			report("trust_failed")
		} else {
			report("unsupported_handshake")
		}
		return
	case <-handshake.Done():
		report("handshake_timeout")
		return
	}
	upstreamTLS := p.transport.TLSClientConfig.Clone()
	upstreamTLS.InsecureSkipVerify = false
	upstreamTLS.ServerName = host
	upstreamTLS.MinVersion = tls.VersionTLS13
	upstreamTLS.NextProtos = []string{http3.NextProtoH3}
	upstreamConfig := nativeQUICConfig()
	upstreamConfig.Versions = []quic.Version{quic.Version1}
	upstream := &http3.Transport{TLSClientConfig: upstreamTLS, QUICConfig: upstreamConfig, DisableCompression: true, MaxResponseHeaderBytes: 32 << 10,
		Dial: func(ctx context.Context, authority string, config *tls.Config, qc *quic.Config) (*quic.Conn, error) {
			name, _, err := net.SplitHostPort(authority)
			if err != nil || name != host || config.ServerName != host {
				return nil, fmt.Errorf("native QUIC authority mismatch")
			}
			return quic.DialAddr(ctx, address, config, qc)
		}}
	defer upstream.Close()
	scoped := *p
	scoped.nativeTransport = nativeQUICUpstream{transport: upstream, logger: p.logger, flow: flow}
	var sequence atomic.Uint64
	var once sync.Once
	server := &http3.Server{MaxHeaderBytes: 32 << 10, IdleTimeout: 30 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, inner *http.Request) {
			requestID := fmt.Sprintf("%s:%d", flow, sequence.Add(1))
			requestInfo := cloneTunnelInfo(info)
			if requestInfo == nil {
				requestInfo = &transform.TunnelInfo{Target: address}
			}
			requestInfo.Native = &transform.NativeFlowInfo{FlowID: flow, PolicyRevision: revision, RequestID: requestID}
			reject := func(status int, reason string) {
				scoped.rejectNativeQUICRequest(w, inner, host, status, reason, requestInfo)
			}
			select {
			case requests <- struct{}{}:
				defer func() { <-requests }()
			default:
				reject(http.StatusServiceUnavailable, "native_http3_capacity")
				return
			}
			// Extended CONNECT, WebTransport and datagrams are not silently mapped
			// onto ordinary requests. HTTP/3 settings do not advertise those features.
			if inner.Method == http.MethodConnect || inner.Header.Get("Upgrade") != "" {
				report("unsupported_protocol")
				reject(http.StatusNotImplemented, "native_http3_protocol")
				return
			}
			authority := inner.Host
			if name, authorityPort, err := net.SplitHostPort(authority); err == nil {
				if authorityPort != port {
					reject(http.StatusMisdirectedRequest, "native_http3_authority")
					return
				}
				authority = name
			}
			name, ok := nativeHostname(authority)
			if !ok || name != host || inner.TLS == nil || inner.TLS.ServerName != host {
				reject(http.StatusMisdirectedRequest, "native_http3_authority")
				return
			}
			defer p.observeNativePrivacy(inner, flow, requestID)()
			for _, h := range []string{"Proxy-Authorization", "X-Nosy-App", "X-Nosy-Capture-App", "X-Nosy-Destination", "X-Nosy-Hostname", "X-PacketSafari-Flow-ID", "X-Nosy-Policy-Revision", "X-Nosy-Inspection-Session", "X-Nosy-Inspection-Version"} {
				inner.Header.Del(h)
			}
			once.Do(func() { report("reported_decrypted") })
			scoped.handleHTTP(w, inner, requestInfo)
		})}
	_ = server.ServeQUICConn(client) // Connection shutdown is not a new inspection verdict.
}

// These are admission decisions, not evidence that decrypted HTTP rules ran.
// Use the approved hostname and fixed reason codes, never the rejected authority.
func (p *Proxy) rejectNativeQUICRequest(w http.ResponseWriter, r *http.Request, host string, status int, reason string, info *transform.TunnelInfo) {
	trace := transform.TransformTrace{Name: reason, Action: transform.ActionReject}
	result := &transform.PipelineResult{Host: host, Method: r.Method, Mode: transform.ModeMITM,
		Tunnel: info, Action: transform.ActionReject, StatusCode: status}
	if status == http.StatusServiceUnavailable {
		result.Action = transform.ActionContinue
		result.Err = errors.New(reason)
		trace.Action = transform.ActionContinue
		trace.Err = result.Err
	}
	result.RequestTransforms = []transform.TransformTrace{trace}
	_, finish := p.beginPipelineRun(result)
	defer finish()
	http.Error(w, http.StatusText(status), status)
}

type nativeQUICUpstream struct {
	transport *http3.Transport
	logger    *slog.Logger
	flow      string
}

func (u nativeQUICUpstream) RoundTrip(r *http.Request) (*http.Response, error) {
	response, err := u.transport.RoundTrip(r)
	if err != nil {
		code := "upstream_transport"
		var unknown x509.UnknownAuthorityError
		var hostname x509.HostnameError
		var invalid x509.CertificateInvalidError
		var remote *quic.TransportError
		switch {
		case errors.As(err, &unknown), errors.As(err, &hostname), errors.As(err, &invalid):
			code = "upstream_certificate_validation"
		case errors.Is(err, context.Canceled):
			code = "request_cancelled"
		case errors.As(err, &remote) && remote.Remote && remote.ErrorCode == 0x174:
			code = "upstream_client_certificate_required"
		}
		u.logger.Info("native_transport", slog.String("flow_id", u.flow), slog.String("phase", "upstream"), slog.String("code", code))
	}
	return response, err
}

// nativePacketConn uses a two-byte network-order length followed by exactly one
// datagram. Blocking writes propagate backpressure; there is no unbounded queue.
type nativePacketConn struct {
	net.Conn
	reader  *bufio.Reader
	first   []byte
	writeMu sync.Mutex
}

func (c *nativePacketConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}
}
func (c *nativePacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2}
	if c.first != nil {
		if len(c.first) > len(b) {
			return 0, nil, io.ErrShortBuffer
		}
		n := copy(b, c.first)
		c.first = nil
		return n, peer, nil
	}
	var head [2]byte
	if _, err := io.ReadFull(c.reader, head[:]); err != nil {
		return 0, nil, err
	}
	n := int(binary.BigEndian.Uint16(head[:]))
	if n == 0 || n > nativeDatagramLimit || n > len(b) {
		return 0, nil, fmt.Errorf("datagram limit")
	}
	_, err := io.ReadFull(c.reader, b[:n])
	return n, peer, err
}
func (c *nativePacketConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	if len(b) == 0 || len(b) > nativeDatagramLimit {
		return 0, fmt.Errorf("datagram limit")
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if err := c.Conn.SetWriteDeadline(time.Now().Add(3 * time.Second)); err != nil {
		return 0, err
	}
	var head [2]byte
	binary.BigEndian.PutUint16(head[:], uint16(len(b)))
	frames := net.Buffers{head[:], b}
	if _, err := frames.WriteTo(c.Conn); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (p *Proxy) relayNativeUDP(ctx context.Context, client *nativePacketConn, address string, report func(string)) {
	dialer := net.Dialer{Timeout: 3 * time.Second, Control: p.guard.DialControl}
	upstream, err := dialer.DialContext(ctx, "udp", address)
	if err != nil {
		report("upstream_error")
		return
	}
	defer upstream.Close()
	stop := context.AfterFunc(ctx, func() { upstream.Close(); client.Close() })
	defer stop()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer upstream.Close()
		b := make([]byte, nativeDatagramLimit)
		for {
			if err := client.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
				return
			}
			n, _, err := client.ReadFrom(b)
			if err != nil {
				return
			}
			if err := upstream.SetWriteDeadline(time.Now().Add(3 * time.Second)); err != nil {
				return
			}
			if _, err := upstream.Write(b[:n]); err != nil {
				return
			}
		}
	}()
	b := make([]byte, nativeDatagramLimit)
	for {
		if err := upstream.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
			break
		}
		n, err := upstream.Read(b)
		if err != nil {
			break
		}
		if _, err := client.WriteTo(b[:n], nil); err != nil {
			break
		}
	}
	client.Close()
	upstream.Close()
	<-done
}

func (p *Proxy) observeNativePrivacy(inner *http.Request, flow, requestID string) func() {
	host := inner.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if !p.browserPrivacy || !privacyVendor(host) {
		return func() {}
	}
	finish := observePrivacy(inner)
	var once sync.Once
	emit := func() {
		once.Do(func() {
			p.logger.Info("browser_privacy", slog.String("flow_id", flow), slog.String("request_id", requestID), slog.String("host", strings.TrimSuffix(strings.ToLower(host), ".")), slog.Any("summary", finish()))
		})
	}
	if body, ok := inner.Body.(*privacyBody); ok {
		body.onComplete = emit
	} else {
		emit()
	}
	return emit
}
