package proxy

import (
	"crypto/tls"
	"log/slog"
	"sync"
)

// Negotiated, non-secret metadata only. Do not include certificates, names,
// key material, or peer-provided strings in this event.
type nativeTLSSecurity struct {
	Version              uint16 `json:"version"`
	Cipher               uint16 `json:"cipher"`
	Group                uint16 `json:"group"`
	ALPN                 string `json:"alpn"`
	Resumed              bool   `json:"resumed"`
	PeerKey              string `json:"peer_key"`
	CertificateSignature string `json:"certificate_signature"`
}

func nativeTLSState(s tls.ConnectionState) nativeTLSSecurity {
	alpn := "other"
	switch s.NegotiatedProtocol {
	case "", "h2", "http/1.1":
		alpn = s.NegotiatedProtocol
	}
	result := nativeTLSSecurity{Version: s.Version, Cipher: s.CipherSuite, Group: uint16(s.CurveID), ALPN: alpn, Resumed: s.DidResume}
	if len(s.PeerCertificates) > 0 {
		result.PeerKey = s.PeerCertificates[0].PublicKeyAlgorithm.String()
		result.CertificateSignature = s.PeerCertificates[0].SignatureAlgorithm.String()
	}
	return result
}

// At most eight distinct negotiated variants per leg, plus a truncation marker.
// A tunnel can open multiple upstream connections; never overwrite classical
// evidence with a later post-quantum handshake.
func nativeTLSReporter(logger *slog.Logger, flow, revision, session string) func(string, tls.ConnectionState) {
	var mu sync.Mutex
	seen := map[string]map[nativeTLSSecurity]bool{}
	overflow := map[string]bool{}
	return func(leg string, s tls.ConnectionState) {
		if !s.HandshakeComplete {
			return
		}
		value := nativeTLSState(s)
		mu.Lock()
		defer mu.Unlock()
		if seen[leg] == nil {
			seen[leg] = map[nativeTLSSecurity]bool{}
		}
		if seen[leg][value] {
			return
		}
		attrs := []any{slog.String("flow_id", flow), slog.String("policy_revision", revision), slog.String("inspection_session", session), slog.String("leg", leg)}
		if len(seen[leg]) >= 8 {
			if !overflow[leg] {
				overflow[leg] = true
				logger.Info("native_tls_security", append(attrs, slog.Bool("truncated", true))...)
			}
			return
		}
		seen[leg][value] = true
		logger.Info("native_tls_security", append(attrs, slog.Any("tls", value))...)
	}
}
