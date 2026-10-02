package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ironsh/iron-proxy/internal/certcache"
	"github.com/stretchr/testify/require"
)

func armCapture(t *testing.T, c *nativeCapture) string {
	t.Helper()
	r := httptest.NewRequest("POST", "/nosy/capture", strings.NewReader(`{"application":"`+strings.Repeat("b", 64)+`","serverName":"localhost"}`))
	w := httptest.NewRecorder()
	c.control(w, r)
	require.Equal(t, 200, w.Code)
	var s captureStatus
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &s))
	t.Cleanup(func() { c.mu.Lock(); defer c.mu.Unlock(); c.clearLocked() })
	return s.ID
}
func TestTargetCaptureScopeAndLimits(t *testing.T) {
	c := &nativeCapture{}
	id := armCapture(t, c)
	cases := []struct{ app, endpoint, name string }{{strings.Repeat("c", 64), "203.0.113.7:443", "localhost"}, {strings.Repeat("b", 64), "203.0.113.7:443", "other"}}
	for _, tc := range cases {
		require.Nil(t, c.begin(tc.app, tc.endpoint, tc.name, "unrelated"))
	}
	s := c.begin(strings.Repeat("b", 64), "203.0.113.7:443", "localhost", "selected")
	require.NotNil(t, s)
	require.NotNil(t, c.begin(strings.Repeat("b", 64), "203.0.113.8:443", "localhost", "second"))
	s.record(0, make([]byte, captureLimit+1))
	require.Equal(t, "ready", c.status.State)
	require.LessOrEqual(t, c.data.Len(), captureLimit)
	w := httptest.NewRecorder()
	c.control(w, httptest.NewRequest("GET", "/nosy/capture/export?id=wrong", nil))
	require.Equal(t, 404, w.Code)
	w = httptest.NewRecorder()
	c.control(w, httptest.NewRequest("DELETE", "/nosy/capture?id="+id, nil))
	require.Equal(t, 200, w.Code)
	require.Zero(t, c.data.Len())
	require.Zero(t, c.keys.Len())
	n, e := s.Write([]byte("late secret"))
	require.NoError(t, e)
	require.Equal(t, 11, n)
	require.Zero(t, c.keys.Len())
}
func TestTargetCaptureRealTLSWireshark(t *testing.T) {
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		t.Run(tls.VersionName(version), func(t *testing.T) {
			c := &nativeCapture{}
			id := armCapture(t, c)
			for i := 0; i < 3; i++ {
				s := c.begin(strings.Repeat("b", 64), "203.0.113.7:443", "localhost", "selected")
				ca, key := generateTestCA(t)
				cache, e := certcache.NewFromCA(ca, key, 16, time.Hour)
				require.NoError(t, e)
				// Reuse the production certificate callback from the native inspection proxy.
				p := New(Options{CertCache: cache})
				pool := x509.NewCertPool()
				pool.AddCert(ca)
				left, right := net.Pipe()
				defer left.Close()
				defer right.Close()
				require.NoError(t, left.SetDeadline(time.Now().Add(5*time.Second)))
				require.NoError(t, right.SetDeadline(time.Now().Add(5*time.Second)))
				server := tls.Server(&captureConn{Conn: left, capture: s}, &tls.Config{GetCertificate: p.getCertificate, MinVersion: version, MaxVersion: version, KeyLogWriter: s})
				client := tls.Client(right, &tls.Config{RootCAs: pool, ServerName: "localhost", MinVersion: version, MaxVersion: version})
				done := make(chan error, 1)
				go func() {
					if e := server.HandshakeContext(context.Background()); e != nil {
						done <- e
						return
					}
					r := bufio.NewReader(server)
					for {
						line, e := r.ReadString('\n')
						if e != nil {
							done <- e
							return
						}
						if line == "\r\n" {
							break
						}
					}
					_, e := io.WriteString(server, "HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\ncapture-proof")
					done <- e
				}()
				require.NoError(t, client.HandshakeContext(context.Background()))
				_, e = io.WriteString(client, "GET /nosy-capture-proof HTTP/1.1\r\nHost: localhost\r\n\r\n")
				require.NoError(t, e)
				b := make([]byte, len("HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\ncapture-proof"))
				_, e = io.ReadFull(client, b)
				require.NoError(t, e)
				require.NoError(t, <-done)
				s.finish()
				require.Equal(t, "capturing", c.status.State, "one connection ending must not end the session")
			}
			require.Equal(t, 3, c.status.Connections)
			c.mu.Lock()
			c.finishLocked("Stopped by user")
			c.mu.Unlock()
			w := httptest.NewRecorder()
			c.control(w, httptest.NewRequest("GET", "/nosy/capture/export?id="+id, nil))
			require.Equal(t, 200, w.Code)
			raw := w.Body.Bytes()
			// Every block is aligned and self-delimiting; TLS secrets are in a DSB.
			blocks := 0
			for pos := 0; pos < len(raw); {
				require.GreaterOrEqual(t, len(raw)-pos, 12)
				n := int(binary.LittleEndian.Uint32(raw[pos+4:]))
				require.GreaterOrEqual(t, n, 12)
				require.LessOrEqual(t, pos+n, len(raw))
				require.Equal(t, uint32(n), binary.LittleEndian.Uint32(raw[pos+n-4:]))
				pos += n
				blocks++
			}
			require.Greater(t, blocks, 6)
			if version == tls.VersionTLS12 {
				require.True(t, bytes.Contains(raw, []byte("CLIENT_RANDOM")))
			}
			if version == tls.VersionTLS13 {
				require.True(t, bytes.Contains(raw, []byte("CLIENT_TRAFFIC_SECRET_0")))
			}
			path := filepath.Join(t.TempDir(), "capture.pcapng")
			require.NoError(t, os.WriteFile(path, raw, 0600))
			tshark, e := exec.LookPath("tshark")
			if e != nil {
				t.Log("Wireshark validation unavailable; set PATH to include tshark")
				return
			}
			cmd := exec.Command(tshark, "-r", path, "-Y", "http.request", "-T", "fields", "-e", "http.request.uri")
			out, e := cmd.CombinedOutput()
			require.NoError(t, e, string(out))
			require.Equal(t, 3, strings.Count(string(out), "/nosy-capture-proof"))
			cmd = exec.Command(tshark, "-r", path, "-Y", "http.response", "-T", "fields", "-e", "http.response.code")
			out, e = cmd.CombinedOutput()
			require.NoError(t, e, string(out))
			require.Contains(t, string(out), "200")
			// Removing the secrets must remove decrypted HTTP visibility.
			var noSecrets bytes.Buffer
			for pos := 0; pos < len(raw); {
				n := int(binary.LittleEndian.Uint32(raw[pos+4:]))
				if binary.LittleEndian.Uint32(raw[pos:]) != 10 {
					noSecrets.Write(raw[pos : pos+n])
				}
				pos += n
			}
			require.NoError(t, os.WriteFile(path, noSecrets.Bytes(), 0600))
			out, e = exec.Command(tshark, "-r", path, "-Y", "http.request", "-T", "fields", "-e", "http.request.uri").CombinedOutput()
			require.NoError(t, e, string(out))
			require.NotContains(t, string(out), "/nosy-capture-proof")
		})
	}
}
func TestTargetCaptureControlRequiresNativeAuthentication(t *testing.T) {
	p, _, _, _, _ := nativeFixture(t, true)
	w := httptest.NewRecorder()
	p.httpServer.Handler.ServeHTTP(w, httptest.NewRequest("POST", "/nosy/capture", strings.NewReader(`{}`)))
	require.Equal(t, 407, w.Code)
}

func TestTargetCaptureNativeListenerReplaysClientHello(t *testing.T) {
	p, _, _, pool, _ := nativeFixture(t, true)
	require.NoError(t, p.enableNativeInspection(strings.Repeat("a", 64), true, "443"))
	host := httptest.NewServer(p.httpServer.Handler)
	defer host.Close()
	call := func(method, path string, body io.Reader) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, body)
		r.Header.Set("Proxy-Authorization", "Bearer "+strings.Repeat("a", 64))
		w := httptest.NewRecorder()
		p.httpServer.Handler.ServeHTTP(w, r)
		return w
	}
	w := call("POST", "/nosy/capture", strings.NewReader(`{"application":"`+strings.Repeat("b", 64)+`","serverName":"localhost"}`))
	require.Equal(t, 200, w.Code)
	var status captureStatus
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &status))
	client, e := nativeConnect(t, host.Listener.Addr().String(), "127.0.0.1:443", strings.Repeat("b", 64), pool)
	require.NoError(t, e)
	require.NoError(t, client.Close())
	require.Eventually(t, func() bool {
		reply := call("GET", "/nosy/capture?id="+status.ID, nil)
		var now captureStatus
		if json.Unmarshal(reply.Body.Bytes(), &now) != nil {
			return false
		}
		return now.Connections == 1 && now.Active == 0
	}, time.Second, 10*time.Millisecond)
	require.Equal(t, 200, call("POST", "/nosy/capture/stop?id="+status.ID, nil).Code)
	reply := call("GET", "/nosy/capture/export?id="+status.ID, nil)
	require.Equal(t, 200, reply.Code)
	raw := reply.Body.Bytes()
	require.True(t, bytes.Contains(raw, []byte("CLIENT_HANDSHAKE_TRAFFIC_SECRET")))
	// Replayed ClientHello must be present at the start of the captured TLS stream.
	found := false
	for pos := 0; pos < len(raw); {
		n := int(binary.LittleEndian.Uint32(raw[pos+4:]))
		if binary.LittleEndian.Uint32(raw[pos:]) == 6 && n > 80 {
			packet := raw[pos+28 : pos+n-4]
			if len(packet) > 45 && packet[40] == 22 && packet[45] == 1 {
				found = true
			}
		}
		pos += n
	}
	require.True(t, found)
	require.Equal(t, 200, call("DELETE", "/nosy/capture?id="+status.ID, nil).Code)
}

func TestTargetCaptureControlBoundsAndStop(t *testing.T) {
	cases := []string{`{}`, `{"application":"bad"}`, `{"application":"` + strings.Repeat("b", 64) + `","endpoint":"203.0.113.7:80"}`, `{"application":"` + strings.Repeat("b", 64) + `","endpoint":"example.com:443"}`, `{"unknown":true}`}
	for _, body := range cases {
		t.Run(body, func(t *testing.T) {
			c := &nativeCapture{}
			w := httptest.NewRecorder()
			c.control(w, httptest.NewRequest("POST", "/nosy/capture", strings.NewReader(body)))
			require.Equal(t, 400, w.Code)
			require.Empty(t, c.status.ID)
		})
	}
	c := &nativeCapture{}
	id := armCapture(t, c)
	w := httptest.NewRecorder()
	c.control(w, httptest.NewRequest("POST", "/nosy/capture", strings.NewReader(`{}`)))
	require.Equal(t, 409, w.Code)
	s := c.begin(strings.Repeat("b", 64), "203.0.113.7:443", "localhost", "selected")
	_, e := s.Write([]byte("test-secret\n"))
	require.NoError(t, e)
	w = httptest.NewRecorder()
	c.control(w, httptest.NewRequest("POST", "/nosy/capture/stop?id="+id, nil))
	require.Equal(t, 200, w.Code)
	require.NotContains(t, w.Body.String(), "test-secret")
	size := c.data.Len()
	keys := c.keys.Len()
	s.record(0, []byte("after stop"))
	_, e = s.Write([]byte("later key"))
	require.NoError(t, e)
	require.Equal(t, size, c.data.Len())
	require.Equal(t, keys, c.keys.Len())
}

func TestCaptureSessionScopes(t *testing.T) {
	cases := []struct {
		name      string
		target    captureTarget
		app, host string
		want      bool
	}{
		{"app across domains", captureTarget{Application: "app"}, "app", "different.test", true},
		{"other app excluded", captureTarget{Application: "app"}, "other", "same.test", false},
		{"missing provider identity excluded", captureTarget{Application: "app"}, "", "same.test", false},
		{"domain across apps", captureTarget{ServerName: "example.com"}, "other", "EXAMPLE.COM.", true},
		{"exact excludes children", captureTarget{ServerName: "example.com"}, "app", "a.example.com", false},
		{"children included", captureTarget{ServerName: "example.com", IncludeSubdomains: true}, "app", "a.example.com", true},
		{"suffix confusion excluded", captureTarget{ServerName: "example.com", IncludeSubdomains: true}, "app", "evilexample.com", false},
		{"combined wrong app", captureTarget{Application: "app", ServerName: "example.com"}, "other", "example.com", false},
		{"combined wrong host", captureTarget{Application: "app", ServerName: "example.com"}, "app", "other.test", false},
		{"combined matches", captureTarget{Application: "app", ServerName: "example.com"}, "app", "example.com", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { require.Equal(t, tc.want, tc.target.matches(tc.app, tc.host)) })
	}
}
func TestCaptureSessionConcurrentStreamsAndGeneration(t *testing.T) {
	c := &nativeCapture{}
	id := armCapture(t, c)
	var group sync.WaitGroup
	for i := 0; i < 64; i++ {
		group.Add(1)
		go func(i int) {
			defer group.Done()
			s := c.begin(strings.Repeat("b", 64), "203.0.113.7:443", "localhost", fmt.Sprint(i))
			if s == nil {
				return
			}
			for j := 0; j < 16; j++ {
				s.record(i%2, []byte("interleaved traffic"))
			}
			s.finish()
			s.finish()
		}(i)
	}
	group.Wait()
	require.Equal(t, 64, c.status.Connections)
	require.Zero(t, c.status.Active)
	require.Equal(t, "capturing", c.status.State)
	old := c.begin(strings.Repeat("b", 64), "203.0.113.7:443", "localhost", "old")
	w := httptest.NewRecorder()
	c.control(w, httptest.NewRequest("DELETE", "/nosy/capture?id="+id, nil))
	require.Equal(t, 200, w.Code)
	armCapture(t, c)
	old.record(0, []byte("old session"))
	_, err := old.Write([]byte("old secret"))
	require.NoError(t, err)
	old.finish()
	require.Zero(t, c.status.Connections)
	require.Zero(t, c.status.Active)
	require.Zero(t, c.data.Len())
	require.Zero(t, c.keys.Len())
	for i := 0; i < captureConnectionLimit; i++ {
		s := c.begin(strings.Repeat("b", 64), "203.0.113.7:443", "localhost", "bounded")
		require.NotNil(t, s)
		s.finish()
	}
	require.Nil(t, c.begin(strings.Repeat("b", 64), "203.0.113.7:443", "localhost", "over limit"))
	require.Equal(t, "ready", c.status.State)
	require.Equal(t, captureConnectionLimit, c.status.Connections)
}

func TestCaptureSessionConfigurableLimits(t *testing.T) {
	for _, tc := range []struct {
		body string
		code int
	}{
		{`{"serverName":"example.com","durationSeconds":60,"maxBytes":4194304}`, 200},
		{`{"serverName":"example.com","durationSeconds":900,"maxBytes":16777216}`, 200},
		{`{"serverName":"example.com","durationSeconds":901}`, 400},
		{`{"serverName":"example.com","durationSeconds":-1}`, 400},
		{`{"serverName":"example.com","maxBytes":16777217}`, 400},
	} {
		c := &nativeCapture{}
		w := httptest.NewRecorder()
		c.control(w, httptest.NewRequest("POST", "/nosy/capture", strings.NewReader(tc.body)))
		require.Equal(t, tc.code, w.Code)
		if tc.code == 200 {
			s := c.begin("", "192.0.2.1:443", "example.com", "test")
			s.record(0, make([]byte, c.target.MaxBytes))
			require.Equal(t, "ready", c.status.State)
			require.LessOrEqual(t, c.status.Bytes, c.target.MaxBytes)
		}
		c.mu.Lock()
		c.clearLocked()
		c.mu.Unlock()
	}
}
