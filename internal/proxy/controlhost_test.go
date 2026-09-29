package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/ironsh/iron-proxy/internal/transform"
	_ "github.com/ironsh/iron-proxy/internal/transform/interactivepolicy"
)

// TestInteractivePolicyControlHostNeverDialsUpstream exercises control hosts
// end to end: the control service answers, and no upstream dial happens on
// either the forward-proxy or the CONNECT MITM path.
func TestInteractivePolicyControlHostNeverDialsUpstream(t *testing.T) {
	const host = "nosy.policy"

	cases := []struct {
		name     string
		exchange func(t *testing.T, conn net.Conn, pool *x509.CertPool) *http.Response
	}{
		{
			name: "forward proxy",
			exchange: func(t *testing.T, conn net.Conn, _ *x509.CertPool) *http.Response {
				_, err := fmt.Fprintf(conn, "GET http://%s/status?x=1 HTTP/1.1\r\nHost: %s\r\n\r\n", host, host)
				require.NoError(t, err)
				resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
				require.NoError(t, err)
				return resp
			},
		},
		{
			name: "CONNECT MITM",
			exchange: func(t *testing.T, conn net.Conn, pool *x509.CertPool) *http.Response {
				br := httpConnect(t, conn, host+":443")
				tlsConn := tls.Client(&bufferedConn{Conn: conn, reader: br}, &tls.Config{RootCAs: pool, ServerName: host})
				require.NoError(t, tlsConn.Handshake())
				req, err := http.NewRequest(http.MethodGet, "https://"+host+"/status?x=1", nil)
				require.NoError(t, err)
				require.NoError(t, req.Write(tlsConn))
				resp, err := http.ReadResponse(bufio.NewReader(tlsConn), req)
				require.NoError(t, err)
				return resp
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var decisionCalls atomic.Int32
			decision := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				decisionCalls.Add(1)
				_, _ = io.WriteString(w, `{"action":"allow"}`)
			}))
			defer decision.Close()
			control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var in map[string]any
				// A decode failure leaves in nil and fails the path assertion.
				_ = json.NewDecoder(r.Body).Decode(&in)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"status":       200,
					"content_type": "application/json",
					"body":         fmt.Sprintf(`{"path":%q,"query":%q}`, in["path"], in["query"]),
				})
			}))
			defer control.Close()

			pipeline := buildPipeline(t, `
transforms:
  - name: interactive_policy
    config:
      endpoint: "`+decision.URL+`"
      control_hosts: ["`+host+`"]
      control_endpoint: "`+control.URL+`"
`)
			p, tunnelAddr, pool := startTunnelProxy(t, nil)
			p.pipeline = transform.NewPipelineHolder(pipeline)
			var dials atomic.Int32
			p.transport = &http.Transport{
				DialContext: func(context.Context, string, string) (net.Conn, error) {
					dials.Add(1)
					return nil, errors.New("upstream dial not permitted in this test")
				},
			}

			conn, err := net.DialTimeout("tcp", tunnelAddr, 5*time.Second)
			require.NoError(t, err)
			defer conn.Close()
			require.NoError(t, conn.SetDeadline(time.Now().Add(10*time.Second)))

			resp := tc.exchange(t, conn, pool)
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, resp.StatusCode)
			require.Equal(t, "application/json", resp.Header.Get("Content-Type"))
			require.JSONEq(t, `{"path":"/status","query":"x=1"}`, string(body))
			require.Zero(t, dials.Load())
			require.Zero(t, decisionCalls.Load())
		})
	}
}
