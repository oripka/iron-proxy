package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ironsh/iron-proxy/internal/transform"
	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/require"
)

func TestNativeQUICRejectedRequestsAreAudited(t *testing.T) {
	records := make(chan *transform.PipelineResult, 8)
	p, addr, target, roots, _ := quicFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("rejected request reached upstream")
	}), func(result *transform.PipelineResult) {
		if result.Tunnel != nil && result.Tunnel.Native != nil {
			records <- result
		}
	})
	client := quicClient(t, addr, target, strings.Repeat("a", 64), roots, quic.Version1)
	cases := []struct {
		name, method, authority, reason string
		status                          int
	}{
		{"hostname", "GET", "unrelated.invalid", "native_http3_authority", 421},
		{"port", "GET", "localhost:1", "native_http3_authority", 421},
		{"connect", "CONNECT", "localhost", "native_http3_protocol", 501},
	}
	ids := map[string]bool{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			request, err := http.NewRequest(tc.method, "https://localhost/private-path", nil)
			require.NoError(t, err)
			request.Host = tc.authority
			response, err := client.Do(request)
			require.NoError(t, err)
			require.Equal(t, tc.status, response.StatusCode)
			_, err = io.Copy(io.Discard, response.Body)
			require.NoError(t, err)
			require.NoError(t, response.Body.Close())
			select {
			case result := <-records:
				require.Equal(t, tc.status, result.StatusCode)
				require.Equal(t, transform.ActionReject, result.Action)
				require.Equal(t, "localhost", result.Host)
				require.Empty(t, result.Path)
				require.Len(t, result.RequestTransforms, 1)
				require.Equal(t, tc.reason, result.RequestTransforms[0].Name)
				require.False(t, ids[result.Tunnel.Native.RequestID])
				ids[result.Tunnel.Native.RequestID] = true
			case <-time.After(time.Second):
				t.Fatal("missing admission audit")
			}
		})
	}
	// The capacity path has the same audit contract but is not a firewall denial.
	info := &transform.TunnelInfo{Native: &transform.NativeFlowInfo{FlowID: "flow", RequestID: "capacity"}}
	response := httptest.NewRecorder()
	p.rejectNativeQUICRequest(response, httptest.NewRequest("GET", "https://localhost/", nil), "localhost", 503, "native_http3_capacity", info)
	result := <-records
	require.Equal(t, 503, response.Code)
	require.Equal(t, transform.ActionContinue, result.Action)
	require.Error(t, result.Err)
	require.Equal(t, "native_http3_capacity", result.RequestTransforms[0].Name)
	require.Empty(t, records, "one audit per rejected request")
}

func TestNativeQUICUpstreamHeadersAreBounded(t *testing.T) {
	_, addr, target, roots, _ := quicFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Oversized", strings.Repeat("a", 64<<10))
		w.WriteHeader(http.StatusOK)
	}))
	client := quicClient(t, addr, target, strings.Repeat("a", 64), roots, quic.Version1)
	response, err := client.Get("https://localhost/")
	require.NoError(t, err)
	require.Equal(t, http.StatusBadGateway, response.StatusCode)
	require.Empty(t, response.Header.Get("X-Oversized"))
	require.NoError(t, response.Body.Close())
}
