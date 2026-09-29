package interactivepolicy

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/transform"
)

func newPolicyForTest(t *testing.T, yamlText string) *InteractivePolicy {
	t.Helper()
	var node yaml.Node
	require.NoError(t, yaml.Unmarshal([]byte(yamlText), &node))
	policy, err := factory(*node.Content[0], nil)
	require.NoError(t, err)
	return policy.(*InteractivePolicy)
}

func TestConfiguredRuleAllowsWithoutDelegating(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	policy := newPolicyForTest(t, `
endpoint: "`+server.URL+`"
rules:
  - host: "api.openai.com"
    methods: ["POST"]
    paths: ["/v1/*"]
`)
	req := httptest.NewRequest(http.MethodPost, "https://api.openai.com/v1/responses?api_key=secret", nil)
	req.Host = "api.openai.com"

	result, err := policy.TransformRequest(context.Background(), &transform.TransformContext{}, req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, result.Action)
	require.Equal(t, 0, calls)
}

func TestConfiguredRuleAllowsConnectPreflightWithoutDelegating(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	policy := newPolicyForTest(t, `
endpoint: "`+server.URL+`"
rules:
  - host: "api.openai.com"
    methods: ["POST"]
    paths: ["/v1/*"]
`)
	req := httptest.NewRequest(http.MethodConnect, "https://api.openai.com:443", nil)
	req.Host = "api.openai.com:443"

	result, err := policy.TransformRequest(context.Background(), &transform.TransformContext{}, req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, result.Action)
	require.Equal(t, 0, calls)
}

func TestDelegatesMissToPolicyService(t *testing.T) {
	var seen decisionRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "application/json", r.Header.Get("content-type"))
		require.NoError(t, json.NewDecoder(r.Body).Decode(&seen))
		_ = json.NewEncoder(w).Encode(decisionResponse{
			Action: "allow",
			Reason: "allowed by test",
			Suggested: map[string]any{
				"host": "api.openai.com",
			},
		})
	}))
	defer server.Close()

	policy := newPolicyForTest(t, `endpoint: "`+server.URL+`"`)
	req := httptest.NewRequest(http.MethodPost, "https://api.openai.com/v1/responses", nil)
	req.Host = "api.openai.com"
	req.Header.Set("Authorization", "Bearer secret")
	req.Header.Set("X-Request-Id", "req_123")
	tctx := &transform.TransformContext{SNI: "api.openai.com"}

	result, err := policy.TransformRequest(context.Background(), tctx, req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, result.Action)
	require.Equal(t, "api.openai.com", seen.Host)
	require.Equal(t, http.MethodPost, seen.Method)
	require.Equal(t, "/v1/responses", seen.Path)
	require.NotContains(t, seen.URL, "api_key")
	require.Empty(t, seen.Header["Authorization"])
	require.Equal(t, []string{"req_123"}, seen.Header["X-Request-Id"])
}

func TestDelegatedDenyRejects(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(decisionResponse{Action: "deny"})
	}))
	defer server.Close()

	policy := newPolicyForTest(t, `endpoint: "`+server.URL+`"`)
	req := httptest.NewRequest(http.MethodDelete, "https://api.openai.com/v1/files/1", nil)
	req.Host = "api.openai.com"

	result, err := policy.TransformRequest(context.Background(), &transform.TransformContext{}, req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionReject, result.Action)
}

func TestDecisionRequestCarriesConnectionContext(t *testing.T) {
	cases := []struct {
		name       string
		method     string
		target     string
		tctx       *transform.TransformContext
		wantMode   string
		wantTunnel string
	}{
		{
			name:     "plain forward proxy request",
			method:   http.MethodGet,
			target:   "http://example.com/x",
			tctx:     &transform.TransformContext{Mode: transform.ModeMITM},
			wantMode: "mitm",
		},
		{
			name:     "connect preflight in sni-only mode",
			method:   http.MethodConnect,
			target:   "https://example.com:443",
			tctx:     &transform.TransformContext{Mode: transform.ModeSNIOnly, SNI: "example.com"},
			wantMode: "sni-only",
		},
		{
			name:   "inner MITM request on a tunnel",
			method: http.MethodPost,
			target: "https://example.com/v1",
			tctx: &transform.TransformContext{
				Mode:   transform.ModeMITM,
				Tunnel: &transform.TunnelInfo{Target: "example.com:443"},
			},
			wantMode:   "mitm",
			wantTunnel: "example.com:443",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var seen map[string]any
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Decode errors surface as a missing field assertion below.
				_ = json.NewDecoder(r.Body).Decode(&seen)
				_ = json.NewEncoder(w).Encode(decisionResponse{Action: "allow"})
			}))
			defer server.Close()

			policy := newPolicyForTest(t, `endpoint: "`+server.URL+`"`)
			req := httptest.NewRequest(tc.method, tc.target, nil)
			req.RemoteAddr = "127.0.0.1:53122"

			result, err := policy.TransformRequest(context.Background(), tc.tctx, req)
			require.NoError(t, err)
			require.Equal(t, transform.ActionContinue, result.Action)
			require.Equal(t, "127.0.0.1:53122", seen["client_addr"])
			require.Equal(t, tc.wantMode, seen["mode"])
			if tc.wantTunnel == "" {
				require.NotContains(t, seen, "tunnel")
			} else {
				require.Equal(t, tc.wantTunnel, seen["tunnel"])
			}
		})
	}
}

func TestDenyResponseShapes(t *testing.T) {
	cases := []struct {
		name            string
		decision        decisionResponse
		wantResponse    bool
		wantStatus      int
		wantContentType string
		wantBody        string
	}{
		{
			name:     "plain deny keeps default pipeline response",
			decision: decisionResponse{Action: "deny", Reason: "nope"},
		},
		{
			name:            "custom body with defaults",
			decision:        decisionResponse{Action: "deny", Body: "blocked by nosy\n"},
			wantResponse:    true,
			wantStatus:      http.StatusForbidden,
			wantContentType: "text/plain; charset=utf-8",
			wantBody:        "blocked by nosy\n",
		},
		{
			name: "custom status and content type",
			decision: decisionResponse{
				Action:      "block",
				Status:      http.StatusTooManyRequests,
				ContentType: "application/json",
				Body:        `{"error":"rate"}`,
			},
			wantResponse:    true,
			wantStatus:      http.StatusTooManyRequests,
			wantContentType: "application/json",
			wantBody:        `{"error":"rate"}`,
		},
		{
			name:     "status without body is ignored",
			decision: decisionResponse{Action: "deny", Status: http.StatusTeapot},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewEncoder(w).Encode(tc.decision)
			}))
			defer server.Close()

			policy := newPolicyForTest(t, `endpoint: "`+server.URL+`"`)
			req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
			tctx := &transform.TransformContext{}

			result, err := policy.TransformRequest(context.Background(), tctx, req)
			require.NoError(t, err)
			require.Equal(t, transform.ActionReject, result.Action)
			require.Equal(t, "deny", tctx.DrainAnnotations()["decision"])
			if !tc.wantResponse {
				require.Nil(t, result.Response)
				return
			}
			require.NotNil(t, result.Response)
			require.Equal(t, tc.wantStatus, result.Response.StatusCode)
			require.Equal(t, tc.wantContentType, result.Response.Header.Get("Content-Type"))
			body, err := io.ReadAll(result.Response.Body)
			require.NoError(t, err)
			require.Equal(t, tc.wantBody, string(body))
		})
	}
}

func TestControlHostConfigValidation(t *testing.T) {
	cases := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{
			name:    "hosts without endpoint",
			yaml:    "endpoint: http://127.0.0.1:1\ncontrol_hosts: [nosy.policy]",
			wantErr: "control_endpoint is required",
		},
		{
			name:    "endpoint without hosts",
			yaml:    "endpoint: http://127.0.0.1:1\ncontrol_endpoint: http://127.0.0.1:2",
			wantErr: "control_hosts is required",
		},
		{
			name:    "wildcard host",
			yaml:    "endpoint: http://127.0.0.1:1\ncontrol_endpoint: http://127.0.0.1:2\ncontrol_hosts: ['*.policy']",
			wantErr: "must be an exact hostname",
		},
		{
			name:    "host with port",
			yaml:    "endpoint: http://127.0.0.1:1\ncontrol_endpoint: http://127.0.0.1:2\ncontrol_hosts: ['nosy.policy:80']",
			wantErr: "must be an exact hostname",
		},
		{
			name: "valid",
			yaml: "endpoint: http://127.0.0.1:1\ncontrol_endpoint: http://127.0.0.1:2\ncontrol_hosts: [Nosy.Policy]",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var node yaml.Node
			require.NoError(t, yaml.Unmarshal([]byte(tc.yaml), &node))
			_, err := factory(*node.Content[0], nil)
			if tc.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tc.wantErr)
		})
	}
}

func TestControlHost(t *testing.T) {
	type controlReply struct {
		status int
		raw    string
	}
	cases := []struct {
		name            string
		method          string
		target          string
		body            string
		contentLength   int64
		maxBodyBytes    int64
		tctx            *transform.TransformContext
		reply           controlReply
		wantControlCall bool
		wantAction      transform.TransformAction
		wantNilResponse bool
		wantStatus      int
		wantContentType string
		wantBody        string
		wantReason      string
	}{
		{
			name:            "GET is answered by the control service",
			method:          http.MethodGet,
			target:          "http://nosy.policy/rules?scope=run",
			tctx:            &transform.TransformContext{},
			reply:           controlReply{status: 200, raw: `{"status":201,"content_type":"application/json","body":"{\"ok\":true}"}`},
			wantControlCall: true,
			wantAction:      transform.ActionStub,
			wantStatus:      http.StatusCreated,
			wantContentType: "application/json",
			wantBody:        `{"ok":true}`,
		},
		{
			name:            "POST body is forwarded and defaults apply",
			method:          http.MethodPost,
			target:          "http://NOSY.policy:8080/approve",
			body:            `{"id":"r1"}`,
			tctx:            &transform.TransformContext{},
			reply:           controlReply{status: 200, raw: `{"body":"done"}`},
			wantControlCall: true,
			wantAction:      transform.ActionStub,
			wantStatus:      http.StatusOK,
			wantContentType: "text/plain; charset=utf-8",
			wantBody:        "done",
		},
		{
			name:            "control service failure returns 502",
			method:          http.MethodGet,
			target:          "http://nosy.policy/",
			tctx:            &transform.TransformContext{},
			reply:           controlReply{status: 500, raw: `boom`},
			wantControlCall: true,
			wantAction:      transform.ActionReject,
			wantStatus:      http.StatusBadGateway,
			wantReason:      "control_service_error",
		},
		{
			name:            "invalid status from control service returns 502",
			method:          http.MethodGet,
			target:          "http://nosy.policy/",
			tctx:            &transform.TransformContext{},
			reply:           controlReply{status: 200, raw: `{"status":101}`},
			wantControlCall: true,
			wantAction:      transform.ActionReject,
			wantStatus:      http.StatusBadGateway,
			wantReason:      "control_service_error",
		},
		{
			name:          "declared oversize body is rejected with 413",
			method:        http.MethodPost,
			target:        "http://nosy.policy/",
			body:          "x",
			contentLength: maxControlBodyBytes + 1,
			tctx:          &transform.TransformContext{},
			wantAction:    transform.ActionReject,
			wantStatus:    http.StatusRequestEntityTooLarge,
			wantReason:    "oversize_body",
		},
		{
			name:          "streamed oversize body is rejected with 413",
			method:        http.MethodPost,
			target:        "http://nosy.policy/",
			body:          strings.Repeat("x", maxControlBodyBytes+1),
			contentLength: -1,
			tctx:          &transform.TransformContext{},
			wantAction:    transform.ActionReject,
			wantStatus:    http.StatusRequestEntityTooLarge,
			wantReason:    "oversize_body",
		},
		{
			name:          "body truncated by max_request_body_bytes is rejected with 413",
			method:        http.MethodPost,
			target:        "http://nosy.policy/",
			body:          strings.Repeat("x", 100),
			contentLength: -1,
			maxBodyBytes:  10,
			tctx:          &transform.TransformContext{},
			wantAction:    transform.ActionReject,
			wantStatus:    http.StatusRequestEntityTooLarge,
			wantReason:    "oversize_body",
		},
		{
			name:            "CONNECT in MITM mode is admitted at tunnel level",
			method:          http.MethodConnect,
			target:          "nosy.policy:443",
			tctx:            &transform.TransformContext{Mode: transform.ModeMITM},
			wantAction:      transform.ActionContinue,
			wantNilResponse: true,
		},
		{
			name:       "CONNECT in sni-only mode is rejected",
			method:     http.MethodConnect,
			target:     "nosy.policy:443",
			tctx:       &transform.TransformContext{Mode: transform.ModeSNIOnly},
			wantAction: transform.ActionReject,
			wantStatus: http.StatusBadRequest,
			wantReason: "control_requires_mitm",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			policyCalls := 0
			policyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				policyCalls++
				_ = json.NewEncoder(w).Encode(decisionResponse{Action: "allow"})
			}))
			defer policyServer.Close()

			var seen controlRequest
			controlCalls := 0
			controlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				controlCalls++
				// A decode failure shows up as a mismatch in the assertions below.
				_ = json.NewDecoder(r.Body).Decode(&seen)
				w.WriteHeader(tc.reply.status)
				_, _ = io.WriteString(w, tc.reply.raw)
			}))
			defer controlServer.Close()

			policy := newPolicyForTest(t, `
endpoint: "`+policyServer.URL+`"
control_hosts: ["nosy.policy"]
control_endpoint: "`+controlServer.URL+`"
`)
			req := httptest.NewRequest(tc.method, tc.target, strings.NewReader(tc.body))
			if tc.contentLength != 0 {
				req.ContentLength = tc.contentLength
			}
			req.Body = transform.NewBufferedBody(req.Body, tc.maxBodyBytes)
			req.RemoteAddr = "127.0.0.1:53122"
			req.Header.Set("Authorization", "Bearer secret")
			req.Header.Set("X-Nosy", "1")

			result, err := policy.TransformRequest(context.Background(), tc.tctx, req)
			require.NoError(t, err)
			require.Equal(t, 0, policyCalls, "control host must never reach the decision service")
			require.Equal(t, tc.wantAction, result.Action)
			annotations := tc.tctx.DrainAnnotations()
			require.Equal(t, "control", annotations["decision"])
			if tc.wantReason != "" {
				require.Equal(t, tc.wantReason, annotations["reason"])
			}
			if tc.wantControlCall {
				require.Equal(t, 1, controlCalls)
				require.Equal(t, tc.method, seen.Method)
				require.Equal(t, "nosy.policy", seen.Host)
				require.Equal(t, req.URL.Path, seen.Path)
				require.Equal(t, req.URL.RawQuery, seen.Query)
				require.Equal(t, tc.body, seen.Body)
				require.Equal(t, "127.0.0.1:53122", seen.ClientAddr)
				require.Empty(t, seen.Header["Authorization"])
				require.Equal(t, []string{"1"}, seen.Header["X-Nosy"])
			} else {
				require.Equal(t, 0, controlCalls)
			}
			if tc.wantNilResponse {
				require.Nil(t, result.Response)
				return
			}
			require.NotNil(t, result.Response)
			require.Equal(t, tc.wantStatus, result.Response.StatusCode)
			if tc.wantContentType != "" {
				require.Equal(t, tc.wantContentType, result.Response.Header.Get("Content-Type"))
			}
			if tc.wantBody != "" {
				body, err := io.ReadAll(result.Response.Body)
				require.NoError(t, err)
				require.Equal(t, tc.wantBody, string(body))
			}
		})
	}
}
