package interactivepolicy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
