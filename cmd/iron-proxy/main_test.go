package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/ironsh/iron-proxy/internal/transform"

	_ "github.com/ironsh/iron-proxy/internal/transform/allowlist"
	_ "github.com/ironsh/iron-proxy/internal/transform/secrets"
)

func mapEnv(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestParseResponseRetryStatuses(t *testing.T) {
	cases := []struct {
		name    string
		value   string
		want    []int
		wantErr string
	}{
		{name: "multiple", value: "402, 409", want: []int{402, 409}},
		{name: "empty entries", value: " ,402,, ", want: []int{402}},
		{name: "empty", value: "", want: nil},
		{name: "invalid", value: "402,nope", wantErr: `invalid status "nope"`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseResponseRetryStatuses(tc.value)
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

func TestSplitCommaSeparated(t *testing.T) {
	require.Equal(t, []string{"Payment-Receipt", "X-Receipt"}, splitCommaSeparated(" Payment-Receipt, ,X-Receipt "))
}

func TestResponseRetryHandlerFromEnv(t *testing.T) {
	base := map[string]string{
		"IRON_RESPONSE_RETRY_HANDLER_URL":         "http://127.0.0.1/authorize",
		"IRON_RESPONSE_RETRY_COMPLETE_URL":        "http://127.0.0.1/complete",
		"IRON_RESPONSE_RETRY_HANDLER_TOKEN":       "handler-token",
		"IRON_RESPONSE_RETRY_HANDLER_SANDBOX_ID":  "sandbox-1",
		"IRON_RESPONSE_RETRY_STATUSES":            "402,409",
		"IRON_RESPONSE_RETRY_COMPLETION_HEADERS":  "X-Receipt",
		"IRON_RESPONSE_RETRY_HANDLER_ALLOW_CIDRS": "10.43.0.0/16",
	}

	handler, statuses, err := responseRetryHandlerFromEnv(mapEnv(base), time.Second, nil, nil)

	require.NoError(t, err)
	require.NotNil(t, handler)
	require.Equal(t, []int{402, 409}, statuses)
}

func TestResponseRetryHandlerFromEnvRejectsUnsafeAllowCIDRs(t *testing.T) {
	cases := []struct {
		name  string
		value string
		want  string
	}{
		{name: "missing prefix", value: "10.43.0.1", want: "must use CIDR notation"},
		{name: "public range", value: "203.0.113.0/24", want: "private address range"},
		{name: "link local", value: "169.254.0.0/16", want: "private address range"},
		{name: "AWS IPv6 metadata", value: "fd00::/8", want: "metadata address"},
		{name: "GCP IPv6 metadata", value: "fd20:ce::/64", want: "metadata address"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := map[string]string{
				"IRON_RESPONSE_RETRY_HANDLER_URL":         "http://127.0.0.1/authorize",
				"IRON_RESPONSE_RETRY_COMPLETE_URL":        "http://127.0.0.1/complete",
				"IRON_RESPONSE_RETRY_HANDLER_TOKEN":       "handler-token",
				"IRON_RESPONSE_RETRY_HANDLER_SANDBOX_ID":  "sandbox-1",
				"IRON_RESPONSE_RETRY_STATUSES":            "402",
				"IRON_RESPONSE_RETRY_HANDLER_ALLOW_CIDRS": tc.value,
			}

			handler, _, err := responseRetryHandlerFromEnv(mapEnv(env), time.Second, nil, nil)

			require.Nil(t, handler)
			require.ErrorContains(t, err, tc.want)
		})
	}
}

func TestResponseRetryHandlerFromEnvDisabled(t *testing.T) {
	handler, statuses, err := responseRetryHandlerFromEnv(mapEnv(nil), time.Second, nil, nil)

	require.NoError(t, err)
	require.Nil(t, handler)
	require.Nil(t, statuses)
}

func TestResponseRetryHandlerFromEnvRequiresDedicatedToken(t *testing.T) {
	env := map[string]string{
		"IRON_RESPONSE_RETRY_HANDLER_URL":        "http://127.0.0.1/authorize",
		"IRON_RESPONSE_RETRY_COMPLETE_URL":       "http://127.0.0.1/complete",
		"IRON_RESPONSE_RETRY_HANDLER_SANDBOX_ID": "sandbox-1",
		"IRON_RESPONSE_RETRY_STATUSES":           "402",
		"IRON_PROXY_TOKEN":                       "control-plane-token",
	}

	handler, _, err := responseRetryHandlerFromEnv(mapEnv(env), time.Second, nil, nil)

	require.Nil(t, handler)
	require.ErrorContains(t, err, "handler token is required")
}

// localListener builds a single-upstream local listener (with its own shared
// client credential) for conflict/passthrough tests.
func TestApplyPipelineSync_ValidConfig_Swaps(t *testing.T) {
	original := transform.NewPipeline(nil, transform.BodyLimits{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	holder := transform.NewPipelineHolder(original)

	logBuf := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(logBuf, nil))

	rules := json.RawMessage(`[{"host":"example.com","methods":["GET"],"paths":["/api/*"]}]`)
	require.NoError(t, applyPipelineSync(holder, transform.BodyLimits{}, logger, rules, nil, nil))

	require.NotSame(t, original, holder.Load(), "pipeline should have been swapped")
	require.Equal(t, "allowlist", holder.Load().Names())
	require.Contains(t, logBuf.String(), "pipeline reloaded")
}

func TestApplyPipelineSync_GCPIDTokenTransformFromControlPlane(t *testing.T) {
	original := transform.NewPipeline(nil, transform.BodyLimits{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	holder := transform.NewPipelineHolder(original)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	transforms := json.RawMessage(`[
		{
			"name": "gcp_id_token",
			"config": {
				"keyfile_path": "/does/not/read/until/request.json",
				"audience": "https://private-service-abc123-uc.a.run.app",
				"rules": [{"host":"private-service-abc123-uc.a.run.app"}]
			}
		}
	]`)
	require.NoError(t, applyPipelineSync(holder, transform.BodyLimits{}, logger, nil, nil, transforms))

	require.NotSame(t, original, holder.Load(), "pipeline should have been swapped")
	require.Equal(t, "gcp_id_token", holder.Load().Names())
}

func TestApplyPipelineSync_InvalidJSON_KeepsExistingPipeline(t *testing.T) {
	original := transform.NewPipeline(nil, transform.BodyLimits{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	holder := transform.NewPipelineHolder(original)

	logBuf := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(logBuf, nil))

	require.Error(t, applyPipelineSync(holder, transform.BodyLimits{}, logger, json.RawMessage(`{not json`), nil, nil))

	require.Same(t, original, holder.Load(), "pipeline must not be swapped on invalid config")
	require.Contains(t, logBuf.String(), "rejecting invalid pipeline config")
	require.Contains(t, logBuf.String(), "level=ERROR")
}

func TestApplyPipelineSync_InvalidRule_KeepsExistingPipeline(t *testing.T) {
	original := transform.NewPipeline(nil, transform.BodyLimits{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	holder := transform.NewPipelineHolder(original)

	logBuf := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(logBuf, nil))

	// host and cidr are mutually exclusive — rule construction fails.
	rules := json.RawMessage(`[{"host":"example.com","cidr":"10.0.0.0/8"}]`)
	require.Error(t, applyPipelineSync(holder, transform.BodyLimits{}, logger, rules, nil, nil))

	require.Same(t, original, holder.Load(), "pipeline must not be swapped when transform construction fails")
	require.Contains(t, logBuf.String(), "rejecting invalid pipeline config")
	require.Contains(t, logBuf.String(), "level=ERROR")
}

func TestApplyPipelineSync_PreservesAuditFunc(t *testing.T) {
	original := transform.NewPipeline(nil, transform.BodyLimits{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	called := false
	original.SetAuditFunc(func(*transform.PipelineResult) { called = true })
	holder := transform.NewPipelineHolder(original)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	rules := json.RawMessage(`[{"host":"example.com"}]`)
	require.NoError(t, applyPipelineSync(holder, transform.BodyLimits{}, logger, rules, nil, nil))

	holder.Load().EmitAudit(nil)
	require.True(t, called, "audit func should be carried over to the new pipeline")
}

// Guard configures interactive_policy; an upstream merge once dropped its
// registration silently, breaking every guarded run.
func TestGuardTransformsAreRegistered(t *testing.T) {
	for _, name := range []string{"allowlist", "interactive_policy", "l7_policy", "secrets"} {
		_, err := transform.Lookup(name)
		require.NoError(t, err, name)
	}
}
