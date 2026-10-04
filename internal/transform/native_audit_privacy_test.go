package transform

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/log"
	sdklog "go.opentelemetry.io/otel/sdk/log"
)

func TestNativeAuditPrivacyPreservesDecisionsInBothExporters(t *testing.T) {
	cases := []struct {
		name              string
		action            TransformAction
		failed, cancelled bool
		verdict, level    string
		severity          log.Severity
	}{
		{"allow", ActionContinue, false, false, "allow", "INFO", log.SeverityInfo1},
		{"deny", ActionReject, false, false, "reject", "WARN", log.SeverityWarn1},
		{"stub", ActionStub, false, false, "stub", "INFO", log.SeverityInfo1},
		{"error", ActionContinue, true, false, "error", "ERROR", log.SeverityError1},
		{"cancel", ActionContinue, true, true, "client_cancel", "ERROR", log.SeverityError1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			trace := TransformTrace{Name: "allowlist", Action: tc.action, Duration: time.Millisecond, Annotations: map[string]any{"url": "sensitive-annotation"}}
			result := &PipelineResult{Host: "example.test", Method: "POST", Path: "/sensitive-path", Action: tc.action, ClientCanceled: tc.cancelled,
				BodyCapture:       &fakeBodyCapture{body: "sensitive-body"},
				Tunnel:            &TunnelInfo{Target: "192.0.2.1:443", Native: &NativeFlowInfo{FlowID: "flow", RequestID: "request", PolicyRevision: "revision"}, RequestTransforms: []TransformTrace{trace}},
				RequestTransforms: []TransformTrace{trace}, ResponseTransforms: []TransformTrace{trace}}
			if tc.failed {
				result.Err = errors.New("sensitive-error")
				result.RequestTransforms[0].Err = result.Err
			}
			parsed, raw := captureAuditLog(result)
			require.Equal(t, tc.verdict, parsed["audit"].(map[string]any)["action"])
			require.Equal(t, tc.level, parsed["level"])
			jsonTraces := parsed["request_transforms"].([]any)
			require.Len(t, jsonTraces, 1)
			expectedTrace := actionString(tc.action)
			if tc.failed {
				expectedTrace = "error"
			}
			require.Equal(t, expectedTrace, jsonTraces[0].(map[string]any)["action"])
			processor := &recordProcessor{}
			provider := sdklog.NewLoggerProvider(sdklog.WithProcessor(processor))
			defer func() { require.NoError(t, provider.Shutdown(context.Background())) }()
			NewOTELAuditFunc(provider)(result)
			records := processor.Records()
			require.Len(t, records, 1)
			attrs := recordAttrs(records[0])
			require.Equal(t, tc.verdict, attrs["action"].AsString())
			require.Equal(t, tc.severity, records[0].Severity())
			otelTraces := attrs["request_transforms"].AsSlice()
			require.Len(t, otelTraces, 1)
			require.Equal(t, expectedTrace, mapFromValue(otelTraces[0])["action"].AsString())
			for _, sensitive := range []string{"sensitive-path", "sensitive-annotation", "sensitive-error", "sensitive-body"} {
				require.NotContains(t, raw, sensitive)
				require.NotContains(t, fmt.Sprint(attrs), sensitive)
			}
			if tc.action == ActionReject {
				require.Equal(t, "allowlist", parsed["rejected_by"])
				require.Equal(t, "allowlist", attrs["rejected_by"].AsString())
			}
			if tc.action == ActionStub {
				require.Equal(t, "allowlist", parsed["stubbed_by"])
				require.Equal(t, "allowlist", attrs["stubbed_by"].AsString())
			}
			require.Equal(t, "/sensitive-path", result.Path)
			require.Equal(t, "sensitive-annotation", result.RequestTransforms[0].Annotations["url"])
			if tc.failed {
				require.EqualError(t, result.Err, "sensitive-error")
			}
		})
	}
}
