package transform

import (
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/log"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"testing"
)

func TestOTELNativeProvenance(t *testing.T) {
	processor := &recordProcessor{}
	provider := sdklog.NewLoggerProvider(sdklog.WithProcessor(processor))
	NewOTELAuditFunc(provider)(&PipelineResult{Action: ActionReject, Tunnel: &TunnelInfo{Native: &NativeFlowInfo{
		FlowID: "provider:flow", PolicyRevision: "revision", InspectionSession: "session", RequestID: "request-2",
	}}})
	records := processor.Records()
	require.Len(t, records, 1)
	values := map[string]string{}
	records[0].WalkAttributes(func(item log.KeyValue) bool {
		if item.Key == "native" {
			for _, field := range item.Value.AsMap() {
				values[field.Key] = field.Value.AsString()
			}
		}
		return true
	})
	require.Equal(t, map[string]string{"flow_id": "provider:flow", "policy_revision": "revision", "inspection_session": "session", "request_id": "request-2"}, values)
}
