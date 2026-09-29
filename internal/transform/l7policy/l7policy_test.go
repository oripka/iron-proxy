package l7policy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/transform"
)

func newPolicy(t *testing.T, src string) (*L7Policy, error) {
	t.Helper()
	var node yaml.Node
	require.NoError(t, yaml.Unmarshal([]byte(src), &node))
	tr, err := factory(*node.Content[0], nil)
	if err != nil {
		return nil, err
	}
	return tr.(*L7Policy), nil
}

func TestConfigValidation(t *testing.T) {
	cases := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{name: "no rules", yaml: `rules: []`, wantErr: "at least one rule"},
		{name: "missing host", yaml: `rules: [{protocol: graphql}]`, wantErr: "one of host or cidr"},
		{name: "unknown protocol", yaml: `rules: [{host: a.com, protocol: grpc}]`, wantErr: "protocol must be"},
		{name: "unknown operation", yaml: `rules: [{host: a.com, protocol: graphql, graphql: {operations: [delete]}}]`, wantErr: "unknown graphql operation"},
		{name: "mismatched block", yaml: `rules: [{host: a.com, protocol: graphql, jsonrpc: {allow_methods: [x]}}]`, wantErr: "takes a graphql block"},
		{name: "two blocks", yaml: `rules: [{host: a.com, protocol: jsonrpc, jsonrpc: {}, websocket: {allow: true}}]`, wantErr: "only the block"},
		{name: "websocket without block", yaml: `rules: [{host: a.com, protocol: websocket}]`, wantErr: "requires websocket.allow"},
		{name: "inner wildcard", yaml: `rules: [{host: a.com, protocol: jsonrpc, jsonrpc: {allow_methods: ["eth_*call"]}}]`, wantErr: "single *"},
		{name: "empty name", yaml: `rules: [{host: a.com, protocol: graphql, graphql: {deny_names: [""]}}]`, wantErr: "single *"},
		{name: "bad path", yaml: `rules: [{host: a.com, paths: [graphql], protocol: graphql}]`, wantErr: "must start with /"},
		{
			name: "valid",
			yaml: `
rules:
  - host: api.github.com
    paths: ["/graphql"]
    protocol: graphql
    graphql: {operations: [query], allow_names: ["Get*"], deny_names: [GetSecret]}
  - cidr: 10.0.0.0/8
    methods: [POST]
    protocol: jsonrpc
    jsonrpc: {allow_methods: [eth_call, "eth_get*"]}
  - host: ws.example.com
    protocol: websocket
    websocket: {allow: true}
`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := newPolicy(t, tc.yaml)
			if tc.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tc.wantErr)
		})
	}
}

const testPolicy = `
rules:
  - host: "api.github.com"
    paths: ["/graphql"]
    protocol: graphql
    graphql:
      operations: ["query"]
      deny_names: ["Secret*"]
  - host: "named.example.com"
    protocol: graphql
    graphql:
      allow_names: ["Get*", "ListRepos"]
      deny_names: ["GetToken"]
  - host: "rpc.example.com"
    protocol: jsonrpc
    jsonrpc:
      allow_methods: ["eth_call", "eth_get*"]
      deny_methods: ["eth_getLogs"]
  - host: "open-rpc.example.com"
    protocol: jsonrpc
  - host: "ws.example.com"
    paths: ["/socket"]
    protocol: websocket
    websocket:
      allow: true
  - host: "ws.example.com"
    paths: ["/admin"]
    protocol: websocket
    websocket:
      allow: false
  - host: "ws.example.com"
    paths: ["/graphql"]
    protocol: graphql
    graphql:
      operations: ["query"]
`

func TestTransformRequest(t *testing.T) {
	type reqSpec struct {
		method      string
		url         string
		body        string
		contentType string
		websocket   bool
		mode        transform.Mode
		maxBody     int64
	}
	cases := []struct {
		name        string
		req         reqSpec
		wantReject  bool
		wantReason  string
		wantAnnots  map[string]any
		wantNoAnnot bool
	}{
		{
			name:        "out of scope host continues untouched",
			req:         reqSpec{method: "POST", url: "https://example.org/graphql", body: `{"query":"mutation { x }"}`},
			wantNoAnnot: true,
		},
		{
			name:        "out of scope path continues untouched",
			req:         reqSpec{method: "POST", url: "https://api.github.com/rest", body: `not json`},
			wantNoAnnot: true,
		},
		{
			name:       "graphql POST query allowed",
			req:        reqSpec{method: "POST", url: "https://api.github.com/graphql", body: `{"query":"query Viewer { viewer { login } }"}`},
			wantAnnots: map[string]any{"protocol": "graphql", "operation_type": "query", "operation_name": "Viewer"},
		},
		{
			name:       "graphql shorthand query allowed",
			req:        reqSpec{method: "POST", url: "https://api.github.com/graphql", body: `{"query":"{ viewer { login } }","variables":{"a":1}}`},
			wantAnnots: map[string]any{"protocol": "graphql", "operation_type": "query", "operation_name": ""},
		},
		{
			name:       "graphql mutation denied by operation type",
			req:        reqSpec{method: "POST", url: "https://api.github.com/graphql", body: `{"query":"mutation AddStar { addStar { id } }"}`},
			wantReject: true,
			wantReason: reasonOperationType,
			wantAnnots: map[string]any{"protocol": "graphql", "operation_type": "mutation", "operation_name": "AddStar"},
		},
		{
			name:       "graphql operationName picks the mutation",
			req:        reqSpec{method: "POST", url: "https://api.github.com/graphql", body: `{"query":"query A { a } mutation B { b }","operationName":"B"}`},
			wantReject: true,
			wantReason: reasonOperationType,
		},
		{
			name:       "graphql operationName picks the query",
			req:        reqSpec{method: "POST", url: "https://api.github.com/graphql", body: `{"query":"query A { a } mutation B { b }","operationName":"A"}`},
			wantAnnots: map[string]any{"operation_type": "query", "operation_name": "A"},
		},
		{
			name:       "graphql deny name beats allowed type",
			req:        reqSpec{method: "POST", url: "https://api.github.com/graphql", body: `{"query":"query SecretStuff { a }"}`},
			wantReject: true,
			wantReason: reasonNameDenied,
		},
		{
			name:       "graphql GET query allowed",
			req:        reqSpec{method: "GET", url: "https://api.github.com/graphql?query=" + url.QueryEscape("query Q { a }")},
			wantAnnots: map[string]any{"operation_type": "query", "operation_name": "Q"},
		},
		{
			name:       "graphql GET mutation denied",
			req:        reqSpec{method: "GET", url: "https://api.github.com/graphql?query=" + url.QueryEscape("mutation M { a }")},
			wantReject: true,
			wantReason: reasonOperationType,
		},
		{
			name:       "graphql GET without query denied",
			req:        reqSpec{method: "GET", url: "https://api.github.com/graphql?extensions=%7B%7D"},
			wantReject: true,
			wantReason: reasonUnparseable,
		},
		{
			name:       "graphql GET with repeated query denied",
			req:        reqSpec{method: "GET", url: "https://api.github.com/graphql?query=%7Ba%7D&query=mutation%7Bb%7D"},
			wantReject: true,
			wantReason: reasonUnparseable,
		},
		{
			name:       "graphql batch with one mutation denied",
			req:        reqSpec{method: "POST", url: "https://api.github.com/graphql", body: `[{"query":"query A { a }"},{"query":"mutation B { b }"}]`},
			wantReject: true,
			wantReason: reasonOperationType,
			wantAnnots: map[string]any{"operation_types": []string{"query", "mutation"}, "operation_names": []string{"A", "B"}},
		},
		{
			name:       "graphql batch of queries allowed",
			req:        reqSpec{method: "POST", url: "https://api.github.com/graphql", body: `[{"query":"query A { a }"},{"query":"{ b }"}]`},
			wantAnnots: map[string]any{"operation_types": []string{"query", "query"}},
		},
		{
			name:       "graphql empty batch denied",
			req:        reqSpec{method: "POST", url: "https://api.github.com/graphql", body: `[]`},
			wantReject: true,
			wantReason: reasonUnparseable,
		},
		{
			name:       "graphql duplicate query key denied",
			req:        reqSpec{method: "POST", url: "https://api.github.com/graphql", body: `{"query":"{ a }","query":"mutation { b }"}`},
			wantReject: true,
			wantReason: reasonUnparseable,
		},
		{
			name:       "graphql query in URL and body denied",
			req:        reqSpec{method: "POST", url: "https://api.github.com/graphql?query=" + url.QueryEscape("mutation { b }"), body: `{"query":"{ a }"}`},
			wantReject: true,
			wantReason: reasonUnparseable,
		},
		{
			name:       "graphql non-JSON body denied",
			req:        reqSpec{method: "POST", url: "https://api.github.com/graphql", body: `query { a }`},
			wantReject: true,
			wantReason: reasonUnparseable,
		},
		{
			name:       "graphql trailing data denied",
			req:        reqSpec{method: "POST", url: "https://api.github.com/graphql", body: `{"query":"{ a }"} {"query":"mutation { b }"}`},
			wantReject: true,
			wantReason: reasonUnparseable,
		},
		{
			name:       "graphql application/graphql body",
			req:        reqSpec{method: "POST", url: "https://api.github.com/graphql", body: `mutation { b }`, contentType: "application/graphql"},
			wantReject: true,
			wantReason: reasonOperationType,
		},
		{
			name:       "graphql unsupported method denied",
			req:        reqSpec{method: "PUT", url: "https://api.github.com/graphql", body: `{"query":"{ a }"}`},
			wantReject: true,
			wantReason: reasonUnsupportedMethod,
		},
		{
			name:       "graphql truncated body denied",
			req:        reqSpec{method: "POST", url: "https://api.github.com/graphql", body: `{"query":"query Q { a }"}`, maxBody: 8},
			wantReject: true,
			wantReason: reasonOversizeBody,
		},
		{
			name:       "graphql allow_names admits prefix match",
			req:        reqSpec{method: "POST", url: "https://named.example.com/", body: `{"query":"mutation GetThing { a }"}`},
			wantAnnots: map[string]any{"operation_name": "GetThing"},
		},
		{
			name:       "graphql allow_names rejects unlisted name",
			req:        reqSpec{method: "POST", url: "https://named.example.com/", body: `{"query":"query Other { a }"}`},
			wantReject: true,
			wantReason: reasonNameNotAllowed,
		},
		{
			name:       "graphql allow_names rejects anonymous",
			req:        reqSpec{method: "POST", url: "https://named.example.com/", body: `{"query":"{ a }"}`},
			wantReject: true,
			wantReason: reasonNameNotAllowed,
		},
		{
			name:       "graphql deny_names beats allow_names",
			req:        reqSpec{method: "POST", url: "https://named.example.com/", body: `{"query":"query GetToken { a }"}`},
			wantReject: true,
			wantReason: reasonNameDenied,
		},
		{
			name:       "jsonrpc allowed method",
			req:        reqSpec{method: "POST", url: "https://rpc.example.com/", body: `{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[]}`},
			wantAnnots: map[string]any{"protocol": "jsonrpc", "method": "eth_call"},
		},
		{
			name:       "jsonrpc prefix allowed",
			req:        reqSpec{method: "POST", url: "https://rpc.example.com/", body: `{"jsonrpc":"2.0","id":1,"method":"eth_getBalance"}`},
			wantAnnots: map[string]any{"method": "eth_getBalance"},
		},
		{
			name:       "jsonrpc deny beats allow",
			req:        reqSpec{method: "POST", url: "https://rpc.example.com/", body: `{"jsonrpc":"2.0","id":1,"method":"eth_getLogs"}`},
			wantReject: true,
			wantReason: reasonMethodDenied,
		},
		{
			name:       "jsonrpc unlisted method",
			req:        reqSpec{method: "POST", url: "https://rpc.example.com/", body: `{"jsonrpc":"2.0","id":1,"method":"eth_sendRawTransaction"}`},
			wantReject: true,
			wantReason: reasonMethodNotAllowed,
		},
		{
			name:       "jsonrpc batch with one bad method",
			req:        reqSpec{method: "POST", url: "https://rpc.example.com/", body: `[{"jsonrpc":"2.0","id":1,"method":"eth_call"},{"jsonrpc":"2.0","id":2,"method":"eth_sendRawTransaction"}]`},
			wantReject: true,
			wantReason: reasonMethodNotAllowed,
			wantAnnots: map[string]any{"methods": []string{"eth_call", "eth_sendRawTransaction"}},
		},
		{
			name:       "jsonrpc non-rpc body denied",
			req:        reqSpec{method: "POST", url: "https://rpc.example.com/", body: `{"hello":"world"}`},
			wantReject: true,
			wantReason: reasonUnparseable,
		},
		{
			name:       "jsonrpc non-string method denied",
			req:        reqSpec{method: "POST", url: "https://rpc.example.com/", body: `{"jsonrpc":"2.0","method":7}`},
			wantReject: true,
			wantReason: reasonUnparseable,
		},
		{
			name:       "jsonrpc wrong version denied",
			req:        reqSpec{method: "POST", url: "https://rpc.example.com/", body: `{"jsonrpc":"3.0","method":"eth_call"}`},
			wantReject: true,
			wantReason: reasonUnparseable,
		},
		{
			name:       "jsonrpc duplicate method key denied",
			req:        reqSpec{method: "POST", url: "https://rpc.example.com/", body: `{"method":"eth_call","method":"eth_sendRawTransaction"}`},
			wantReject: true,
			wantReason: reasonUnparseable,
		},
		{
			name:       "jsonrpc GET denied",
			req:        reqSpec{method: "GET", url: "https://rpc.example.com/"},
			wantReject: true,
			wantReason: reasonUnsupportedMethod,
		},
		{
			name:       "jsonrpc truncated body denied",
			req:        reqSpec{method: "POST", url: "https://rpc.example.com/", body: `{"jsonrpc":"2.0","method":"eth_call"}`, maxBody: 10},
			wantReject: true,
			wantReason: reasonOversizeBody,
		},
		{
			name:       "jsonrpc without method lists admits any method",
			req:        reqSpec{method: "POST", url: "https://open-rpc.example.com/", body: `{"method":"anything"}`},
			wantAnnots: map[string]any{"method": "anything"},
		},
		{
			name:       "websocket upgrade allowed",
			req:        reqSpec{method: "GET", url: "https://ws.example.com/socket", websocket: true},
			wantAnnots: map[string]any{"protocol": "websocket"},
		},
		{
			name:       "websocket upgrade denied",
			req:        reqSpec{method: "GET", url: "https://ws.example.com/admin", websocket: true},
			wantReject: true,
			wantReason: reasonWebSocketDenied,
		},
		{
			name:        "plain request in websocket scope continues",
			req:         reqSpec{method: "GET", url: "https://ws.example.com/admin"},
			wantNoAnnot: true,
		},
		{
			name:        "websocket upgrade in graphql scope is not affected",
			req:         reqSpec{method: "GET", url: "https://ws.example.com/graphql", websocket: true},
			wantNoAnnot: true,
		},
		{
			name:       "sni-only in scope denied as uninspected",
			req:        reqSpec{url: "https://api.github.com", mode: transform.ModeSNIOnly},
			wantReject: true,
			wantReason: reasonUninspected,
		},
		{
			name:       "sni-only CONNECT in scope denied as uninspected",
			req:        reqSpec{method: "CONNECT", url: "api.github.com:443", mode: transform.ModeSNIOnly},
			wantReject: true,
			wantReason: reasonUninspected,
		},
		{
			name:        "sni-only out of scope continues",
			req:         reqSpec{url: "https://example.org", mode: transform.ModeSNIOnly},
			wantNoAnnot: true,
		},
		{
			name:        "MITM CONNECT preflight continues",
			req:         reqSpec{method: "CONNECT", url: "api.github.com:443"},
			wantNoAnnot: true,
		},
	}

	policy, err := newPolicy(t, testPolicy)
	require.NoError(t, err)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			method := tc.req.method
			if method == "" {
				method = http.MethodGet
			}
			req := httptest.NewRequest(method, tc.req.url, strings.NewReader(tc.req.body))
			if tc.req.method == "" {
				// sni-only synthetic requests carry no method.
				req.Method = ""
			}
			req.Body = transform.NewBufferedBody(req.Body, tc.req.maxBody)
			if tc.req.contentType != "" {
				req.Header.Set("Content-Type", tc.req.contentType)
			} else if tc.req.body != "" {
				req.Header.Set("Content-Type", "application/json")
			}
			if tc.req.websocket {
				req.Header.Set("Connection", "Upgrade")
				req.Header.Set("Upgrade", "websocket")
			}
			tctx := &transform.TransformContext{Mode: tc.req.mode}

			result, err := policy.TransformRequest(context.Background(), tctx, req)
			require.NoError(t, err)
			annots := tctx.DrainAnnotations()

			if tc.wantNoAnnot {
				require.Empty(t, annots)
			}
			for k, v := range tc.wantAnnots {
				require.Equal(t, v, annots[k], k)
			}
			if !tc.wantReject {
				require.Equal(t, transform.ActionContinue, result.Action)
				require.Nil(t, result.Response)
				return
			}
			require.Equal(t, transform.ActionReject, result.Action)
			require.Equal(t, tc.wantReason, annots["reason"])
			require.NotNil(t, result.Response)
			require.Equal(t, http.StatusForbidden, result.Response.StatusCode)
			body, err := io.ReadAll(result.Response.Body)
			require.NoError(t, err)
			require.Contains(t, string(body), "l7_policy")
			require.Contains(t, string(body), tc.wantReason)
		})
	}
}

// TestBodyRemainsReadable pins that l7_policy leaves the buffered body
// rewound for later transforms and the upstream send.
func TestBodyRemainsReadable(t *testing.T) {
	policy, err := newPolicy(t, testPolicy)
	require.NoError(t, err)
	const payload = `{"jsonrpc":"2.0","id":1,"method":"eth_call"}`
	req := httptest.NewRequest(http.MethodPost, "https://rpc.example.com/", strings.NewReader(payload))
	req.Body = transform.NewBufferedBody(req.Body, 0)

	result, err := policy.TransformRequest(context.Background(), &transform.TransformContext{}, req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionContinue, result.Action)
	got, err := io.ReadAll(transform.RequireBufferedBody(req.Body).StreamingReader())
	require.NoError(t, err)
	require.Equal(t, payload, string(got))
}
