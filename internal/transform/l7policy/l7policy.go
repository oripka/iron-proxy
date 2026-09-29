// Package l7policy implements protocol-aware request rules for GraphQL,
// JSON-RPC, and WebSocket upgrades on top of host/method/path scoping.
package l7policy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/hostmatch"
	"github.com/ironsh/iron-proxy/internal/transform"
)

func init() {
	transform.Register("l7_policy", factory)
}

const (
	protocolGraphQL   = "graphql"
	protocolJSONRPC   = "jsonrpc"
	protocolWebSocket = "websocket"
)

// Rejection reasons recorded in the audit trace.
const (
	reasonOversizeBody      = "oversize_body"
	reasonUninspected       = "uninspected"
	reasonUnparseable       = "unparseable"
	reasonUnsupportedMethod = "unsupported_method"
	reasonOperationType     = "operation_type_not_allowed"
	reasonNameDenied        = "operation_name_denied"
	reasonNameNotAllowed    = "operation_name_not_allowed"
	reasonMethodDenied      = "method_denied"
	reasonMethodNotAllowed  = "method_not_allowed"
	reasonWebSocketDenied   = "websocket_denied"
)

// maxAnnotationLen caps attacker-controlled identifiers (operation names,
// JSON-RPC methods) written to the audit trace.
const maxAnnotationLen = 128

type policyConfig struct {
	Rules []ruleConfig `yaml:"rules"`
}

type ruleConfig struct {
	hostmatch.RuleConfig `yaml:",inline"`
	Protocol             string           `yaml:"protocol"`
	GraphQL              *graphqlConfig   `yaml:"graphql"`
	JSONRPC              *jsonrpcConfig   `yaml:"jsonrpc"`
	WebSocket            *websocketConfig `yaml:"websocket"`
}

type graphqlConfig struct {
	Operations []string `yaml:"operations"`
	AllowNames []string `yaml:"allow_names"`
	DenyNames  []string `yaml:"deny_names"`
}

type jsonrpcConfig struct {
	AllowMethods []string `yaml:"allow_methods"`
	DenyMethods  []string `yaml:"deny_methods"`
}

type websocketConfig struct {
	Allow bool `yaml:"allow"`
}

type rule struct {
	match    hostmatch.Rule
	protocol string

	// graphql
	operations map[string]bool // nil = all operation types
	allowNames []string
	denyNames  []string

	// jsonrpc
	allowMethods []string
	denyMethods  []string

	// websocket
	allowWebSocket bool
}

// L7Policy enforces protocol-aware rules on in-scope requests. Requests that
// match no rule pass through unchanged.
type L7Policy struct {
	rules []rule
}

func factory(cfg yaml.Node, _ *slog.Logger) (transform.Transformer, error) {
	var c policyConfig
	if err := cfg.Decode(&c); err != nil {
		return nil, fmt.Errorf("parsing l7_policy config: %w", err)
	}
	return newFromConfig(c)
}

func newFromConfig(c policyConfig) (*L7Policy, error) {
	if len(c.Rules) == 0 {
		return nil, fmt.Errorf("l7_policy: at least one rule is required")
	}
	rules := make([]rule, 0, len(c.Rules))
	for i, rc := range c.Rules {
		compiled, err := hostmatch.CompileRules([]hostmatch.RuleConfig{rc.RuleConfig}, fmt.Sprintf("l7_policy: rules[%d]", i))
		if err != nil {
			return nil, err
		}
		r := rule{match: compiled[0], protocol: strings.ToLower(strings.TrimSpace(rc.Protocol))}

		blocks := 0
		for _, set := range []bool{rc.GraphQL != nil, rc.JSONRPC != nil, rc.WebSocket != nil} {
			if set {
				blocks++
			}
		}
		if blocks > 1 {
			return nil, fmt.Errorf("l7_policy: rules[%d]: only the block matching protocol may be set", i)
		}

		switch r.protocol {
		case protocolGraphQL:
			if rc.JSONRPC != nil || rc.WebSocket != nil {
				return nil, fmt.Errorf("l7_policy: rules[%d]: protocol graphql takes a graphql block", i)
			}
			if g := rc.GraphQL; g != nil {
				if len(g.Operations) > 0 {
					r.operations = make(map[string]bool, len(g.Operations))
					for _, op := range g.Operations {
						op = strings.ToLower(strings.TrimSpace(op))
						if op != "query" && op != "mutation" && op != "subscription" {
							return nil, fmt.Errorf("l7_policy: rules[%d]: unknown graphql operation %q", i, op)
						}
						r.operations[op] = true
					}
				}
				if r.allowNames, err = compileNames(g.AllowNames); err != nil {
					return nil, fmt.Errorf("l7_policy: rules[%d]: graphql.allow_names: %w", i, err)
				}
				if r.denyNames, err = compileNames(g.DenyNames); err != nil {
					return nil, fmt.Errorf("l7_policy: rules[%d]: graphql.deny_names: %w", i, err)
				}
			}
		case protocolJSONRPC:
			if rc.GraphQL != nil || rc.WebSocket != nil {
				return nil, fmt.Errorf("l7_policy: rules[%d]: protocol jsonrpc takes a jsonrpc block", i)
			}
			if j := rc.JSONRPC; j != nil {
				if r.allowMethods, err = compileNames(j.AllowMethods); err != nil {
					return nil, fmt.Errorf("l7_policy: rules[%d]: jsonrpc.allow_methods: %w", i, err)
				}
				if r.denyMethods, err = compileNames(j.DenyMethods); err != nil {
					return nil, fmt.Errorf("l7_policy: rules[%d]: jsonrpc.deny_methods: %w", i, err)
				}
			}
		case protocolWebSocket:
			if rc.GraphQL != nil || rc.JSONRPC != nil {
				return nil, fmt.Errorf("l7_policy: rules[%d]: protocol websocket takes a websocket block", i)
			}
			if rc.WebSocket == nil {
				return nil, fmt.Errorf("l7_policy: rules[%d]: protocol websocket requires websocket.allow", i)
			}
			r.allowWebSocket = rc.WebSocket.Allow
		default:
			return nil, fmt.Errorf("l7_policy: rules[%d]: protocol must be graphql, jsonrpc, or websocket, got %q", i, rc.Protocol)
		}
		rules = append(rules, r)
	}
	return &L7Policy{rules: rules}, nil
}

// compileNames validates name patterns: exact names or a single trailing "*".
func compileNames(names []string) ([]string, error) {
	out := make([]string, 0, len(names))
	for _, n := range names {
		if n == "" || strings.Contains(strings.TrimSuffix(n, "*"), "*") {
			return nil, fmt.Errorf("pattern %q must be an exact name or end in a single *", n)
		}
		out = append(out, n)
	}
	return out, nil
}

func matchName(patterns []string, name string) bool {
	for _, p := range patterns {
		if prefix, ok := strings.CutSuffix(p, "*"); ok {
			if strings.HasPrefix(name, prefix) {
				return true
			}
		} else if p == name {
			return true
		}
	}
	return false
}

func (p *L7Policy) Name() string { return "l7_policy" }

// denial records why an in-scope request was refused.
type denial struct {
	protocol string
	reason   string
}

func (p *L7Policy) TransformRequest(_ context.Context, tctx *transform.TransformContext, req *http.Request) (*transform.TransformResult, error) {
	host := hostmatch.StripPort(req.Host)

	if tctx.Mode == transform.ModeSNIOnly {
		// Method, path, and body are unavailable, so any rule whose host
		// matches might apply; refuse rather than pass traffic uninspected.
		for _, r := range p.rules {
			if r.match.MatchesHost(host) {
				return reject(tctx, req, denial{protocol: r.protocol, reason: reasonUninspected}), nil
			}
		}
		return continueResult(), nil
	}
	if req.Method == http.MethodConnect {
		// The tunnel's inner requests are evaluated individually.
		return continueResult(), nil
	}

	ws := isWebSocketUpgrade(req)
	body := &lazyBody{req: req}
	for _, r := range p.rules {
		if !r.match.Matches(host, req.Method, req.URL.Path) {
			continue
		}
		var d *denial
		switch r.protocol {
		case protocolWebSocket:
			d = r.checkWebSocket(tctx, ws)
		case protocolGraphQL:
			if ws {
				continue
			}
			d = r.checkGraphQL(tctx, req, body)
		case protocolJSONRPC:
			if ws {
				continue
			}
			d = r.checkJSONRPC(tctx, req, body)
		}
		if d != nil {
			return reject(tctx, req, *d), nil
		}
	}
	return continueResult(), nil
}

func (p *L7Policy) TransformResponse(_ context.Context, _ *transform.TransformContext, _ *http.Request, _ *http.Response) (*transform.TransformResult, error) {
	return continueResult(), nil
}

func continueResult() *transform.TransformResult {
	return &transform.TransformResult{Action: transform.ActionContinue}
}

func reject(tctx *transform.TransformContext, req *http.Request, d denial) *transform.TransformResult {
	tctx.Annotate("protocol", d.protocol)
	tctx.Annotate("reason", d.reason)
	msg := fmt.Sprintf("l7_policy: %s request denied (%s)\n", d.protocol, d.reason)
	return &transform.TransformResult{
		Action: transform.ActionReject,
		Response: &http.Response{
			StatusCode:    http.StatusForbidden,
			Status:        "403 Forbidden",
			Proto:         "HTTP/1.1",
			ProtoMajor:    1,
			ProtoMinor:    1,
			Header:        http.Header{"Content-Type": {"text/plain; charset=utf-8"}},
			Body:          io.NopCloser(strings.NewReader(msg)),
			ContentLength: int64(len(msg)),
			Request:       req,
		},
	}
}

func isWebSocketUpgrade(req *http.Request) bool {
	for _, v := range req.Header.Values("Upgrade") {
		for _, tok := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(tok), "websocket") {
				return true
			}
		}
	}
	return false
}

func (r *rule) checkWebSocket(tctx *transform.TransformContext, ws bool) *denial {
	if !ws {
		return nil
	}
	tctx.Annotate("protocol", protocolWebSocket)
	if !r.allowWebSocket {
		return &denial{protocol: protocolWebSocket, reason: reasonWebSocketDenied}
	}
	return nil
}

// lazyBody reads the request body at most once per request and remembers
// whether max_request_body_bytes truncated it.
type lazyBody struct {
	req       *http.Request
	read      bool
	data      []byte
	truncated bool
	err       error
}

func (b *lazyBody) get() ([]byte, bool, error) {
	if !b.read {
		b.read = true
		buf := transform.RequireBufferedBody(b.req.Body)
		b.data, b.err = io.ReadAll(buf)
		buf.Reset()
		b.truncated = buf.Truncated()
	}
	return b.data, b.truncated, b.err
}

func (r *rule) checkGraphQL(tctx *transform.TransformContext, req *http.Request, body *lazyBody) *denial {
	deny := func(reason string) *denial { return &denial{protocol: protocolGraphQL, reason: reason} }
	tctx.Annotate("protocol", protocolGraphQL)

	var requests []graphqlRequest
	switch req.Method {
	case http.MethodGet:
		q := req.URL.Query()
		if _, ok := q["query"]; !ok || len(q["query"]) != 1 || len(q["operationName"]) > 1 {
			return deny(reasonUnparseable)
		}
		requests = []graphqlRequest{{query: q.Get("query"), operationName: q.Get("operationName")}}
	case http.MethodPost:
		data, truncated, err := body.get()
		if truncated {
			return deny(reasonOversizeBody)
		}
		if err != nil {
			return deny(reasonUnparseable)
		}
		if requests, err = parseGraphQLBody(req.Header.Get("Content-Type"), req.URL.Query(), data); err != nil {
			return deny(reasonUnparseable)
		}
	default:
		return deny(reasonUnsupportedMethod)
	}

	types := make([]string, 0, len(requests))
	names := make([]string, 0, len(requests))
	var denied *denial
	for _, gr := range requests {
		op, err := selectOperation(gr.query, gr.operationName)
		if err != nil {
			return deny(reasonUnparseable)
		}
		types = append(types, op.kind)
		names = append(names, truncate(op.name))
		if denied != nil {
			continue
		}
		switch {
		case r.operations != nil && !r.operations[op.kind]:
			denied = deny(reasonOperationType)
		case matchName(r.denyNames, op.name):
			denied = deny(reasonNameDenied)
		case len(r.allowNames) > 0 && !matchName(r.allowNames, op.name):
			denied = deny(reasonNameNotAllowed)
		}
	}
	if len(requests) == 1 {
		tctx.Annotate("operation_type", types[0])
		tctx.Annotate("operation_name", names[0])
	} else {
		tctx.Annotate("operation_types", types)
		tctx.Annotate("operation_names", names)
	}
	return denied
}

type graphqlRequest struct {
	query         string
	operationName string
}

// parseGraphQLBody extracts GraphQL requests from a POST body. It accepts
// application/graphql (the body is the document, operationName from the URL)
// and JSON objects or batched arrays of {query, operationName}.
func parseGraphQLBody(contentType string, urlQuery url.Values, data []byte) ([]graphqlRequest, error) {
	// Some servers let URL parameters override the body; refuse the
	// ambiguity rather than guess which one the upstream will execute.
	if urlQuery.Has("query") {
		return nil, errors.New("query in both URL and body")
	}
	mediaType := strings.ToLower(strings.TrimSpace(strings.SplitN(contentType, ";", 2)[0]))
	if mediaType == "application/graphql" {
		if len(urlQuery["operationName"]) > 1 {
			return nil, errors.New("repeated operationName")
		}
		return []graphqlRequest{{query: string(data), operationName: urlQuery.Get("operationName")}}, nil
	}
	if urlQuery.Has("operationName") {
		return nil, errors.New("operationName in both URL and body")
	}
	objects, err := decodeObjects(data)
	if err != nil {
		return nil, err
	}
	out := make([]graphqlRequest, 0, len(objects))
	for _, obj := range objects {
		query, ok, err := stringField(obj, "query")
		if err != nil || !ok {
			return nil, errors.New("graphql request without string query")
		}
		name, _, err := stringField(obj, "operationName")
		if err != nil {
			return nil, err
		}
		out = append(out, graphqlRequest{query: query, operationName: name})
	}
	return out, nil
}

func (r *rule) checkJSONRPC(tctx *transform.TransformContext, req *http.Request, body *lazyBody) *denial {
	deny := func(reason string) *denial { return &denial{protocol: protocolJSONRPC, reason: reason} }
	tctx.Annotate("protocol", protocolJSONRPC)
	if req.Method != http.MethodPost {
		return deny(reasonUnsupportedMethod)
	}
	data, truncated, err := body.get()
	if truncated {
		return deny(reasonOversizeBody)
	}
	if err != nil {
		return deny(reasonUnparseable)
	}
	objects, err := decodeObjects(data)
	if err != nil {
		return deny(reasonUnparseable)
	}

	methods := make([]string, 0, len(objects))
	var denied *denial
	for _, obj := range objects {
		method, ok, err := stringField(obj, "method")
		if err != nil || !ok || method == "" {
			return deny(reasonUnparseable)
		}
		if v, ok, err := stringField(obj, "jsonrpc"); err != nil || (ok && v != "2.0") {
			return deny(reasonUnparseable)
		}
		methods = append(methods, truncate(method))
		if denied != nil {
			continue
		}
		switch {
		case matchName(r.denyMethods, method):
			denied = deny(reasonMethodDenied)
		case len(r.allowMethods) > 0 && !matchName(r.allowMethods, method):
			denied = deny(reasonMethodNotAllowed)
		}
	}
	if len(methods) == 1 {
		tctx.Annotate("method", methods[0])
	} else {
		tctx.Annotate("methods", methods)
	}
	return denied
}

// decodeObjects parses data as a single JSON object or a non-empty array of
// objects. Duplicate keys are rejected so the proxy and the upstream cannot
// disagree about which value applies.
func decodeObjects(data []byte) ([]map[string]json.RawMessage, error) {
	trimmed := bytes.TrimLeft(data, " \t\r\n")
	if len(trimmed) == 0 {
		return nil, errors.New("empty body")
	}
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	var objects []map[string]json.RawMessage
	if trimmed[0] == '[' {
		if _, err := dec.Token(); err != nil {
			return nil, err
		}
		for dec.More() {
			obj, err := decodeObject(dec)
			if err != nil {
				return nil, err
			}
			objects = append(objects, obj)
		}
		if _, err := dec.Token(); err != nil {
			return nil, err
		}
		if len(objects) == 0 {
			return nil, errors.New("empty batch")
		}
	} else {
		obj, err := decodeObject(dec)
		if err != nil {
			return nil, err
		}
		objects = append(objects, obj)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing data after JSON value")
	}
	return objects, nil
}

func decodeObject(dec *json.Decoder) (map[string]json.RawMessage, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if tok != json.Delim('{') {
		return nil, errors.New("expected JSON object")
	}
	obj := make(map[string]json.RawMessage)
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, ok := tok.(string)
		if !ok {
			return nil, errors.New("expected object key")
		}
		if _, dup := obj[key]; dup {
			return nil, fmt.Errorf("duplicate key %q", key)
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil, err
		}
		obj[key] = value
	}
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	return obj, nil
}

// stringField returns obj[key] as a string. A missing key or JSON null
// reports ok=false; any other non-string value is an error.
func stringField(obj map[string]json.RawMessage, key string) (string, bool, error) {
	raw, ok := obj[key]
	if !ok || string(raw) == "null" {
		return "", false, nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", false, fmt.Errorf("field %q is not a string", key)
	}
	return s, true, nil
}

func truncate(s string) string {
	if len(s) <= maxAnnotationLen {
		return s
	}
	return s[:maxAnnotationLen] + "..."
}
