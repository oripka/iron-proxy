// Package interactivepolicy delegates allowlist misses to an external policy
// decision service.
package interactivepolicy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/hostmatch"
	"github.com/ironsh/iron-proxy/internal/transform"
)

func init() {
	transform.Register("interactive_policy", factory)
}

// maxControlBodyBytes caps the request body forwarded to control_endpoint.
const maxControlBodyBytes = 64 << 10

const defaultContentType = "text/plain; charset=utf-8"

type policyConfig struct {
	Endpoint        string                 `yaml:"endpoint"`
	TimeoutMS       int                    `yaml:"timeout_ms"`
	Rules           []hostmatch.RuleConfig `yaml:"rules"`
	ControlHosts    []string               `yaml:"control_hosts"`
	ControlEndpoint string                 `yaml:"control_endpoint"`
}

type InteractivePolicy struct {
	endpoint        string
	timeout         time.Duration
	rules           []hostmatch.Rule
	controlHosts    map[string]bool
	controlEndpoint string
	client          *http.Client
}

type decisionRequest struct {
	Host       string              `json:"host"`
	Method     string              `json:"method"`
	Path       string              `json:"path"`
	URL        string              `json:"url"`
	SNI        string              `json:"sni,omitempty"`
	Header     map[string][]string `json:"headers,omitempty"`
	ClientAddr string              `json:"client_addr,omitempty"`
	Mode       string              `json:"mode,omitempty"`
	Tunnel     string              `json:"tunnel,omitempty"`
}

type decisionResponse struct {
	Action      string         `json:"action"`
	Reason      string         `json:"reason,omitempty"`
	Suggested   map[string]any `json:"suggestedRule,omitempty"`
	Annotations map[string]any `json:"annotations,omitempty"`
	Status      int            `json:"status"`
	Body        string         `json:"body"`
	ContentType string         `json:"content_type"`
}

// controlRequest is POSTed to control_endpoint for requests addressed to a
// control host. Those requests are answered by the control service and are
// never dialed upstream.
type controlRequest struct {
	Method     string              `json:"method"`
	Host       string              `json:"host"`
	Path       string              `json:"path"`
	Query      string              `json:"query"`
	Header     map[string][]string `json:"headers"`
	Body       string              `json:"body"`
	ClientAddr string              `json:"client_addr"`
}

type controlResponse struct {
	Status      int    `json:"status"`
	ContentType string `json:"content_type"`
	Body        string `json:"body"`
}

func factory(cfg yaml.Node, _ *slog.Logger) (transform.Transformer, error) {
	var c policyConfig
	if err := cfg.Decode(&c); err != nil {
		return nil, fmt.Errorf("parsing interactive_policy config: %w", err)
	}
	if c.Endpoint == "" {
		return nil, fmt.Errorf("interactive_policy: endpoint is required")
	}

	rules, err := hostmatch.CompileRules(c.Rules, "interactive_policy")
	if err != nil {
		return nil, err
	}

	if len(c.ControlHosts) > 0 && c.ControlEndpoint == "" {
		return nil, fmt.Errorf("interactive_policy: control_endpoint is required when control_hosts is set")
	}
	if c.ControlEndpoint != "" && len(c.ControlHosts) == 0 {
		return nil, fmt.Errorf("interactive_policy: control_hosts is required when control_endpoint is set")
	}
	controlHosts := make(map[string]bool, len(c.ControlHosts))
	for i, raw := range c.ControlHosts {
		host := strings.ToLower(strings.TrimSpace(raw))
		if host == "" || strings.ContainsAny(host, "*:/ ") {
			return nil, fmt.Errorf("interactive_policy: control_hosts[%d]: %q must be an exact hostname", i, raw)
		}
		controlHosts[host] = true
	}

	timeout := time.Duration(c.TimeoutMS) * time.Millisecond
	if timeout <= 0 {
		timeout = 60 * time.Second
	}

	return &InteractivePolicy{
		endpoint:        c.Endpoint,
		timeout:         timeout,
		rules:           rules,
		controlHosts:    controlHosts,
		controlEndpoint: c.ControlEndpoint,
		client: &http.Client{
			Timeout: timeout,
		},
	}, nil
}

func (p *InteractivePolicy) Name() string { return "interactive_policy" }

func (p *InteractivePolicy) TransformRequest(ctx context.Context, tctx *transform.TransformContext, req *http.Request) (*transform.TransformResult, error) {
	if p.controlHosts[strings.ToLower(hostmatch.StripPort(req.Host))] {
		return p.control(ctx, tctx, req), nil
	}
	if req.Method == http.MethodConnect && len(p.rules) > 0 && hostmatch.MatchAnyRuleHost(p.rules, req) {
		tctx.Annotate("decision", "connect-host-allow")
		return &transform.TransformResult{Action: transform.ActionContinue}, nil
	}
	if len(p.rules) > 0 && hostmatch.MatchAnyRule(p.rules, req) {
		tctx.Annotate("decision", "configured-allow")
		return &transform.TransformResult{Action: transform.ActionContinue}, nil
	}

	decision, err := p.ask(ctx, tctx, req)
	if err != nil {
		return nil, err
	}

	for key, value := range decision.Annotations {
		tctx.Annotate(key, value)
	}
	if decision.Reason != "" {
		tctx.Annotate("reason", decision.Reason)
	}
	if decision.Suggested != nil {
		tctx.Annotate("suggestedRule", decision.Suggested)
	}

	switch strings.ToLower(decision.Action) {
	case "allow", "continue":
		tctx.Annotate("decision", "allow")
		return &transform.TransformResult{Action: transform.ActionContinue}, nil
	case "deny", "reject", "block", "":
		tctx.Annotate("decision", "deny")
		result := &transform.TransformResult{Action: transform.ActionReject}
		if decision.Body != "" {
			status := decision.Status
			if status == 0 {
				status = http.StatusForbidden
			}
			result.Response = textResponse(req, status, decision.ContentType, decision.Body)
		}
		return result, nil
	default:
		return nil, fmt.Errorf("interactive_policy: unsupported action %q", decision.Action)
	}
}

func (p *InteractivePolicy) TransformResponse(_ context.Context, _ *transform.TransformContext, _ *http.Request, _ *http.Response) (*transform.TransformResult, error) {
	return &transform.TransformResult{Action: transform.ActionContinue}, nil
}

func (p *InteractivePolicy) ask(ctx context.Context, tctx *transform.TransformContext, req *http.Request) (*decisionResponse, error) {
	payload := decisionRequest{
		Host:       hostmatch.StripPort(req.Host),
		Method:     req.Method,
		Path:       req.URL.Path,
		URL:        redactedURL(req),
		SNI:        tctx.SNI,
		Header:     safeHeaders(req.Header),
		ClientAddr: req.RemoteAddr,
		Mode:       tctx.Mode.String(),
	}
	if tctx.Tunnel != nil {
		payload.Tunnel = tctx.Tunnel.Target
	}
	var decision decisionResponse
	if err := p.post(ctx, p.endpoint, "policy service", payload, &decision); err != nil {
		return nil, err
	}
	return &decision, nil
}

// control answers a request addressed to a control host. Apart from admitting
// a CONNECT in MITM mode (whose inner requests come back here), every outcome
// is a stub or a rejection, so a control-host request never reaches an
// upstream dial.
func (p *InteractivePolicy) control(ctx context.Context, tctx *transform.TransformContext, req *http.Request) *transform.TransformResult {
	tctx.Annotate("decision", "control")
	if tctx.Mode == transform.ModeSNIOnly {
		// An sni-only tunnel is a TCP passthrough that would dial the control
		// host upstream, so it is refused outright.
		tctx.Annotate("reason", "control_requires_mitm")
		return reject(req, http.StatusBadRequest, "interactive_policy: control host requires TLS inspection\n")
	}
	if req.Method == http.MethodConnect {
		// In MITM mode the tunnel never dials upstream itself; each inner
		// request is re-evaluated here and answered by the control service.
		tctx.Annotate("control", "connect")
		return &transform.TransformResult{Action: transform.ActionContinue}
	}

	if req.ContentLength > maxControlBodyBytes {
		tctx.Annotate("reason", "oversize_body")
		return reject(req, http.StatusRequestEntityTooLarge, "interactive_policy: control request body too large\n")
	}
	var body []byte
	if req.Body != nil {
		var err error
		body, err = io.ReadAll(io.LimitReader(req.Body, maxControlBodyBytes+1))
		if err != nil {
			tctx.Annotate("reason", "read_body_failed")
			return reject(req, http.StatusBadRequest, "interactive_policy: reading control request body failed\n")
		}
	}
	truncated := false
	if b, ok := req.Body.(*transform.BufferedBody); ok {
		truncated = b.Truncated()
	}
	if len(body) > maxControlBodyBytes || truncated {
		tctx.Annotate("reason", "oversize_body")
		return reject(req, http.StatusRequestEntityTooLarge, "interactive_policy: control request body too large\n")
	}

	payload := controlRequest{
		Method:     req.Method,
		Host:       strings.ToLower(hostmatch.StripPort(req.Host)),
		Path:       req.URL.Path,
		Query:      req.URL.RawQuery,
		Header:     safeHeaders(req.Header),
		Body:       string(body),
		ClientAddr: req.RemoteAddr,
	}
	var out controlResponse
	if err := p.post(ctx, p.controlEndpoint, "control service", payload, &out); err != nil {
		tctx.Annotate("reason", "control_service_error")
		tctx.Annotate("error", err.Error())
		return reject(req, http.StatusBadGateway, "interactive_policy: control service unavailable\n")
	}
	status := out.Status
	if status == 0 {
		status = http.StatusOK
	}
	if status < 200 || status > 599 {
		tctx.Annotate("reason", "control_service_error")
		tctx.Annotate("error", fmt.Sprintf("control service returned invalid status %d", out.Status))
		return reject(req, http.StatusBadGateway, "interactive_policy: control service unavailable\n")
	}
	tctx.Annotate("status", status)
	return &transform.TransformResult{
		Action:   transform.ActionStub,
		Response: textResponse(req, status, out.ContentType, out.Body),
	}
}

// post sends payload as JSON to endpoint and decodes a 2xx JSON response into out.
func (p *InteractivePolicy) post(ctx context.Context, endpoint, service string, payload, out any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("interactive_policy: marshaling request: %w", err)
	}

	askCtx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(askCtx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("interactive_policy: building request: %w", err)
	}
	httpReq.Header.Set("content-type", "application/json")

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("interactive_policy: %s: %w", service, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("interactive_policy: %s returned %s", service, resp.Status)
	}

	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("interactive_policy: decoding %s response: %w", service, err)
	}
	return nil
}

func reject(req *http.Request, status int, body string) *transform.TransformResult {
	return &transform.TransformResult{
		Action:   transform.ActionReject,
		Response: textResponse(req, status, "", body),
	}
}

func textResponse(req *http.Request, status int, contentType, body string) *http.Response {
	if contentType == "" {
		contentType = defaultContentType
	}
	return &http.Response{
		StatusCode:    status,
		Status:        fmt.Sprintf("%d %s", status, http.StatusText(status)),
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{"Content-Type": {contentType}},
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       req,
	}
}

func redactedURL(req *http.Request) string {
	if req.URL == nil {
		return ""
	}
	u := *req.URL
	u.RawQuery = ""
	u.ForceQuery = false
	return u.String()
}

func safeHeaders(headers http.Header) map[string][]string {
	out := make(map[string][]string)
	for key, values := range headers {
		lower := strings.ToLower(key)
		if lower == "authorization" || lower == "cookie" || lower == "proxy-authorization" {
			continue
		}
		out[key] = append([]string(nil), values...)
	}
	return out
}
