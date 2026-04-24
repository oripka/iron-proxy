// Package interactivepolicy delegates allowlist misses to an external policy
// decision service.
package interactivepolicy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
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

type policyConfig struct {
	Endpoint  string                 `yaml:"endpoint"`
	TimeoutMS int                    `yaml:"timeout_ms"`
	Rules     []hostmatch.RuleConfig `yaml:"rules"`
}

type InteractivePolicy struct {
	endpoint string
	timeout  time.Duration
	rules    []hostmatch.Rule
	client   *http.Client
}

type decisionRequest struct {
	Host   string              `json:"host"`
	Method string              `json:"method"`
	Path   string              `json:"path"`
	URL    string              `json:"url"`
	SNI    string              `json:"sni,omitempty"`
	Header map[string][]string `json:"headers,omitempty"`
}

type decisionResponse struct {
	Action      string         `json:"action"`
	Reason      string         `json:"reason,omitempty"`
	Suggested   map[string]any `json:"suggestedRule,omitempty"`
	Annotations map[string]any `json:"annotations,omitempty"`
}

func factory(cfg yaml.Node, _ *slog.Logger) (transform.Transformer, error) {
	var c policyConfig
	if err := cfg.Decode(&c); err != nil {
		return nil, fmt.Errorf("parsing interactive_policy config: %w", err)
	}
	if c.Endpoint == "" {
		return nil, fmt.Errorf("interactive_policy: endpoint is required")
	}

	rules, err := hostmatch.CompileRules(c.Rules, hostmatch.DefaultResolver(), "interactive_policy")
	if err != nil {
		return nil, err
	}

	timeout := time.Duration(c.TimeoutMS) * time.Millisecond
	if timeout <= 0 {
		timeout = 60 * time.Second
	}

	return &InteractivePolicy{
		endpoint: c.Endpoint,
		timeout:  timeout,
		rules:    rules,
		client: &http.Client{
			Timeout: timeout,
		},
	}, nil
}

func (p *InteractivePolicy) Name() string { return "interactive_policy" }

func (p *InteractivePolicy) TransformRequest(ctx context.Context, tctx *transform.TransformContext, req *http.Request) (*transform.TransformResult, error) {
	if len(p.rules) > 0 && hostmatch.MatchAnyRule(ctx, p.rules, req) {
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
		return &transform.TransformResult{Action: transform.ActionReject}, nil
	default:
		return nil, fmt.Errorf("interactive_policy: unsupported action %q", decision.Action)
	}
}

func (p *InteractivePolicy) TransformResponse(_ context.Context, _ *transform.TransformContext, _ *http.Request, _ *http.Response) (*transform.TransformResult, error) {
	return &transform.TransformResult{Action: transform.ActionContinue}, nil
}

func (p *InteractivePolicy) ask(ctx context.Context, tctx *transform.TransformContext, req *http.Request) (*decisionResponse, error) {
	payload := decisionRequest{
		Host:   hostmatch.StripPort(req.Host),
		Method: req.Method,
		Path:   req.URL.Path,
		URL:    redactedURL(req),
		SNI:    tctx.SNI,
		Header: safeHeaders(req.Header),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("interactive_policy: marshaling request: %w", err)
	}

	askCtx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(askCtx, http.MethodPost, p.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("interactive_policy: building request: %w", err)
	}
	httpReq.Header.Set("content-type", "application/json")

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("interactive_policy: policy service: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("interactive_policy: policy service returned %s", resp.Status)
	}

	var decision decisionResponse
	if err := json.NewDecoder(resp.Body).Decode(&decision); err != nil {
		return nil, fmt.Errorf("interactive_policy: decoding decision: %w", err)
	}
	return &decision, nil
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
