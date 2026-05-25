// Package awssigv4 implements AWS Signature Version 4 request signing.
package awssigv4

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"gopkg.in/yaml.v3"

	"github.com/ironsh/iron-proxy/internal/hostmatch"
	"github.com/ironsh/iron-proxy/internal/transform"
)

func init() {
	transform.Register("aws_sigv4", factory)
}

type sigv4Config struct {
	Signers []signerConfig `yaml:"signers"`
}

type signerConfig struct {
	Service            string                 `yaml:"service"`
	Region             string                 `yaml:"region"`
	AccessKeyIDEnv     string                 `yaml:"access_key_id_env"`
	SecretAccessKeyEnv string                 `yaml:"secret_access_key_env"`
	SessionTokenEnv    string                 `yaml:"session_token_env,omitempty"`
	Rules              []hostmatch.RuleConfig `yaml:"rules"`
}

type resolvedSigner struct {
	service            string
	region             string
	accessKeyIDEnv     string
	secretAccessKeyEnv string
	sessionTokenEnv    string
	rules              []hostmatch.Rule
}

// AWSSigV4 signs matching outbound requests with AWS Signature Version 4.
type AWSSigV4 struct {
	signers []resolvedSigner
	signer  *v4.Signer
	now     func() time.Time
}

func factory(cfg yaml.Node, _ *slog.Logger) (transform.Transformer, error) {
	var c sigv4Config
	if err := cfg.Decode(&c); err != nil {
		return nil, fmt.Errorf("parsing aws_sigv4 config: %w", err)
	}
	return newFromConfig(c, time.Now)
}

func newFromConfig(cfg sigv4Config, now func() time.Time) (*AWSSigV4, error) {
	if len(cfg.Signers) == 0 {
		return nil, fmt.Errorf("aws_sigv4: at least one signer is required")
	}
	if now == nil {
		now = time.Now
	}

	resolved := make([]resolvedSigner, 0, len(cfg.Signers))
	for i, entry := range cfg.Signers {
		if entry.Service == "" {
			return nil, fmt.Errorf("aws_sigv4: signers[%d].service is required", i)
		}
		if entry.Region == "" {
			return nil, fmt.Errorf("aws_sigv4: signers[%d].region is required", i)
		}
		if entry.AccessKeyIDEnv == "" {
			return nil, fmt.Errorf("aws_sigv4: signers[%d].access_key_id_env is required", i)
		}
		if entry.SecretAccessKeyEnv == "" {
			return nil, fmt.Errorf("aws_sigv4: signers[%d].secret_access_key_env is required", i)
		}
		rules, err := hostmatch.CompileRules(entry.Rules, hostmatch.NullResolver{}, fmt.Sprintf("aws_sigv4 signers[%d]", i))
		if err != nil {
			return nil, err
		}
		if len(rules) == 0 {
			return nil, fmt.Errorf("aws_sigv4: signers[%d].rules is required", i)
		}
		resolved = append(resolved, resolvedSigner{
			service:            entry.Service,
			region:             entry.Region,
			accessKeyIDEnv:     entry.AccessKeyIDEnv,
			secretAccessKeyEnv: entry.SecretAccessKeyEnv,
			sessionTokenEnv:    entry.SessionTokenEnv,
			rules:              rules,
		})
	}

	return &AWSSigV4{
		signers: resolved,
		signer:  v4.NewSigner(),
		now:     now,
	}, nil
}

func (a *AWSSigV4) Name() string { return "aws_sigv4" }

func (a *AWSSigV4) TransformRequest(ctx context.Context, tctx *transform.TransformContext, req *http.Request) (*transform.TransformResult, error) {
	if req.Method == http.MethodConnect || tctx.Mode == transform.ModeSNIOnly {
		return &transform.TransformResult{Action: transform.ActionContinue}, nil
	}

	for _, signer := range a.signers {
		if !hostmatch.MatchAnyRule(ctx, signer.rules, req) {
			continue
		}
		if err := a.sign(ctx, tctx, req, signer); err != nil {
			return nil, err
		}
		return &transform.TransformResult{Action: transform.ActionContinue}, nil
	}
	return &transform.TransformResult{Action: transform.ActionContinue}, nil
}

func (a *AWSSigV4) TransformResponse(_ context.Context, _ *transform.TransformContext, _ *http.Request, _ *http.Response) (*transform.TransformResult, error) {
	return &transform.TransformResult{Action: transform.ActionContinue}, nil
}

func (a *AWSSigV4) sign(ctx context.Context, tctx *transform.TransformContext, req *http.Request, signer resolvedSigner) error {
	creds, err := signer.credentials()
	if err != nil {
		return err
	}

	body, err := readExactBody(req)
	if err != nil {
		return err
	}
	payloadHash := sha256Hex(body)

	req.Header.Del("Authorization")
	req.Header.Del("X-Amz-Date")
	req.Header.Del("X-Amz-Security-Token")

	req.Body = transform.NewBufferedBodyFromBytes(body)
	req.ContentLength = int64(len(body))
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(body)), nil
	}

	if err := a.signer.SignHTTP(ctx, creds, req, payloadHash, signer.service, signer.region, a.now().UTC()); err != nil {
		return fmt.Errorf("aws_sigv4 signing request: %w", err)
	}

	tctx.Annotate("signed", map[string]any{
		"host":          hostmatch.StripPort(req.Host),
		"service":       signer.service,
		"region":        signer.region,
		"session_token": creds.SessionToken != "",
	})
	return nil
}

func (s resolvedSigner) credentials() (aws.Credentials, error) {
	accessKeyID := os.Getenv(s.accessKeyIDEnv)
	if accessKeyID == "" {
		return aws.Credentials{}, fmt.Errorf("aws_sigv4: %s is required", s.accessKeyIDEnv)
	}
	secretAccessKey := os.Getenv(s.secretAccessKeyEnv)
	if secretAccessKey == "" {
		return aws.Credentials{}, fmt.Errorf("aws_sigv4: %s is required", s.secretAccessKeyEnv)
	}

	creds := aws.Credentials{
		AccessKeyID:     accessKeyID,
		SecretAccessKey: secretAccessKey,
		Source:          "iron-proxy-env",
	}
	if s.sessionTokenEnv != "" {
		creds.SessionToken = os.Getenv(s.sessionTokenEnv)
	}
	return creds, nil
}

func readExactBody(req *http.Request) ([]byte, error) {
	if req.Body == nil {
		return nil, nil
	}

	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, fmt.Errorf("reading request body for aws_sigv4 signing: %w", err)
	}

	if buffered, ok := req.Body.(*transform.BufferedBody); ok && buffered.Truncated() {
		return nil, fmt.Errorf("aws_sigv4: request body exceeded proxy.max_request_body_bytes before signing")
	}
	if req.ContentLength >= 0 && int64(len(body)) != req.ContentLength {
		return nil, fmt.Errorf("aws_sigv4: request body length mismatch: read %d bytes, expected %d", len(body), req.ContentLength)
	}
	return body, nil
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
