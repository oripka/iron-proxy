//go:build !nosy

package secrets

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/ironsh/iron-proxy/internal/hostmatch"
	"github.com/ironsh/iron-proxy/internal/transform"
	"github.com/stretchr/testify/require"
	"io"
	"log/slog"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// --- End-to-end tests with real awsSMBuilder and mock AWS client ---

func awsSMRegistry(client smClient) sourceBuilderRegistry {
	return sourceBuilderRegistry{"aws_sm": &awsSMBuilder{
		clientFor: func(_ context.Context, _ string) (smClient, error) {
			return client, nil
		},
		logger: slog.Default(),
	}}
}

func makeAWSSMSecrets(t *testing.T, client smClient, entries []secretEntry) *Secrets {
	t.Helper()
	cfg := secretsConfig{Secrets: entries}
	s, err := newFromConfig(cfg, awsSMRegistry(client))
	require.NoError(t, err)
	return s
}

func TestAWSSM_EndToEnd_HeaderSwap(t *testing.T) {
	client := &mockSMClient{fn: func(_ context.Context, input *secretsmanager.GetSecretValueInput) (*secretsmanager.GetSecretValueOutput, error) {
		require.Equal(t, "arn:aws:sm:us-east-1:123:secret:openai", aws.ToString(input.SecretId))
		return &secretsmanager.GetSecretValueOutput{
			SecretString: aws.String("sk-real-openai-key"),
		}, nil
	}}

	s := makeAWSSMSecrets(t, client, []secretEntry{{
		Source:       yamlNode(t, map[string]string{"type": "aws_sm", "secret_id": "arn:aws:sm:us-east-1:123:secret:openai"}),
		ProxyValue:   "proxy-openai-abc123",
		MatchHeaders: []string{"Authorization"},
		Rules:        []hostmatch.RuleConfig{{Host: "api.openai.com"}},
	}})

	req := openaiReq("POST", "/v1/chat")
	req.Header.Set("Authorization", "Bearer proxy-openai-abc123")

	doTransform(t, s, req)
	require.Equal(t, "Bearer sk-real-openai-key", req.Header.Get("Authorization"))
}

func TestAWSSM_EndToEnd_JSONKey(t *testing.T) {
	client := staticSMClient(&secretsmanager.GetSecretValueOutput{
		SecretString: aws.String(`{"api_key": "sk-from-json", "other": "ignored"}`),
	}, nil)

	s := makeAWSSMSecrets(t, client, []secretEntry{{
		Source: yamlNode(t, map[string]string{
			"type":      "aws_sm",
			"secret_id": "arn:aws:sm:us-east-1:123:secret:multi",
			"json_key":  "api_key",
		}),
		ProxyValue:   "proxy-tok",
		MatchHeaders: []string{"X-Api-Key"},
		Rules:        []hostmatch.RuleConfig{{Host: "api.example.com"}},
	}})

	req := httptest.NewRequest("GET", "http://api.example.com/v1/data", nil)
	req.Host = "api.example.com"
	req.Header.Set("X-Api-Key", "proxy-tok")

	doTransform(t, s, req)
	require.Equal(t, "sk-from-json", req.Header.Get("X-Api-Key"))
}

func TestAWSSM_EndToEnd_BodySwap(t *testing.T) {
	client := staticSMClient(&secretsmanager.GetSecretValueOutput{
		SecretString: aws.String("real-secret"),
	}, nil)

	s := makeAWSSMSecrets(t, client, []secretEntry{{
		Source:     yamlNode(t, map[string]string{"type": "aws_sm", "secret_id": "arn:test"}),
		ProxyValue: "proxy-tok",
		MatchBody:  true,
		Rules:      []hostmatch.RuleConfig{{Host: "api.example.com"}},
	}})

	body := `{"key": "proxy-tok"}`
	rb := transform.NewBufferedBody(io.NopCloser(strings.NewReader(body)), 1<<20)
	req := httptest.NewRequest("POST", "http://api.example.com/v1/data", nil)
	req.Host = "api.example.com"
	req.Body = rb

	doTransform(t, s, req)

	result, err := io.ReadAll(req.Body)
	require.NoError(t, err)
	require.Contains(t, string(result), "real-secret")
	require.NotContains(t, string(result), "proxy-tok")
}

func TestAWSSM_EndToEnd_TTLRefresh(t *testing.T) {
	var callCount atomic.Int32
	client := &mockSMClient{fn: func(_ context.Context, _ *secretsmanager.GetSecretValueInput) (*secretsmanager.GetSecretValueOutput, error) {
		n := callCount.Add(1)
		// Return a different value each call so we can observe the refresh.
		return &secretsmanager.GetSecretValueOutput{
			SecretString: aws.String(fmt.Sprintf("value-%d", n)),
		}, nil
	}}

	s := makeAWSSMSecrets(t, client, []secretEntry{{
		Source: yamlNode(t, map[string]string{
			"type":      "aws_sm",
			"secret_id": "arn:test",
			"ttl":       "1ns", // expires immediately so each request triggers refresh
		}),
		ProxyValue:   "proxy-tok",
		MatchHeaders: []string{"Authorization"},
		Rules:        []hostmatch.RuleConfig{{Host: "api.example.com"}},
	}})
	require.Equal(t, int32(0), callCount.Load(), "lazy: no fetch before first request")

	// First request: triggers initial fetch (call 1, value-1).
	req := httptest.NewRequest("GET", "http://api.example.com/v1", nil)
	req.Host = "api.example.com"
	req.Header.Set("Authorization", "Bearer proxy-tok")
	doTransform(t, s, req)
	require.Equal(t, "Bearer value-1", req.Header.Get("Authorization"))

	// Second request: TTL already expired, triggers refresh (call 2, value-2).
	req = httptest.NewRequest("GET", "http://api.example.com/v1", nil)
	req.Host = "api.example.com"
	req.Header.Set("Authorization", "Bearer proxy-tok")
	doTransform(t, s, req)
	require.Equal(t, "Bearer value-2", req.Header.Get("Authorization"))

	require.GreaterOrEqual(t, callCount.Load(), int32(2))
}

func TestAWSSM_EndToEnd_TTLServesStaleOnError(t *testing.T) {
	var callCount atomic.Int32
	client := &mockSMClient{fn: func(_ context.Context, _ *secretsmanager.GetSecretValueInput) (*secretsmanager.GetSecretValueOutput, error) {
		n := callCount.Add(1)
		// First fetch (lazy, on first request) succeeds.
		if n == 1 {
			return &secretsmanager.GetSecretValueOutput{
				SecretString: aws.String("good-value"),
			}, nil
		}
		// All subsequent refresh attempts fail.
		return nil, fmt.Errorf("aws transient error")
	}}

	s := makeAWSSMSecrets(t, client, []secretEntry{{
		Source: yamlNode(t, map[string]string{
			"type":      "aws_sm",
			"secret_id": "arn:test",
			"ttl":       "1ns",
		}),
		ProxyValue:   "proxy-tok",
		MatchHeaders: []string{"Authorization"},
		Rules:        []hostmatch.RuleConfig{{Host: "api.example.com"}},
	}})
	require.Equal(t, int32(0), callCount.Load(), "lazy: no fetch before first request")

	// First request: lazy fetch succeeds and caches "good-value".
	req := httptest.NewRequest("GET", "http://api.example.com/v1", nil)
	req.Host = "api.example.com"
	req.Header.Set("Authorization", "Bearer proxy-tok")
	doTransform(t, s, req)
	require.Equal(t, "Bearer good-value", req.Header.Get("Authorization"))

	// Second request: TTL expired, refresh fails, stale "good-value" served.
	req = httptest.NewRequest("GET", "http://api.example.com/v1", nil)
	req.Host = "api.example.com"
	req.Header.Set("Authorization", "Bearer proxy-tok")
	doTransform(t, s, req)
	require.Equal(t, "Bearer good-value", req.Header.Get("Authorization"))

	// Third request: same — refresh fails again, stale value still served.
	req = httptest.NewRequest("GET", "http://api.example.com/v1", nil)
	req.Host = "api.example.com"
	req.Header.Set("Authorization", "Bearer proxy-tok")
	doTransform(t, s, req)
	require.Equal(t, "Bearer good-value", req.Header.Get("Authorization"))

	// At least 2 refresh attempts beyond the initial successful fetch.
	require.GreaterOrEqual(t, callCount.Load(), int32(3))
}

func TestAWSSM_EndToEnd_RequireRejectsWithoutToken(t *testing.T) {
	client := staticSMClient(&secretsmanager.GetSecretValueOutput{
		SecretString: aws.String("real-secret"),
	}, nil)

	s := makeAWSSMSecrets(t, client, []secretEntry{{
		Source:       yamlNode(t, map[string]string{"type": "aws_sm", "secret_id": "arn:test"}),
		ProxyValue:   "proxy-tok",
		MatchHeaders: []string{"Authorization"},
		Require:      true,
		Rules:        []hostmatch.RuleConfig{{Host: "api.example.com"}},
	}})

	req := httptest.NewRequest("GET", "http://api.example.com/v1", nil)
	req.Host = "api.example.com"
	req.Header.Set("Authorization", "Bearer wrong-token")

	res, err := s.TransformRequest(context.Background(), &transform.TransformContext{}, req)
	require.NoError(t, err)
	require.Equal(t, transform.ActionReject, res.Action)
}

// --- End-to-end tests with real awsSSMBuilder and mock AWS client ---

func awsSSMRegistry(client ssmClient) sourceBuilderRegistry {
	return sourceBuilderRegistry{"aws_ssm": &awsSSMBuilder{
		clientFor: func(_ context.Context, _ string) (ssmClient, error) {
			return client, nil
		},
		logger: slog.Default(),
	}}
}

func makeAWSSSMSecrets(t *testing.T, client ssmClient, entries []secretEntry) *Secrets {
	t.Helper()
	cfg := secretsConfig{Secrets: entries}
	s, err := newFromConfig(cfg, awsSSMRegistry(client))
	require.NoError(t, err)
	return s
}

func TestAWSSSM_EndToEnd_JSONKeyHeaderSwap(t *testing.T) {
	client := &mockSSMClient{fn: func(_ context.Context, input *ssm.GetParameterInput) (*ssm.GetParameterOutput, error) {
		require.Equal(t, "/myapp/api-key", aws.ToString(input.Name))
		require.True(t, aws.ToBool(input.WithDecryption))
		return &ssm.GetParameterOutput{
			Parameter: &ssmtypes.Parameter{Value: aws.String(`{"api_key":"sk-from-ssm"}`)},
		}, nil
	}}

	s := makeAWSSSMSecrets(t, client, []secretEntry{{
		Source: yamlNode(t, map[string]string{
			"type":     "aws_ssm",
			"name":     "/myapp/api-key",
			"region":   "us-east-1",
			"json_key": "api_key",
			"ttl":      "15m",
		}),
		Replace: &replaceConfig{
			ProxyValue:   "proxy-token-789",
			MatchHeaders: []string{"Authorization"},
		},
		Rules: []hostmatch.RuleConfig{{Host: "api.example.com"}},
	}})

	req := httptest.NewRequest("GET", "http://api.example.com/v1/data", nil)
	req.Host = "api.example.com"
	req.Header.Set("Authorization", "Bearer proxy-token-789")

	doTransform(t, s, req)
	require.Equal(t, "Bearer sk-from-ssm", req.Header.Get("Authorization"))
}
