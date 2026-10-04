//go:build !nosy

package secrets

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/stretchr/testify/require"
	"log/slog"
	"testing"
)

// mockSMClient is a configurable mock for the AWS Secrets Manager client.
type mockSMClient struct {
	fn func(ctx context.Context, input *secretsmanager.GetSecretValueInput) (*secretsmanager.GetSecretValueOutput, error)
}

func (m *mockSMClient) GetSecretValue(ctx context.Context, input *secretsmanager.GetSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	return m.fn(ctx, input)
}

// staticSMClient returns a mockSMClient that always returns the given output/error.
func staticSMClient(out *secretsmanager.GetSecretValueOutput, err error) *mockSMClient {
	return &mockSMClient{fn: func(_ context.Context, _ *secretsmanager.GetSecretValueInput) (*secretsmanager.GetSecretValueOutput, error) {
		return out, err
	}}
}

func newTestAWSSMBuilder(client smClient) *awsSMBuilder {
	return &awsSMBuilder{
		clientFor: func(_ context.Context, _ string) (smClient, error) {
			return client, nil
		},
		logger: slog.Default(),
	}
}

// mockSSMClient is a configurable mock for the AWS SSM client.
type mockSSMClient struct {
	fn func(ctx context.Context, input *ssm.GetParameterInput) (*ssm.GetParameterOutput, error)
}

func (m *mockSSMClient) GetParameter(ctx context.Context, input *ssm.GetParameterInput, _ ...func(*ssm.Options)) (*ssm.GetParameterOutput, error) {
	return m.fn(ctx, input)
}

// staticSSMClient returns a mockSSMClient that always returns the given output/error.
func staticSSMClient(out *ssm.GetParameterOutput, err error) *mockSSMClient {
	return &mockSSMClient{fn: func(_ context.Context, _ *ssm.GetParameterInput) (*ssm.GetParameterOutput, error) {
		return out, err
	}}
}

func newTestAWSSSMBuilder(client ssmClient) *awsSSMBuilder {
	return &awsSSMBuilder{
		clientFor: func(_ context.Context, _ string) (ssmClient, error) {
			return client, nil
		},
		logger: slog.Default(),
	}
}

// --- awsSMBuilder tests ---

func TestAWSSMBuilder_PlainString(t *testing.T) {
	client := staticSMClient(&secretsmanager.GetSecretValueOutput{
		SecretString: aws.String("my-secret-value"),
	}, nil)
	r := newTestAWSSMBuilder(client)
	node := yamlNode(t, map[string]string{"type": "aws_sm", "secret_id": "arn:aws:sm:us-east-1:123:secret:foo"})
	result, err := r.Build(node)
	require.NoError(t, err)
	require.Equal(t, "arn:aws:sm:us-east-1:123:secret:foo", result.Name())

	val, err := result.Get(context.Background())
	require.NoError(t, err)
	require.Equal(t, "my-secret-value", val)
}

func TestAWSSMBuilder_TTLReturnsCachedValue(t *testing.T) {
	client := staticSMClient(&secretsmanager.GetSecretValueOutput{
		SecretString: aws.String("value"),
	}, nil)
	r := newTestAWSSMBuilder(client)
	node := yamlNode(t, map[string]string{
		"type":      "aws_sm",
		"secret_id": "arn:aws:sm:us-east-1:123:secret:foo",
		"ttl":       "15m",
	})
	result, err := r.Build(node)
	require.NoError(t, err)

	// GetValue should return cached value without re-fetching.
	val, err := result.Get(context.Background())
	require.NoError(t, err)
	require.Equal(t, "value", val)
}

func TestAWSSMBuilder_Errors(t *testing.T) {
	// errAt: "build" for static config errors; "fetch" for network/value errors
	// that surface lazily on first Get call.
	tests := []struct {
		name   string
		client *mockSMClient
		input  map[string]string
		errMsg string
		errAt  string
	}{
		{
			name:   "missing secret_id",
			client: staticSMClient(nil, nil),
			input:  map[string]string{"type": "aws_sm"},
			errMsg: "\"secret_id\" field",
			errAt:  "build",
		},
		{
			name:   "invalid TTL",
			client: staticSMClient(nil, nil),
			input:  map[string]string{"type": "aws_sm", "secret_id": "arn:foo", "ttl": "not-a-duration"},
			errMsg: "parsing ttl",
			errAt:  "build",
		},
		{
			name:   "aws error",
			client: staticSMClient(nil, fmt.Errorf("access denied")),
			input:  map[string]string{"type": "aws_sm", "secret_id": "arn:foo"},
			errMsg: "access denied",
			errAt:  "fetch",
		},
		{
			name: "empty secret value",
			client: staticSMClient(&secretsmanager.GetSecretValueOutput{
				SecretString: aws.String(""),
			}, nil),
			input:  map[string]string{"type": "aws_sm", "secret_id": "arn:foo"},
			errMsg: "empty value",
			errAt:  "fetch",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newTestAWSSMBuilder(tt.client)
			node := yamlNode(t, tt.input)
			result, err := r.Build(node)
			if tt.errAt == "build" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.errMsg)
				return
			}
			require.NoError(t, err)
			_, err = result.Get(context.Background())
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.errMsg)
		})
	}
}

// --- awsSSMBuilder tests ---

func TestAWSSSMBuilder_PlainString(t *testing.T) {
	client := staticSSMClient(&ssm.GetParameterOutput{
		Parameter: &ssmtypes.Parameter{Value: aws.String("my-param-value")},
	}, nil)
	r := newTestAWSSSMBuilder(client)
	node := yamlNode(t, map[string]string{"type": "aws_ssm", "name": "/myapp/api-key"})
	result, err := r.Build(node)
	require.NoError(t, err)
	require.Equal(t, "/myapp/api-key", result.Name())

	val, err := result.Get(context.Background())
	require.NoError(t, err)
	require.Equal(t, "my-param-value", val)
}

func TestAWSSSMBuilder_TTLReturnsCachedValue(t *testing.T) {
	client := staticSSMClient(&ssm.GetParameterOutput{
		Parameter: &ssmtypes.Parameter{Value: aws.String("value")},
	}, nil)
	r := newTestAWSSSMBuilder(client)
	node := yamlNode(t, map[string]string{
		"type": "aws_ssm",
		"name": "/myapp/secret",
		"ttl":  "15m",
	})
	result, err := r.Build(node)
	require.NoError(t, err)

	val, err := result.Get(context.Background())
	require.NoError(t, err)
	require.Equal(t, "value", val)
}

func TestAWSSSMBuilder_WithDecryption(t *testing.T) {
	tests := []struct {
		name string
		raw  map[string]any
		want bool
	}{
		{
			name: "defaults to true",
			raw:  map[string]any{"type": "aws_ssm", "name": "/myapp/secret"},
			want: true,
		},
		{
			name: "explicit true",
			raw:  map[string]any{"type": "aws_ssm", "name": "/myapp/secret", "with_decryption": true},
			want: true,
		},
		{
			name: "explicit false",
			raw:  map[string]any{"type": "aws_ssm", "name": "/myapp/secret", "with_decryption": false},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var capturedInput *ssm.GetParameterInput
			client := &mockSSMClient{fn: func(_ context.Context, input *ssm.GetParameterInput) (*ssm.GetParameterOutput, error) {
				capturedInput = input
				return &ssm.GetParameterOutput{
					Parameter: &ssmtypes.Parameter{Value: aws.String("decrypted-value")},
				}, nil
			}}
			r := newTestAWSSSMBuilder(client)
			result, err := r.Build(yamlNode(t, tt.raw))
			require.NoError(t, err)

			val, err := result.Get(context.Background())
			require.NoError(t, err)
			require.Equal(t, "decrypted-value", val)
			require.Equal(t, tt.want, aws.ToBool(capturedInput.WithDecryption))
		})
	}
}

func TestAWSSSMBuilder_Region(t *testing.T) {
	client := staticSSMClient(&ssm.GetParameterOutput{
		Parameter: &ssmtypes.Parameter{Value: aws.String("value")},
	}, nil)
	var gotRegion string
	r := &awsSSMBuilder{
		clientFor: func(_ context.Context, region string) (ssmClient, error) {
			gotRegion = region
			return client, nil
		},
		logger: slog.Default(),
	}

	result, err := r.Build(yamlNode(t, map[string]string{
		"type":   "aws_ssm",
		"name":   "/myapp/secret",
		"region": "us-east-1",
	}))
	require.NoError(t, err)
	_, err = result.Get(context.Background())
	require.NoError(t, err)
	require.Equal(t, "us-east-1", gotRegion)
}

func TestAWSSSMBuilder_Errors(t *testing.T) {
	tests := []struct {
		name   string
		client *mockSSMClient
		input  map[string]string
		errMsg string
		errAt  string
	}{
		{
			name:   "missing name",
			client: staticSSMClient(nil, nil),
			input:  map[string]string{"type": "aws_ssm"},
			errMsg: "\"name\" field",
			errAt:  "build",
		},
		{
			name:   "invalid TTL",
			client: staticSSMClient(nil, nil),
			input:  map[string]string{"type": "aws_ssm", "name": "/myapp/key", "ttl": "not-a-duration"},
			errMsg: "parsing ttl",
			errAt:  "build",
		},
		{
			name:   "aws error",
			client: staticSSMClient(nil, fmt.Errorf("parameter not found")),
			input:  map[string]string{"type": "aws_ssm", "name": "/myapp/missing"},
			errMsg: "parameter not found",
			errAt:  "fetch",
		},
		{
			name: "empty parameter value",
			client: staticSSMClient(&ssm.GetParameterOutput{
				Parameter: &ssmtypes.Parameter{Value: aws.String("")},
			}, nil),
			input:  map[string]string{"type": "aws_ssm", "name": "/myapp/empty"},
			errMsg: "empty value",
			errAt:  "fetch",
		},
		{
			name:   "missing parameter",
			client: staticSSMClient(&ssm.GetParameterOutput{}, nil),
			input:  map[string]string{"type": "aws_ssm", "name": "/myapp/missing-value"},
			errMsg: "without a value",
			errAt:  "fetch",
		},
		{
			name:   "nil response",
			client: staticSSMClient(nil, nil),
			input:  map[string]string{"type": "aws_ssm", "name": "/myapp/nil-response"},
			errMsg: "without a value",
			errAt:  "fetch",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newTestAWSSSMBuilder(tt.client)
			node := yamlNode(t, tt.input)
			result, err := r.Build(node)
			if tt.errAt == "build" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.errMsg)
				return
			}
			require.NoError(t, err)
			_, err = result.Get(context.Background())
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.errMsg)
		})
	}
}

func TestAWSSMBuilder_BuildDoesNotFetch(t *testing.T) {
	calls := 0
	client := &mockSMClient{fn: func(_ context.Context, _ *secretsmanager.GetSecretValueInput) (*secretsmanager.GetSecretValueOutput, error) {
		calls++
		return &secretsmanager.GetSecretValueOutput{SecretString: aws.String("v")}, nil
	}}
	r := newTestAWSSMBuilder(client)
	node := yamlNode(t, map[string]string{"type": "aws_sm", "secret_id": "arn:test"})
	result, err := r.Build(node)
	require.NoError(t, err)
	require.Equal(t, 0, calls, "Build must not call AWS")

	_, err = result.Get(context.Background())
	require.NoError(t, err)
	require.Equal(t, 1, calls, "first GetValue triggers fetch")
}

func TestAWSSSMBuilder_BuildDoesNotFetch(t *testing.T) {
	calls := 0
	client := &mockSSMClient{fn: func(_ context.Context, _ *ssm.GetParameterInput) (*ssm.GetParameterOutput, error) {
		calls++
		return &ssm.GetParameterOutput{Parameter: &ssmtypes.Parameter{Value: aws.String("v")}}, nil
	}}
	r := newTestAWSSSMBuilder(client)
	node := yamlNode(t, map[string]string{"type": "aws_ssm", "name": "/p"})
	result, err := r.Build(node)
	require.NoError(t, err)
	require.Equal(t, 0, calls)

	_, err = result.Get(context.Background())
	require.NoError(t, err)
	require.Equal(t, 1, calls)
}

func TestResolveSource_AWSJSONKey(t *testing.T) {
	const blob = `{"refresh_token": "rt-123", "client_id": "cid", "num": 42}`
	t.Run("extracts field from aws_sm source", func(t *testing.T) {
		reg := sourceBuilderRegistry{"aws_sm": newTestAWSSMBuilder(staticSMClient(
			&secretsmanager.GetSecretValueOutput{SecretString: aws.String(blob)}, nil,
		))}
		node := yamlNode(t, map[string]string{
			"type":      "aws_sm",
			"secret_id": "arn:foo",
			"json_key":  "client_id",
		})
		src, err := resolveSource(reg, node)
		require.NoError(t, err)

		val, err := src.Get(context.Background())
		require.NoError(t, err)
		require.Equal(t, "cid", val)
	})

}
