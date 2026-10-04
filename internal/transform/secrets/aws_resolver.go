//go:build !nosy

package secrets

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"gopkg.in/yaml.v3"
	"log/slog"
	"sync"
)

// --- shared AWS client cache ---

// awsClientCache provides region-keyed caching for any AWS service client.
type awsClientCache[C any] struct {
	mu        sync.Mutex
	clients   map[string]C
	newClient func(cfg aws.Config) C
}

func (c *awsClientCache[C]) get(ctx context.Context, region string) (C, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if client, ok := c.clients[region]; ok {
		return client, nil
	}
	var opts []func(*awsconfig.LoadOptions) error
	if region != "" {
		opts = append(opts, awsconfig.WithRegion(region))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		var zero C
		return zero, fmt.Errorf("loading AWS config: %w", err)
	}
	client := c.newClient(cfg)
	c.clients[region] = client
	return client, nil
}

// --- AWS Secrets Manager builder ---

// smClient is the subset of the AWS Secrets Manager API used by awsSMBuilder.
type smClient interface {
	GetSecretValue(ctx context.Context, input *secretsmanager.GetSecretValueInput, opts ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
}

// awsSMBuilder reads secrets from AWS Secrets Manager.
type awsSMBuilder struct {
	clientFor func(ctx context.Context, region string) (smClient, error)
	logger    *slog.Logger
}

type awsSMConfig struct {
	Type       string `yaml:"type"`
	SecretID   string `yaml:"secret_id"`
	Region     string `yaml:"region,omitempty"`
	TTL        string `yaml:"ttl,omitempty"`
	FailureTTL string `yaml:"failure_ttl,omitempty"`
}

func newAWSSMBuilder(logger *slog.Logger) *awsSMBuilder {
	cache := &awsClientCache[smClient]{
		clients:   make(map[string]smClient),
		newClient: func(cfg aws.Config) smClient { return secretsmanager.NewFromConfig(cfg) },
	}
	return &awsSMBuilder{clientFor: cache.get, logger: logger}
}

func (r *awsSMBuilder) Build(raw yaml.Node) (secretSource, error) {
	var cfg awsSMConfig
	if err := raw.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parsing aws_sm source config: %w", err)
	}
	if cfg.SecretID == "" {
		return nil, fmt.Errorf("aws_sm source requires \"secret_id\" field")
	}
	return buildLazySource(cfg.SecretID, cfg.TTL, cfg.FailureTTL, r.logger, func(ctx context.Context) (string, error) {
		return r.fetchSecret(ctx, cfg)
	})
}

func (r *awsSMBuilder) fetchSecret(ctx context.Context, cfg awsSMConfig) (string, error) {
	client, err := r.clientFor(ctx, cfg.Region)
	if err != nil {
		return "", fmt.Errorf("creating AWS SM client: %w", err)
	}
	out, err := client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(cfg.SecretID),
	})
	if err != nil {
		return "", fmt.Errorf("fetching secret %q: %w", cfg.SecretID, err)
	}
	val := aws.ToString(out.SecretString)
	if val == "" {
		return "", fmt.Errorf("secret %q resolved to empty value", cfg.SecretID)
	}
	return val, nil
}

// --- AWS Systems Manager Parameter Store builder ---

// ssmClient is the subset of the AWS SSM API used by awsSSMBuilder.
type ssmClient interface {
	GetParameter(ctx context.Context, input *ssm.GetParameterInput, opts ...func(*ssm.Options)) (*ssm.GetParameterOutput, error)
}

// awsSSMBuilder reads secrets from AWS Systems Manager Parameter Store.
type awsSSMBuilder struct {
	clientFor func(ctx context.Context, region string) (ssmClient, error)
	logger    *slog.Logger
}

type awsSSMConfig struct {
	Type           string `yaml:"type"`
	Name           string `yaml:"name"`
	Region         string `yaml:"region,omitempty"`
	WithDecryption *bool  `yaml:"with_decryption,omitempty"`
	TTL            string `yaml:"ttl,omitempty"`
	FailureTTL     string `yaml:"failure_ttl,omitempty"`
}

func (cfg awsSSMConfig) decryptValue() bool {
	return cfg.WithDecryption == nil || *cfg.WithDecryption
}

func newAWSSSMBuilder(logger *slog.Logger) *awsSSMBuilder {
	cache := &awsClientCache[ssmClient]{
		clients:   make(map[string]ssmClient),
		newClient: func(cfg aws.Config) ssmClient { return ssm.NewFromConfig(cfg) },
	}
	return &awsSSMBuilder{clientFor: cache.get, logger: logger}
}

func (r *awsSSMBuilder) Build(raw yaml.Node) (secretSource, error) {
	var cfg awsSSMConfig
	if err := raw.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parsing aws_ssm source config: %w", err)
	}
	if cfg.Name == "" {
		return nil, fmt.Errorf("aws_ssm source requires \"name\" field")
	}
	return buildLazySource(cfg.Name, cfg.TTL, cfg.FailureTTL, r.logger, func(ctx context.Context) (string, error) {
		return r.fetchParameter(ctx, cfg)
	})
}

func (r *awsSSMBuilder) fetchParameter(ctx context.Context, cfg awsSSMConfig) (string, error) {
	client, err := r.clientFor(ctx, cfg.Region)
	if err != nil {
		return "", fmt.Errorf("creating AWS SSM client: %w", err)
	}
	out, err := client.GetParameter(ctx, &ssm.GetParameterInput{
		Name:           aws.String(cfg.Name),
		WithDecryption: aws.Bool(cfg.decryptValue()),
	})
	if err != nil {
		return "", fmt.Errorf("fetching parameter %q: %w", cfg.Name, err)
	}
	if out == nil || out.Parameter == nil {
		return "", fmt.Errorf("parameter %q resolved without a value", cfg.Name)
	}
	val := aws.ToString(out.Parameter.Value)
	if val == "" {
		return "", fmt.Errorf("parameter %q resolved to empty value", cfg.Name)
	}
	return val, nil
}
