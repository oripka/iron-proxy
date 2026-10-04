//go:build !nosy

package config

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// parseS3 fetches a config file from S3 and parses it without applying defaults
// or validation. It uses the default AWS credential chain.
func parseS3(ctx context.Context, rawURL string) (*Config, error) {
	bucket, key, err := parseS3URL(rawURL)
	if err != nil {
		return nil, err
	}

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("loading AWS config: %w", err)
	}

	client := s3.NewFromConfig(awsCfg)
	out, err := client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, fmt.Errorf("fetching s3://%s/%s: %w", bucket, key, err)
	}
	defer out.Body.Close()

	return parse(out.Body)
}
