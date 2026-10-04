package config

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"
)

// parseS3URL parses an S3 URL of the form s3://bucket/key and returns the
// bucket and key. It returns an error if the URL is malformed.
func parseS3URL(url string) (bucket, key string, err error) {
	rest := strings.TrimPrefix(url, "s3://")
	idx := strings.IndexByte(rest, '/')
	if idx <= 0 || idx == len(rest)-1 {
		return "", "", fmt.Errorf("invalid S3 URL %q: expected s3://bucket/key", url)
	}
	return rest[:idx], rest[idx+1:], nil
}

// parseFileOrS3 parses a config from a local file path or an S3 URL without
// applying defaults or validation.
func parseFileOrS3(path string) (*Config, error) {
	if strings.HasPrefix(path, "s3://") {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		return parseS3(ctx, path)
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening config file: %w", err)
	}
	defer f.Close()

	return parse(f)
}
