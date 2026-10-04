//go:build nosy

package config

import (
	"context"
	"errors"
)

func parseS3(_ context.Context, _ string) (*Config, error) {
	return nil, errors.New("S3 configuration sources are not supported by the Nosy proxy build; use a local configuration file")
}
