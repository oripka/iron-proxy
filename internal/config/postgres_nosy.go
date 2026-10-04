//go:build nosy

package config

import (
	"fmt"
	"os"
	"strings"
)

// Reject unsupported configuration before a listener or control-plane client
// starts. Do not silently ignore a security policy this build cannot enforce.
func validateBuildConfig(cfg *Config) error {
	if cfg.Postgres.Kind != 0 && cfg.Postgres.Tag != "!!null" {
		return fmt.Errorf("postgres is unavailable in the nosy build; use the full iron-proxy build")
	}
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if strings.HasPrefix(key, "IRON_PROXY_PG_") {
			return fmt.Errorf("%s is unavailable in the nosy build; PostgreSQL requires the full iron-proxy build", key)
		}
	}
	return nil
}
