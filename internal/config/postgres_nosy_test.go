//go:build nosy

package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestNosyRejectsPostgresConfig(t *testing.T) {
	cases := []struct {
		name, yaml string
		reject     bool
	}{
		{"absent", "proxy: {}", false},
		{"null", "postgres: null", false},
		{"empty block", "postgres: {}", true},
		{"listener", "postgres:\n  listen: 127.0.0.1:5432", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var cfg Config
			require.NoError(t, yaml.Unmarshal([]byte(tc.yaml), &cfg))
			err := validateBuildConfig(&cfg)
			if tc.reject {
				require.ErrorContains(t, err, "postgres is unavailable")
			} else {
				require.NoError(t, err)
			}
			path := filepath.Join(t.TempDir(), "config.yaml")
			require.NoError(t, os.WriteFile(path, []byte(tc.yaml), 0600))
			_, err = LoadConfig(path)
			if tc.reject {
				require.ErrorContains(t, err, "postgres is unavailable")
			} else {
				require.NoError(t, err)
			}
		})
	}
}
func TestNosyRejectsPostgresEnvironmentWithoutLeakingValues(t *testing.T) {
	for _, key := range []string{"IRON_PROXY_PG_LISTEN", "IRON_PROXY_PG_CLIENT_USER", "IRON_PROXY_PG_CLIENT_PASSWORD"} {
		t.Run(key, func(t *testing.T) {
			t.Setenv(key, "private-value-must-not-appear")
			_, err := LoadConfig("")
			require.ErrorContains(t, err, key+" is unavailable")
			require.NotContains(t, err.Error(), "private-value-must-not-appear")
		})
	}
}
