//go:build nosy

package main

import (
	"context"
	"encoding/json"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
	"testing"
)

func TestNosyRejectsPostgresSync(t *testing.T) {
	cases := []struct {
		name, raw string
		reject    bool
	}{
		{"omitted", "", false}, {"null", " null ", false},
		{"empty array", "[]", true}, {"configured", `[{"database":"private-value"}]`, true}, {"malformed", "{", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := json.RawMessage(tc.raw)
			err := validatePostgresSync(raw)
			if tc.reject {
				require.ErrorContains(t, err, "postgres sync is unavailable")
				require.NotContains(t, err.Error(), "private-value")
			} else {
				require.NoError(t, err)
			}
			_, ok := postgresListenerFromSync(nil, mapEnv(nil), discardLogger(), raw)
			require.Equal(t, !tc.reject, ok)
			err = applyPostgresSync(context.Background(), newPostgresManager(discardLogger()), nil, mapEnv(nil), discardLogger(), raw)
			if tc.reject {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
func TestNosyRejectsPostgresListener(t *testing.T) {
	_, err := loadPostgresFromNode(yaml.Node{Kind: yaml.MappingNode}, discardLogger())
	require.ErrorContains(t, err, "postgres is unavailable")
}
func TestNosyBuildCapabilities(t *testing.T) {
	info := buildInfo()
	require.Equal(t, "nosy", info.BuildFlavor)
	require.False(t, info.Features.Postgres)
	require.False(t, info.Features.ExternalSecretSources)
	require.False(t, info.Features.RemoteConfigS3)
}
