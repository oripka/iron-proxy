//go:build nosy

package config

import (
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"testing"
)

func TestNosyConfigurationSources(t *testing.T) {
	t.Run("remote refused", func(t *testing.T) {
		_, err := parseFileOrS3("s3://unused-bucket/config.yaml")
		require.ErrorContains(t, err, "S3 configuration sources are not supported")
	})
	t.Run("local retained", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config.yaml")
		require.NoError(t, os.WriteFile(path, []byte("proxy:\n  http_listen: 127.0.0.1:8123\n"), 0600))
		_, err := parseFileOrS3(path)
		require.NoError(t, err)
	})
}
