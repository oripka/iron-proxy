//go:build nosy

package secrets

import (
	"context"
	"log/slog"
	"net/http/httptest"
	"testing"

	"github.com/ironsh/iron-proxy/internal/hostmatch"
	"github.com/ironsh/iron-proxy/internal/transform"
	"github.com/stretchr/testify/require"
)

func TestNosyExcludedSourcesRejectConfiguration(t *testing.T) {
	cases := []string{"1password", "1password_connect", "aws_sm", "aws_ssm"}
	for _, sourceType := range cases {
		t.Run(sourceType, func(t *testing.T) {
			node := yamlNode(t, map[string]string{"type": sourceType})
			src, err := BuildSource(node, slog.Default())
			require.ErrorContains(t, err, "not supported by the Nosy proxy build")
			require.Nil(t, src)
			// Optional injection must not silently accept a disabled backend.
			_, err = newFromConfig(secretsConfig{Secrets: []secretEntry{{
				Source: node,
				Inject: &injectConfig{Header: "Authorization", Require: false},
				Rules:  []hostmatch.RuleConfig{{Host: "api.example.com"}},
			}}}, defaultRegistry(slog.Default()))
			require.ErrorContains(t, err, "not supported by the Nosy proxy build")
		})
	}
}

func TestNosyEnvironmentInjectionStaysHostScoped(t *testing.T) {
	t.Setenv("NOSY_TEST_SECRET", "private-secret")
	s, err := newFromConfig(secretsConfig{Secrets: []secretEntry{{
		Source: yamlNode(t, map[string]string{"type": "env", "var": "NOSY_TEST_SECRET"}),
		Inject: &injectConfig{Header: "Authorization", Require: true},
		Rules:  []hostmatch.RuleConfig{{Host: "api.example.com"}},
	}}}, defaultRegistry(slog.Default()))
	require.NoError(t, err)
	cases := []struct{ host, want string }{
		{"api.example.com", "private-secret"},
		{"other.example.com", ""},
	}
	for _, tc := range cases {
		t.Run(tc.host, func(t *testing.T) {
			req := httptest.NewRequest("GET", "https://"+tc.host+"/", nil)
			result, err := s.TransformRequest(context.Background(), &transform.TransformContext{}, req)
			require.NoError(t, err)
			require.Equal(t, transform.ActionContinue, result.Action)
			require.Equal(t, tc.want, req.Header.Get("Authorization"))
		})
	}
}
