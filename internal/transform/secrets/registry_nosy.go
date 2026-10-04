//go:build nosy

package secrets

import (
	"fmt"
	"gopkg.in/yaml.v3"
	"log/slog"
)

// The desktop build keeps local and control-plane sources without linking
// cloud vault SDKs. Reject excluded sources during configuration, even when
// the request-level secret is optional.
func defaultRegistry(logger *slog.Logger) sourceBuilderRegistry {
	return sourceBuilderRegistry{
		"env":               newEnvBuilder(logger),
		"file":              newFileBuilder(logger),
		"control_plane":     newControlPlaneBuilder(logger),
		"aws_sm":            unsupportedSource("aws_sm"),
		"aws_ssm":           unsupportedSource("aws_ssm"),
		"1password":         unsupportedSource("1password"),
		"1password_connect": unsupportedSource("1password_connect"),
	}
}

type unsupportedSource string

func (s unsupportedSource) Build(_ yaml.Node) (secretSource, error) {
	return nil, fmt.Errorf("secret source %q is not supported by the Nosy proxy build", s)
}
