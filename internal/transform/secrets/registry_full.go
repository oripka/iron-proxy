//go:build !nosy

package secrets

import "log/slog"

// defaultRegistry returns the standard set of secret source builders. It is
// used by both the secrets transform's factory and by BuildSource so other
// transforms can compose the same sources.
func defaultRegistry(logger *slog.Logger) sourceBuilderRegistry {
	return sourceBuilderRegistry{
		"env":               newEnvBuilder(logger),
		"file":              newFileBuilder(logger),
		"control_plane":     newControlPlaneBuilder(logger),
		"aws_sm":            newAWSSMBuilder(logger),
		"aws_ssm":           newAWSSSMBuilder(logger),
		"1password":         newOPBuilder(logger),
		"1password_connect": newOPConnectBuilder(logger),
	}
}
