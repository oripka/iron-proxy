//go:build nosy

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"gopkg.in/yaml.v3"
)

// These empty lifecycle types keep the shared HTTP startup and reload path
// identical while ensuring the PostgreSQL package is absent from this binary.
// Every config entry point rejects PostgreSQL before reaching these methods.
type postgresListener struct{}
type postgresManager struct{}

func newPostgresManager(*slog.Logger) *postgresManager             { return &postgresManager{} }
func (*postgresManager) Start(*postgresListener, chan<- error)     {}
func (*postgresManager) Reload(context.Context, *postgresListener) {}
func (*postgresManager) Shutdown(context.Context) error            { return nil }
func loadPostgresFromNode(node yaml.Node, _ *slog.Logger) (*postgresListener, error) {
	if node.Kind != 0 && node.Tag != "!!null" {
		return nil, fmt.Errorf("postgres is unavailable in the nosy build")
	}
	return nil, nil
}
func validatePostgresSync(raw json.RawMessage) error {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return nil
	}
	return fmt.Errorf("postgres sync is unavailable in the nosy build; use the full iron-proxy build")
}
func postgresListenerFromSync(_ *postgresListener, _ func(string) string, logger *slog.Logger, raw json.RawMessage) (*postgresListener, bool) {
	if err := validatePostgresSync(raw); err != nil {
		logger.Error("rejecting unsupported postgres config from sync", slog.String("error", err.Error()))
		return nil, false
	}
	return nil, true
}
func applyPostgresSync(_ context.Context, _ *postgresManager, _ *postgresListener, _ func(string) string, _ *slog.Logger, raw json.RawMessage) error {
	return validatePostgresSync(raw)
}
