//go:build !nosy

package config

import (
	"encoding/json"
	"fmt"
	"github.com/ironsh/iron-proxy/internal/postgres"
	"github.com/ironsh/iron-proxy/internal/transform/secrets"
	"log/slog"
)

func validateBuildConfig(*Config) error { return nil }

// PostgresSyncEntry is one control-plane-synced postgres upstream, mapped to a
// single route under the managed listener. The DSN, optional role, and routing
// database come from the control plane; the per-route client credentials are
// supplied separately via environment variables keyed off ForeignID (see the
// managed-mode env convention in cmd/iron-proxy).
type PostgresSyncEntry struct {
	ForeignID string
	// Database is the routing key clients use to reach this upstream. Required:
	// it must equal the database the DSN connects to, so the control plane must
	// supply it explicitly.
	Database string
	DSN      secrets.Source
	Role     string
	// Settings are the pinned session variables the proxy SETs at session start
	// for this upstream. Optional; nil when the control plane sends none.
	Settings []postgres.Setting
}

// PostgresFromSync parses the top-level postgres: array from the control
// plane's sync payload into PostgresSyncEntry values, building each entry's DSN
// source through the same secrets.BuildSource path the YAML config uses. A nil
// or JSON-null payload returns (nil, nil); individual null array elements are
// skipped. Source construction is lazy, so an entry whose DSN points at an
// unset env var still parses without error here.
func PostgresFromSync(raw json.RawMessage, logger *slog.Logger) ([]PostgresSyncEntry, error) {
	if !isNonNullJSON(raw) {
		return nil, nil
	}

	var rawEntries []json.RawMessage
	if err := json.Unmarshal(raw, &rawEntries); err != nil {
		return nil, fmt.Errorf("parsing postgres: %w", err)
	}

	entries := make([]PostgresSyncEntry, 0, len(rawEntries))
	for i, re := range rawEntries {
		if !isNonNullJSON(re) {
			continue
		}
		var e struct {
			ForeignID string          `json:"foreign_id"`
			Database  string          `json:"database"`
			DSN       json.RawMessage `json:"dsn"`
			Role      string          `json:"role"`
			Settings  []struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			} `json:"settings"`
		}
		if err := json.Unmarshal(re, &e); err != nil {
			return nil, fmt.Errorf("parsing postgres[%d]: %w", i, err)
		}
		if e.ForeignID == "" {
			return nil, fmt.Errorf("postgres[%d]: foreign_id is required", i)
		}
		if !isNonNullJSON(e.DSN) {
			return nil, fmt.Errorf("postgres[%q]: dsn is required", e.ForeignID)
		}
		if e.Database == "" {
			return nil, fmt.Errorf("postgres[%q]: database is required", e.ForeignID)
		}
		node, err := yamlNodeFromRawJSON(e.DSN)
		if err != nil {
			return nil, fmt.Errorf("postgres[%q]: parsing dsn: %w", e.ForeignID, err)
		}
		src, err := secrets.BuildSource(node, logger)
		if err != nil {
			return nil, fmt.Errorf("postgres[%q]: building dsn source: %w", e.ForeignID, err)
		}
		var settings []postgres.Setting
		if len(e.Settings) > 0 {
			settings = make([]postgres.Setting, len(e.Settings))
			for j, s := range e.Settings {
				settings[j] = postgres.Setting{Name: s.Name, Value: s.Value}
			}
		}
		entries = append(entries, PostgresSyncEntry{
			ForeignID: e.ForeignID,
			Database:  e.Database,
			DSN:       src,
			Role:      e.Role,
			Settings:  settings,
		})
	}
	return entries, nil
}
