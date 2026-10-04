//go:build !nosy

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/ironsh/iron-proxy/internal/config"
	"github.com/ironsh/iron-proxy/internal/postgres"
	"log/slog"
)

type postgresListener = postgres.Listener
type postgresManager = postgres.Manager

var loadPostgresFromNode = postgres.LoadFromNode
var newPostgresManager = postgres.NewManager

func validatePostgresSync(json.RawMessage) error { return nil }

// Environment variables that configure the managed postgres listener when the
// proxy has no local YAML postgres block to source these from. They configure
// the single listener, not individual upstreams.
const (
	pgListenEnv         = "IRON_PROXY_PG_LISTEN"
	pgClientUserEnv     = "IRON_PROXY_PG_CLIENT_USER"
	pgClientPasswordEnv = "IRON_PROXY_PG_CLIENT_PASSWORD"
)

// postgresListenerFromSync builds the single postgres listener for managed mode.
// Each synced entry becomes an upstream keyed by its database, carrying the
// database, DSN, and role the control plane delivered.
//
// When a local YAML postgres block is present, the synced upstreams are layered
// onto it, reusing its bind address and client credential; a synced upstream
// whose database collides with a local one is dropped (logged). Otherwise the
// listener is built from the environment: IRON_PROXY_PG_LISTEN plus the shared
// IRON_PROXY_PG_CLIENT_USER / IRON_PROXY_PG_CLIENT_PASSWORD. When no bind address
// or client credential is available, or no upstreams resolve, no listener is
// returned. Returns ok=false only when the sync payload itself is invalid,
// signaling the caller to keep the current listener.
func postgresListenerFromSync(local *postgres.Listener, getenv func(string) string, logger *slog.Logger, raw json.RawMessage) (*postgres.Listener, bool) {
	entries, err := config.PostgresFromSync(raw, logger)
	if err != nil {
		logger.Error("rejecting invalid postgres config from sync, keeping current listener", slog.String("error", err.Error()))
		return nil, false
	}

	synced := make([]*postgres.Upstream, 0, len(entries))
	seen := make(map[string]bool, len(entries))
	for _, e := range entries {
		u, err := postgres.NewManagedUpstream(e.Database, e.DSN, e.Role, e.Settings)
		if err != nil {
			logger.Error("skipping synced postgres upstream: invalid upstream",
				slog.String("foreign_id", e.ForeignID),
				slog.String("error", err.Error()),
			)
			continue
		}
		if seen[u.Database()] {
			logger.Warn("skipping synced postgres upstream: duplicate database",
				slog.String("foreign_id", e.ForeignID),
				slog.String("database", u.Database()),
			)
			continue
		}
		seen[u.Database()] = true
		synced = append(synced, u)
	}

	// With a local listener, layer the synced upstreams on top, reusing its
	// address and client credential. Local wins on a database collision.
	if local != nil {
		merged, dropped := local.WithUpstreams(synced)
		for _, db := range dropped {
			logger.Warn("skipping synced postgres upstream: duplicate database",
				slog.String("database", db))
		}
		return merged, true
	}

	// No local listener: source the listener knobs from the environment.
	if len(synced) == 0 {
		return nil, true
	}
	listen := getenv(pgListenEnv)
	clientUser := getenv(pgClientUserEnv)
	clientPassword := getenv(pgClientPasswordEnv)
	if listen == "" || clientUser == "" || clientPassword == "" {
		logger.Info("skipping control-plane postgres upstreams: listener env not fully set",
			slog.Bool("has_listen", listen != ""),
			slog.Bool("has_client_user", clientUser != ""),
			slog.Bool("has_client_password", clientPassword != ""),
			slog.Int("upstream_count", len(synced)),
		)
		return nil, true
	}

	listener, err := postgres.NewListener(listen, clientUser, clientPassword, synced)
	if err != nil {
		logger.Error("skipping postgres listener: invalid listener", slog.String("error", err.Error()))
		return nil, true
	}
	return listener, true
}

// applyPostgresSync rebuilds the postgres listener from a sync payload and
// hot-reloads the manager. An invalid payload is logged and the running
// listener is preserved.
func applyPostgresSync(ctx context.Context, mgr *postgres.Manager, local *postgres.Listener, getenv func(string) string, logger *slog.Logger, raw json.RawMessage) error {
	listener, ok := postgresListenerFromSync(local, getenv, logger, raw)
	if !ok {
		return fmt.Errorf("postgres sync: invalid postgres config")
	}
	mgr.Reload(ctx, listener)
	logger.Info("postgres listener reloaded from sync", slog.Bool("running", listener != nil))
	return nil
}
