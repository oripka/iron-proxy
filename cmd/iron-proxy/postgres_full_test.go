//go:build !nosy

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/ironsh/iron-proxy/internal/postgres"
	"github.com/ironsh/iron-proxy/internal/transform/secrets"
	"github.com/stretchr/testify/require"
	"log/slog"
	"testing"
)

// staticSource is a no-op secrets.Source for building local test listeners.
type staticSource struct{ name, value string }

func (s staticSource) Name() string                        { return s.name }
func (s staticSource) Get(context.Context) (string, error) { return s.value, nil }

func localListener(t *testing.T, database string) *postgres.Listener {
	t.Helper()
	u, err := postgres.NewManagedUpstream(database, staticSource{name: "local", value: "host=local"}, "", nil)
	require.NoError(t, err)
	l, err := postgres.NewListener("127.0.0.1:0", "u", "p", []*postgres.Upstream{u})
	require.NoError(t, err)
	return l
}

// pgListenerEnv is the env set needed to build a managed listener from sync when
// there is no local YAML listener: bind address plus the shared client credential.
func pgListenerEnv() map[string]string {
	return map[string]string{
		"IRON_PROXY_PG_LISTEN":          "127.0.0.1:0",
		"IRON_PROXY_PG_CLIENT_USER":     "app",
		"IRON_PROXY_PG_CLIENT_PASSWORD": "s3cret",
	}
}

func TestPostgresListenerFromSync_Basic(t *testing.T) {
	raw := json.RawMessage(`[{"id":"pgs_1","foreign_id":"pg-analytics","database":"analytics","dsn":{"type":"env","var":"PG_ANALYTICS_DSN"},"role":"readonly"}]`)

	listener, ok := postgresListenerFromSync(nil, mapEnv(pgListenerEnv()), discardLogger(), raw)
	require.True(t, ok)
	require.NotNil(t, listener)
	require.Equal(t, "127.0.0.1:0", listener.Listen())
	// The client credential is the single shared one from the environment.
	require.True(t, listener.VerifyClient("app", "s3cret"))

	// Routed by the synced database, which is independent of the foreign_id.
	upstream := listener.Upstream("analytics")
	require.NotNil(t, upstream)
	require.Nil(t, listener.Upstream("pg-analytics"))
	require.Equal(t, "readonly", upstream.Role())
}

func TestPostgresListenerFromSync_NoRole(t *testing.T) {
	raw := json.RawMessage(`[{"id":"pgs_1","foreign_id":"pgmain","database":"maindb","dsn":{"type":"env","var":"PG_DSN"}}]`)

	listener, ok := postgresListenerFromSync(nil, mapEnv(pgListenerEnv()), discardLogger(), raw)
	require.True(t, ok)
	require.NotNil(t, listener)
	require.Empty(t, listener.Upstream("maindb").Role(), "absent role must be a no-op")
}

func TestPostgresListenerFromSync_MissingClientEnvDropsUpstreams(t *testing.T) {
	raw := json.RawMessage(`[{"id":"pgs_1","foreign_id":"pg-analytics","database":"analytics","dsn":{"type":"env","var":"PG_DSN"}}]`)
	logBuf := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(logBuf, nil))

	// Bind address set but the shared client credential env is missing: with no
	// local listener to source it from, no listener is built.
	getenv := mapEnv(map[string]string{"IRON_PROXY_PG_LISTEN": "127.0.0.1:0"})
	listener, ok := postgresListenerFromSync(nil, getenv, logger, raw)
	require.True(t, ok)
	require.Nil(t, listener)
	require.Contains(t, logBuf.String(), "listener env not fully set")
}

func TestPostgresListenerFromSync_NoListenEnvDropsUpstreams(t *testing.T) {
	raw := json.RawMessage(`[{"id":"pgs_1","foreign_id":"pg-analytics","database":"analytics","dsn":{"type":"env","var":"PG_DSN"}}]`)
	logBuf := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(logBuf, nil))

	// No local listener and no env at all: nothing to bind, upstreams dropped.
	listener, ok := postgresListenerFromSync(nil, mapEnv(nil), logger, raw)
	require.True(t, ok)
	require.Nil(t, listener)
	require.Contains(t, logBuf.String(), "listener env not fully set")
}

func TestPostgresListenerFromSync_MergesLocalAndSynced(t *testing.T) {
	local := localListener(t, "appdb")
	raw := json.RawMessage(`[{"id":"pgs_1","foreign_id":"pg-analytics","database":"analytics","dsn":{"type":"env","var":"PG_DSN"}}]`)
	// No env: the bind address and client credential come from the local listener.
	listener, ok := postgresListenerFromSync(local, mapEnv(nil), discardLogger(), raw)
	require.True(t, ok)
	require.NotNil(t, listener)
	require.Equal(t, local.Listen(), listener.Listen())
	require.True(t, listener.VerifyClient("u", "p"), "local client credential carried over")
	require.NotNil(t, listener.Upstream("appdb"), "local upstream preserved")
	require.NotNil(t, listener.Upstream("analytics"), "synced upstream layered on")
}

func TestPostgresListenerFromSync_LocalWinsOnCollision(t *testing.T) {
	local := localListener(t, "shared")
	raw := json.RawMessage(`[{"id":"pgs_1","foreign_id":"pg-analytics","database":"shared","dsn":{"type":"env","var":"PG_DSN"}}]`)
	logBuf := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(logBuf, nil))

	listener, ok := postgresListenerFromSync(local, mapEnv(nil), logger, raw)
	require.True(t, ok)
	require.NotNil(t, listener)
	require.Len(t, listener.Upstreams(), 1, "the synced upstream colliding with the local one is dropped")
	require.Contains(t, logBuf.String(), "duplicate database")
}

func TestPostgresListenerFromSync_DuplicateSyncedDatabaseDropped(t *testing.T) {
	raw := json.RawMessage(`[
		{"id":"pgs_1","foreign_id":"a","database":"shared","dsn":{"type":"env","var":"PG_DSN"}},
		{"id":"pgs_2","foreign_id":"b","database":"shared","dsn":{"type":"env","var":"PG_DSN"}}
	]`)
	logBuf := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(logBuf, nil))

	listener, ok := postgresListenerFromSync(nil, mapEnv(pgListenerEnv()), logger, raw)
	require.True(t, ok)
	require.NotNil(t, listener)
	require.Len(t, listener.Upstreams(), 1)
	require.NotNil(t, listener.Upstream("shared"))
	require.Contains(t, logBuf.String(), "duplicate database")
}

func TestPostgresListenerFromSync_InvalidPayload(t *testing.T) {
	logBuf := &bytes.Buffer{}
	logger := slog.New(slog.NewTextHandler(logBuf, nil))

	listener, ok := postgresListenerFromSync(nil, mapEnv(nil), logger, json.RawMessage(`{not an array`))
	require.False(t, ok, "invalid payload must signal keep-current")
	require.Nil(t, listener)
	require.Contains(t, logBuf.String(), "rejecting invalid postgres config")
}

func TestPostgresListenerFromSync_NullPayloadKeepsLocal(t *testing.T) {
	local := localListener(t, "appdb")

	listener, ok := postgresListenerFromSync(local, mapEnv(nil), discardLogger(), json.RawMessage("null"))
	require.True(t, ok)
	require.NotNil(t, listener)
	require.Equal(t, local.Listen(), listener.Listen())
	require.NotNil(t, listener.Upstream("appdb"))
}

func TestApplyPostgresSync_ReloadsListener(t *testing.T) {
	mgr := postgres.NewManager(discardLogger())
	t.Cleanup(func() { _ = mgr.Shutdown(context.Background()) })

	raw := json.RawMessage(`[{"id":"pgs_1","foreign_id":"pg-analytics","database":"analytics","dsn":{"type":"env","var":"PG_DSN"}}]`)

	require.NoError(t, applyPostgresSync(context.Background(), mgr, nil, mapEnv(pgListenerEnv()), discardLogger(), raw))
	require.True(t, mgr.Running())
}

var _ secrets.Source = staticSource{}
