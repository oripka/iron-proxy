//go:build !nosy

package config

import (
	"context"
	"encoding/json"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestPostgresFromSync_NilAndNull(t *testing.T) {
	entries, err := PostgresFromSync(nil, syncTestLogger())
	require.NoError(t, err)
	require.Empty(t, entries)

	entries, err = PostgresFromSync(json.RawMessage("null"), syncTestLogger())
	require.NoError(t, err)
	require.Empty(t, entries)
}

func TestPostgresFromSync_ParsesEntries(t *testing.T) {
	t.Setenv("PG_ANALYTICS_DSN", "host=analytics")
	t.Setenv("PG_MAIN_DSN", "host=main")

	raw := json.RawMessage(`[
		{"id":"pgs_1","foreign_id":"pg-analytics","database":"analytics","dsn":{"type":"env","var":"PG_ANALYTICS_DSN"},"role":"readonly","settings":[{"name":"app.tenant","value":"centaur"},{"name":"app.region","value":"us"}]},
		{"id":"pgs_2","foreign_id":"pg-main","database":"maindb","dsn":{"type":"env","var":"PG_MAIN_DSN"}}
	]`)

	entries, err := PostgresFromSync(raw, syncTestLogger())
	require.NoError(t, err)
	require.Len(t, entries, 2)

	require.Equal(t, "pg-analytics", entries[0].ForeignID)
	require.Equal(t, "analytics", entries[0].Database)
	require.Equal(t, "readonly", entries[0].Role)
	require.NotNil(t, entries[0].DSN)
	got, err := entries[0].DSN.Get(context.Background())
	require.NoError(t, err)
	require.Equal(t, "host=analytics", got)
	require.Len(t, entries[0].Settings, 2)
	require.Equal(t, "app.tenant", entries[0].Settings[0].Name)
	require.Equal(t, "centaur", entries[0].Settings[0].Value)
	require.Equal(t, "app.region", entries[0].Settings[1].Name)

	require.Equal(t, "pg-main", entries[1].ForeignID)
	require.Equal(t, "maindb", entries[1].Database)
	require.Empty(t, entries[1].Role)
	require.Empty(t, entries[1].Settings)
}

func TestPostgresFromSync_DatabaseDistinctFromForeignID(t *testing.T) {
	t.Setenv("PG_DSN", "host=x")
	raw := json.RawMessage(`[{"id":"pgs_1","foreign_id":"pg-analytics","database":"analytics","dsn":{"type":"env","var":"PG_DSN"}}]`)

	entries, err := PostgresFromSync(raw, syncTestLogger())
	require.NoError(t, err)
	require.Len(t, entries, 1)
	require.Equal(t, "pg-analytics", entries[0].ForeignID)
	require.Equal(t, "analytics", entries[0].Database, "database is the routing key, independent of foreign_id")
}

func TestPostgresFromSync_MissingDatabase(t *testing.T) {
	raw := json.RawMessage(`[{"id":"pgs_1","foreign_id":"pg-x","dsn":{"type":"env","var":"PG_DSN"}}]`)
	_, err := PostgresFromSync(raw, syncTestLogger())
	require.ErrorContains(t, err, "database is required")
}

func TestPostgresFromSync_SkipsNullElements(t *testing.T) {
	t.Setenv("PG_DSN", "host=x")
	raw := json.RawMessage(`[null,{"id":"pgs_1","foreign_id":"pg-x","database":"xdb","dsn":{"type":"env","var":"PG_DSN"}},null]`)

	entries, err := PostgresFromSync(raw, syncTestLogger())
	require.NoError(t, err)
	require.Len(t, entries, 1)
	require.Equal(t, "pg-x", entries[0].ForeignID)
}

func TestPostgresFromSync_MissingForeignID(t *testing.T) {
	raw := json.RawMessage(`[{"id":"pgs_1","dsn":{"type":"env","var":"PG_DSN"}}]`)
	_, err := PostgresFromSync(raw, syncTestLogger())
	require.ErrorContains(t, err, "foreign_id is required")
}

func TestPostgresFromSync_MissingDSN(t *testing.T) {
	raw := json.RawMessage(`[{"id":"pgs_1","foreign_id":"pg-x"}]`)
	_, err := PostgresFromSync(raw, syncTestLogger())
	require.ErrorContains(t, err, "dsn is required")
}

func TestPostgresFromSync_UnknownSourceType(t *testing.T) {
	raw := json.RawMessage(`[{"id":"pgs_1","foreign_id":"pg-x","database":"xdb","dsn":{"type":"bogus"}}]`)
	_, err := PostgresFromSync(raw, syncTestLogger())
	require.ErrorContains(t, err, "building dsn source")
}

func TestPostgresFromSync_InvalidJSON(t *testing.T) {
	_, err := PostgresFromSync(json.RawMessage(`{not an array`), syncTestLogger())
	require.ErrorContains(t, err, "parsing postgres")
}
