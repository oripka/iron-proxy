package secrets

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// yamlNode marshals v to YAML and returns the resulting yaml.Node.
func yamlNode(t *testing.T, v any) yaml.Node {
	t.Helper()
	data, err := yaml.Marshal(v)
	require.NoError(t, err)
	var node yaml.Node
	require.NoError(t, yaml.Unmarshal(data, &node))
	// yaml.Unmarshal wraps in a document node; return the first content node.
	return *node.Content[0]
}

// --- envBuilder tests ---

func TestEnvBuilder_HappyPath(t *testing.T) {
	r := &envBuilder{getenv: func(key string) string {
		if key == "MY_SECRET" {
			return "real-value"
		}
		return ""
	}, logger: slog.Default()}
	node := yamlNode(t, map[string]string{"type": "env", "var": "MY_SECRET"})
	result, err := r.Build(node)
	require.NoError(t, err)
	require.Equal(t, "MY_SECRET", result.Name())

	val, err := result.Get(context.Background())
	require.NoError(t, err)
	require.Equal(t, "real-value", val)
}

// --- fileBuilder tests ---

func TestFileBuilder_HappyPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret")
	require.NoError(t, os.WriteFile(path, []byte("real-file-value"), 0o400))

	r := newFileBuilder(slog.Default())
	node := yamlNode(t, map[string]string{"type": "file", "path": path})
	result, err := r.Build(node)
	require.NoError(t, err)
	require.Equal(t, path, result.Name())

	val, err := result.Get(context.Background())
	require.NoError(t, err)
	require.Equal(t, "real-file-value", val)
}

func TestFileBuilder_PreservesExactBytes(t *testing.T) {
	// The value is the exact file contents — no trimming — so the writer
	// controls trailing whitespace (matching k8s/docker file-mounted secrets).
	dir := t.TempDir()
	path := filepath.Join(dir, "secret")
	require.NoError(t, os.WriteFile(path, []byte("token-with-newline\n"), 0o400))

	r := newFileBuilder(slog.Default())
	node := yamlNode(t, map[string]string{"type": "file", "path": path})
	result, err := r.Build(node)
	require.NoError(t, err)

	val, err := result.Get(context.Background())
	require.NoError(t, err)
	require.Equal(t, "token-with-newline\n", val)
}

func TestFileBuilder_TTLRefreshSeesNewContents(t *testing.T) {
	// With a ttl set, a rotated file is picked up on cache expiry without a
	// pipeline rebuild. Rotation mirrors the integrator's atomic write-temp +
	// rename onto a read-only (0o400) secret file.
	dir := t.TempDir()
	path := filepath.Join(dir, "secret")
	writeAtomic := func(value string) {
		tmp := filepath.Join(dir, "secret.tmp")
		require.NoError(t, os.WriteFile(tmp, []byte(value), 0o400))
		require.NoError(t, os.Rename(tmp, path))
	}
	writeAtomic("v1")

	r := newFileBuilder(slog.Default())
	node := yamlNode(t, map[string]string{"type": "file", "path": path, "ttl": "10ms"})
	result, err := r.Build(node)
	require.NoError(t, err)

	val, err := result.Get(context.Background())
	require.NoError(t, err)
	require.Equal(t, "v1", val)

	writeAtomic("v2")
	require.Eventually(t, func() bool {
		v, err := result.Get(context.Background())
		return err == nil && v == "v2"
	}, time.Second, 5*time.Millisecond)
}

func TestFileBuilder_Errors(t *testing.T) {
	tests := []struct {
		name   string
		input  map[string]string
		errMsg string
		errAt  string
	}{
		{
			name:   "missing path field",
			input:  map[string]string{"type": "file"},
			errMsg: "\"path\" field",
			errAt:  "build",
		},
		{
			name:   "nonexistent file",
			input:  map[string]string{"type": "file", "path": "/nonexistent/secret/path"},
			errMsg: "reading secret file",
			errAt:  "fetch",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newFileBuilder(slog.Default())
			node := yamlNode(t, tt.input)
			result, err := r.Build(node)
			if tt.errAt == "build" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.errMsg)
				return
			}
			require.NoError(t, err)
			_, err = result.Get(context.Background())
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.errMsg)
		})
	}
}

func TestFileBuilder_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secret")
	require.NoError(t, os.WriteFile(path, []byte(""), 0o400))

	r := newFileBuilder(slog.Default())
	node := yamlNode(t, map[string]string{"type": "file", "path": path})
	result, err := r.Build(node)
	require.NoError(t, err)

	_, err = result.Get(context.Background())
	require.Error(t, err)
	require.Contains(t, err.Error(), "is empty")
}

func TestEnvBuilder_Errors(t *testing.T) {
	tests := []struct {
		name   string
		input  map[string]string
		errMsg string
		errAt  string
	}{
		{
			name:   "missing var field",
			input:  map[string]string{"type": "env"},
			errMsg: "\"var\" field",
			errAt:  "build",
		},
		{
			name:   "empty value",
			input:  map[string]string{"type": "env", "var": "EMPTY_VAR"},
			errMsg: "not set or empty",
			errAt:  "fetch",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &envBuilder{getenv: func(string) string { return "" }, logger: slog.Default()}
			node := yamlNode(t, tt.input)
			result, err := r.Build(node)
			if tt.errAt == "build" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.errMsg)
				return
			}
			require.NoError(t, err)
			_, err = result.Get(context.Background())
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.errMsg)
		})
	}
}

// --- extractJSONKey tests ---

func TestExtractJSONKey(t *testing.T) {
	tests := []struct {
		name   string
		json   string
		key    string
		want   string
		errMsg string
	}{
		{
			name: "valid",
			json: `{"key": "value", "other": "data"}`,
			key:  "key",
			want: "value",
		},
		{
			name:   "invalid JSON",
			json:   `not json`,
			key:    "key",
			errMsg: "not valid JSON",
		},
		{
			name:   "missing key",
			json:   `{"other": "value"}`,
			key:    "key",
			errMsg: "not found",
		},
		{
			name:   "non-string value",
			json:   `{"key": 42}`,
			key:    "key",
			errMsg: "not a string",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			val, err := extractJSONKey(tt.json, tt.key)
			if tt.errMsg != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.want, val)
			}
		})
	}
}

// --- json_key via resolveSource (available to every source type) ---

func TestResolveSource_JSONKey(t *testing.T) {
	const blob = `{"refresh_token": "rt-123", "client_id": "cid", "num": 42}`

	t.Run("extracts field from env source", func(t *testing.T) {
		reg := sourceBuilderRegistry{"env": &envBuilder{
			getenv: func(string) string { return blob },
			logger: slog.Default(),
		}}
		node := yamlNode(t, map[string]string{"type": "env", "var": "CRED", "json_key": "refresh_token"})
		src, err := resolveSource(reg, node)
		require.NoError(t, err)

		val, err := src.Get(context.Background())
		require.NoError(t, err)
		require.Equal(t, "rt-123", val)
	})

	t.Run("without json_key returns the raw value", func(t *testing.T) {
		reg := sourceBuilderRegistry{"env": &envBuilder{
			getenv: func(string) string { return blob },
			logger: slog.Default(),
		}}
		node := yamlNode(t, map[string]string{"type": "env", "var": "CRED"})
		src, err := resolveSource(reg, node)
		require.NoError(t, err)

		val, err := src.Get(context.Background())
		require.NoError(t, err)
		require.Equal(t, blob, val)
	})

	errCases := []struct {
		name   string
		value  string
		key    string
		errMsg string
	}{
		{name: "invalid JSON", value: "not-json", key: "refresh_token", errMsg: "not valid JSON"},
		{name: "key not found", value: blob, key: "missing", errMsg: "not found"},
		{name: "non-string value", value: blob, key: "num", errMsg: "not a string"},
	}
	for _, tc := range errCases {
		t.Run(tc.name, func(t *testing.T) {
			reg := sourceBuilderRegistry{"env": &envBuilder{
				getenv: func(string) string { return tc.value },
				logger: slog.Default(),
			}}
			node := yamlNode(t, map[string]string{"type": "env", "var": "CRED", "json_key": tc.key})
			src, err := resolveSource(reg, node)
			require.NoError(t, err)

			_, err = src.Get(context.Background())
			require.ErrorContains(t, err, tc.errMsg)
		})
	}
}

// --- cachedValue tests ---

func TestCachedValue_ServesStaleOnError(t *testing.T) {
	calls := 0
	cv := &cachedValue{
		name:       "test",
		logger:     slog.Default(),
		successTTL: time.Millisecond,
		failureTTL: time.Millisecond,
		now:        time.Now,
		fetch: func(_ context.Context) (string, error) {
			calls++
			return "", fmt.Errorf("aws error")
		},
		initialized: true,
		value:       "initial",
		expiresAt:   time.Now().Add(-time.Hour), // already expired
	}

	val, err := cv.Get(context.Background())
	require.NoError(t, err)
	require.Equal(t, "initial", val)
	require.Equal(t, 1, calls)
}

func TestCachedValue_LazyInitFetchOnFirstGet(t *testing.T) {
	calls := 0
	cv := &cachedValue{
		name:       "test",
		successTTL: time.Hour,
		failureTTL: time.Hour,
		now:        time.Now,
		fetch: func(_ context.Context) (string, error) {
			calls++
			return "value", nil
		},
	}
	val, err := cv.Get(context.Background())
	require.NoError(t, err)
	require.Equal(t, "value", val)
	require.Equal(t, 1, calls)

	// Second get within successTTL: cached, no fetch.
	val, err = cv.Get(context.Background())
	require.NoError(t, err)
	require.Equal(t, "value", val)
	require.Equal(t, 1, calls)
}

func TestCachedValue_FailureCachedForTTL(t *testing.T) {
	calls := 0
	now := time.Now()
	cv := &cachedValue{
		name:       "test",
		successTTL: 0,
		failureTTL: 30 * time.Second,
		now:        func() time.Time { return now },
		fetch: func(_ context.Context) (string, error) {
			calls++
			return "", fmt.Errorf("backend down")
		},
	}

	_, err := cv.Get(context.Background())
	require.Error(t, err)
	require.Equal(t, 1, calls)

	// Within failureTTL: cached error returned, no fetch.
	_, err = cv.Get(context.Background())
	require.Error(t, err)
	require.Equal(t, 1, calls)

	// Advance past failureTTL: fetch retried.
	now = now.Add(31 * time.Second)
	_, err = cv.Get(context.Background())
	require.Error(t, err)
	require.Equal(t, 2, calls)
}

func TestCachedValue_FailureRecovers(t *testing.T) {
	calls := 0
	now := time.Now()
	cv := &cachedValue{
		name:       "test",
		successTTL: 0, // cache forever after success
		failureTTL: 30 * time.Second,
		now:        func() time.Time { return now },
		fetch: func(_ context.Context) (string, error) {
			calls++
			if calls == 1 {
				return "", fmt.Errorf("transient error")
			}
			return "real-value", nil
		},
	}

	_, err := cv.Get(context.Background())
	require.Error(t, err)

	// Advance past failureTTL.
	now = now.Add(31 * time.Second)
	val, err := cv.Get(context.Background())
	require.NoError(t, err)
	require.Equal(t, "real-value", val)

	// Subsequent gets: cached, no further fetches.
	val, err = cv.Get(context.Background())
	require.NoError(t, err)
	require.Equal(t, "real-value", val)
	require.Equal(t, 2, calls)
}

func TestCachedValue_CallerContextCancellationDoesNotPropagate(t *testing.T) {
	cv := newLazyValue("test", 0, time.Minute, slog.Default(), func(ctx context.Context) (string, error) {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		return "value", nil
	})

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()

	val, err := cv.Get(cancelled)
	require.NoError(t, err)
	require.Equal(t, "value", val)
}

func TestCachedValue_ZeroSuccessTTLCachesForever(t *testing.T) {
	calls := 0
	cv := &cachedValue{
		name:       "test",
		successTTL: 0,
		failureTTL: time.Second,
		now:        time.Now,
		fetch: func(_ context.Context) (string, error) {
			calls++
			return "value", nil
		},
	}
	for range 5 {
		val, err := cv.Get(context.Background())
		require.NoError(t, err)
		require.Equal(t, "value", val)
	}
	require.Equal(t, 1, calls)
}

func TestParseTTL(t *testing.T) {
	d, err := parseTTL("")
	require.NoError(t, err)
	require.Equal(t, time.Duration(0), d)

	d, err = parseTTL("15m")
	require.NoError(t, err)
	require.Equal(t, 15*time.Minute, d)

	_, err = parseTTL("not-a-duration")
	require.Error(t, err)
}

func TestBuildLazySource_FailureTTLDefaults(t *testing.T) {
	// Empty failure_ttl falls back to defaultFailureTTL regardless of success TTL.
	result, err := buildLazySource("name", "1h", "", slog.Default(), func(context.Context) (string, error) {
		return "v", nil
	})
	require.NoError(t, err)
	require.NotNil(t, result)
}

func TestBuildLazySource_FailureTTLOverride(t *testing.T) {
	now := time.Now()
	calls := 0
	successTTL, err := parseTTL("1h")
	require.NoError(t, err)
	failTTL, err := parseTTL("5s")
	require.NoError(t, err)
	cv := &cachedValue{
		name:       "name",
		successTTL: successTTL,
		failureTTL: failTTL,
		now:        func() time.Time { return now },
		fetch: func(_ context.Context) (string, error) {
			calls++
			return "", fmt.Errorf("boom")
		},
	}
	_, err = cv.Get(context.Background())
	require.Error(t, err)

	// Within 5s the error is cached.
	now = now.Add(4 * time.Second)
	_, err = cv.Get(context.Background())
	require.Error(t, err)
	require.Equal(t, 1, calls)

	// After 5s, retry — even though successTTL is 1h.
	now = now.Add(2 * time.Second)
	_, err = cv.Get(context.Background())
	require.Error(t, err)
	require.Equal(t, 2, calls)
}

func TestBuildLazySource_InvalidFailureTTL(t *testing.T) {
	_, err := buildLazySource("name", "", "not-a-duration", slog.Default(), func(context.Context) (string, error) {
		return "v", nil
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "failure_ttl")
}

// Lazy-init tests: each builder's Build should not call the underlying client.

func TestEnvBuilder_BuildDoesNotReadEnv(t *testing.T) {
	calls := 0
	r := &envBuilder{getenv: func(_ string) string {
		calls++
		return "value"
	}, logger: slog.Default()}
	node := yamlNode(t, map[string]string{"type": "env", "var": "FOO"})
	result, err := r.Build(node)
	require.NoError(t, err)
	require.Equal(t, 0, calls, "Build must not call getenv")

	_, err = result.Get(context.Background())
	require.NoError(t, err)
	require.Equal(t, 1, calls)
}
