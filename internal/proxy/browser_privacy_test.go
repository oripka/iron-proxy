package proxy

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type privacyLog struct{ reports chan []byte }

func (l *privacyLog) Write(data []byte) (int, error) {
	if strings.Contains(string(data), `"msg":"browser_privacy"`) {
		l.reports <- append([]byte(nil), data...)
	}
	return len(data), nil
}

func TestBrowserPrivacyNativeTLSReport(t *testing.T) {
	p, addr, target, pool, _ := nativeFixture(t, false)
	logs := &privacyLog{reports: make(chan []byte, 4)}
	p.logger = slog.New(slog.NewJSONHandler(logs, nil))
	p.EnableBrowserPrivacy()
	conn, err := nativeConnect(t, addr, target, strings.Repeat("b", 64), pool)
	require.NoError(t, err)
	// Native admission is pinned to localhost. The vendor Host cannot change it.
	_, err = fmt.Fprint(conn, "GET /?page=https%3A%2F%2Fprivate.example%2F HTTP/1.1\r\nHost: telemetry.google.com\r\nConnection: close\r\n\r\n")
	require.NoError(t, err)
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	require.NoError(t, err)
	require.NoError(t, response.Body.Close())
	require.NoError(t, conn.Close())
	select {
	case data := <-logs.reports:
		var report struct {
			Msg     string         `json:"msg"`
			Flow    string         `json:"flow_id"`
			Request string         `json:"request_id"`
			Summary privacySummary `json:"summary"`
		}
		require.NoError(t, json.Unmarshal(data, &report))
		require.Equal(t, "provider:flow-test", report.Flow)
		require.Equal(t, "provider:flow-test:1", report.Request)
		require.Contains(t, report.Summary.Categories, "url-value")
		require.NotContains(t, string(data), "private.example")
	case <-time.After(time.Second):
		t.Fatal("missing native privacy summary")
	}
}

func TestBrowserPrivacyBoundedOutboundObserver(t *testing.T) {
	cases := []struct {
		name, body, media, encoding, coverage string
		categories                            []string
		chunked                               bool
	}{
		{"json", `{"page":"https://private.example/secret","email":"person@example.com","user_id":123}`, "application/json", "", "supported-body", []string{"email-field", "email-value", "identifier-field", "url-value"}, false},
		{"form", "q=private+search&device_id=123", "application/x-www-form-urlencoded", "", "supported-body", []string{"identifier-field", "search-field"}, false},
		{"compressed", "compressed bytes", "application/json", "gzip", "unsupported-body", []string{}, false},
		{"protobuf", "binary", "application/x-protobuf", "", "unsupported-body", []string{}, false},
		{"multipart", "file upload", "multipart/form-data; boundary=x", "", "unsupported-body", []string{}, false},
		{"malformed", "{", "application/json", "", "unparseable-body", []string{}, false},
		{"large", strings.Repeat("x", privacyLimit+1), "application/json", "", "body-too-large", []string{}, false},
		{"chunked-large", strings.Repeat("x", privacyLimit+1), "application/json", "", "body-too-large", []string{}, true},
		{"chunked", `{"email":"person@example.com"}`, "application/json", "", "supported-body", []string{"email-field", "email-value"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "https://telemetry.google.com/report", strings.NewReader(tc.body))
			r.Header.Set("Content-Type", tc.media)
			r.Header.Set("Content-Encoding", tc.encoding)
			if tc.chunked {
				r.ContentLength = -1
			}
			finish := observePrivacy(r)
			forwarded, err := io.ReadAll(r.Body)
			require.NoError(t, err)
			require.NoError(t, r.Body.Close())
			require.Equal(t, tc.body, string(forwarded), "observation must not change upload bytes")
			summary := finish()
			require.Equal(t, tc.coverage, summary.Coverage)
			require.ElementsMatch(t, tc.categories, summary.Categories)
			encoded, err := json.Marshal(summary)
			require.NoError(t, err)
			require.NotContains(t, string(encoded), "person@example.com")
			require.NotContains(t, string(encoded), "private.example")
			if body, ok := r.Body.(*privacyBody); ok {
				require.Empty(t, body.data)
			}
		})
	}
}

func TestBrowserPrivacyQueryAndPartialCoverage(t *testing.T) {
	r := httptest.NewRequest("POST", "https://google.com/?page=https%3A%2F%2Fprivate.example%2F&email=person%40example.com", strings.NewReader(`{"q":"secret"}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Referer", "https://private.example/")
	finish := observePrivacy(r)
	summary := finish() // A rejected/unconsumed body must not be called inspected.
	require.Equal(t, "body-not-consumed", summary.Coverage)
	require.ElementsMatch(t, []string{"url-value", "email-value", "email-field", "referrer-header"}, summary.Categories)
	forwarded, err := io.ReadAll(r.Body)
	require.NoError(t, err)
	require.NoError(t, r.Body.Close())
	require.Equal(t, `{"q":"secret"}`, string(forwarded))
	require.Empty(t, r.Body.(*privacyBody).data, "late transport reads must not retain data after report")
	for _, host := range []string{"google.com.evil.example", "notgoogle.com", "example.org"} {
		require.False(t, privacyVendor(host))
	}
	require.True(t, privacyVendor("Telemetry.Google.Com."))
}

func TestBrowserPrivacyReleasesCaptureOnUploadCompletion(t *testing.T) {
	r := httptest.NewRequest("POST", "https://google.com/", strings.NewReader(`{"q":"private query"}`))
	r.Header.Set("Content-Type", "application/json")
	finish := observePrivacy(r)
	body := r.Body.(*privacyBody)
	var summary privacySummary
	var once sync.Once
	body.onComplete = func() { once.Do(func() { summary = finish() }) }
	forwarded, err := io.ReadAll(r.Body)
	require.NoError(t, err)
	require.NoError(t, r.Body.Close())
	require.Equal(t, `{"q":"private query"}`, string(forwarded))
	require.Equal(t, "supported-body", summary.Coverage)
	require.Contains(t, summary.Categories, "search-field")
	require.Empty(t, body.data, "capture must be released before any response is read")
}
