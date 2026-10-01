package proxy

// This observer never buffers forwarding or reads responses. Only fixed category
// names leave the scanner; URLs, field names, credentials and values never do.
import (
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"net/mail"
	"net/url"
	"sort"
	"strings"
	"sync"
)

const privacyLimit = 64 * 1024

type privacySummary struct {
	Categories []string `json:"categories"`
	Coverage   string   `json:"coverage"`
}

type privacyBody struct {
	onComplete func()
	expected   int64
	io.ReadCloser
	mu        sync.Mutex
	data      []byte
	complete  bool
	oversized bool
	closed    bool
}

func (b *privacyBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	b.mu.Lock()
	if !b.closed && !b.oversized {
		if len(b.data)+n > privacyLimit {
			b.data = nil
			b.oversized = true
		} else {
			b.data = append(b.data, p[:n]...)
		}
	}
	if err == io.EOF || (b.expected >= 0 && int64(len(b.data)) == b.expected) {
		b.complete = true
	}
	complete := b.complete
	b.mu.Unlock()
	// Emit and release captured bytes as soon as the outgoing body is consumed,
	// even if the response is a long-lived download. Never wait for a response.
	if complete && b.onComplete != nil {
		b.onComplete()
	}
	return n, err
}

// Called once before serving; immutable for the listener's lifetime.
func (p *Proxy) EnableBrowserPrivacy() { p.browserPrivacy = true }

func privacyVendor(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	for _, root := range []string{"google.com", "googleapis.com", "gstatic.com", "googleusercontent.com", "mozilla.org", "mozilla.com", "mozilla.net", "firefox.com", "apple.com", "icloud.com", "microsoft.com", "msedge.net", "bing.com", "brave.com"} {
		if host == root || strings.HasSuffix(host, "."+root) {
			return true
		}
	}
	return false
}

func observePrivacy(r *http.Request) func() privacySummary {
	categories := map[string]bool{}
	add := func(key, value string) {
		if value == "" {
			return
		}
		if u, err := url.Parse(value); err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Hostname() != "" {
			categories["url-value"] = true
		}
		if strings.Contains(value, "@") {
			if a, err := mail.ParseAddress(value); err == nil && a.Address == value {
				categories["email-value"] = true
			}
		}
		switch strings.ToLower(key) {
		case "email", "email_address":
			categories["email-field"] = true
		case "query", "search", "search_terms", "q":
			categories["search-field"] = true
		case "user_id", "userid", "account_id", "client_id", "device_id", "installation_id":
			categories["identifier-field"] = true
		case "phone", "phone_number", "address", "first_name", "last_name", "full_name":
			categories["personal-field"] = true
		}
	}
	form := func(text string) bool {
		if strings.Count(text, "&") >= 1024 {
			return false
		}
		values, err := url.ParseQuery(text)
		if err != nil {
			return false
		}
		for key, list := range values {
			for _, value := range list {
				add(key, value)
			}
		}
		return true
	}
	queryComplete := len(r.URL.RawQuery) <= privacyLimit
	if queryComplete {
		queryComplete = form(r.URL.RawQuery)
	}
	if ref := r.Header.Get("Referer"); len(ref) > 0 && len(ref) <= 8192 {
		categories["referrer-header"] = true
	}
	media, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	coverage := "no-body"
	var body *privacyBody
	if r.Body != nil && r.Body != http.NoBody {
		coverage = "unsupported-body"
		if r.ContentLength > privacyLimit {
			coverage = "body-too-large"
		} else if r.Header.Get("Content-Encoding") == "" && (media == "application/json" || media == "application/x-www-form-urlencoded") {
			body = &privacyBody{ReadCloser: r.Body, expected: r.ContentLength}
			r.Body = body
			coverage = "body-not-consumed"
		}
	}
	return func() privacySummary {
		if body != nil {
			body.mu.Lock()
			defer body.mu.Unlock()
			body.closed = true
			defer func() { clear(body.data); body.data = nil }()
			if body.oversized {
				coverage = "body-too-large"
			} else if body.complete {
				coverage = "supported-body"
				if media == "application/x-www-form-urlencoded" {
					if !form(string(body.data)) {
						coverage = "unparseable-body"
					}
				} else {
					var value any
					if json.Unmarshal(body.data, &value) != nil {
						coverage = "unparseable-body"
					} else {
						budget := 4096
						var walk func(string, any, int)
						walk = func(key string, v any, depth int) {
							budget--
							if budget < 0 || depth > 16 {
								coverage = "partial-body"
								return
							}
							switch v := v.(type) {
							case string:
								add(key, v)
							case float64:
								add(key, "number")
							case map[string]any:
								for k, child := range v {
									if budget < 0 {
										break
									}
									walk(k, child, depth+1)
								}
							case []any:
								for _, child := range v {
									if budget < 0 {
										break
									}
									walk(key, child, depth+1)
								}
							}
						}
						walk("", value, 0)
					}
				}
			}
		}
		if !queryComplete {
			coverage = "partial-query"
		}
		result := privacySummary{Categories: []string{}, Coverage: coverage}
		for category := range categories {
			result.Categories = append(result.Categories, category)
		}
		sort.Strings(result.Categories)
		return result
	}
}
