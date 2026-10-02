package proxy

import (
	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/require"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestNativeQUICSustainedLoad(t *testing.T) {
	if os.Getenv("NOSY_QUIC_LOAD") != "1" {
		t.Skip("explicit load run required")
	}
	_, addr, target, roots, _ := quicFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := io.Copy(w, r.Body)
		if err != nil {
			t.Errorf("echo: %v", err)
		}
	}))
	var requests, failures atomic.Int64
	var peak atomic.Uint64
	end := time.Now().Add(5 * time.Second)
	var workers sync.WaitGroup
	for i := 0; i < 4; i++ {
		client := quicClient(t, addr, target, strings.Repeat(string(rune('a'+i)), 64), roots, quic.Version1)
		workers.Add(1)
		go func() {
			defer workers.Done()
			for time.Now().Before(end) {
				response, err := client.Post("https://localhost/load", "application/octet-stream", strings.NewReader(strings.Repeat("x", 16384)))
				if err != nil {
					failures.Add(1)
					continue
				}
				n, err := io.Copy(io.Discard, response.Body)
				_ = response.Body.Close()
				if err != nil || response.StatusCode != 200 || n != 16384 {
					failures.Add(1)
				} else {
					requests.Add(1)
				}
			}
		}()
	}
	for time.Now().Before(end) {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		if m.HeapAlloc > peak.Load() {
			peak.Store(m.HeapAlloc)
		}
		time.Sleep(100 * time.Millisecond)
	}
	workers.Wait()
	require.Zero(t, failures.Load())
	require.Greater(t, requests.Load(), int64(100))
	require.Less(t, peak.Load(), uint64(128<<20))
	t.Logf("5s / 4 concurrent streams: requests=%d failures=%d sampled_heap_peak=%d bytes", requests.Load(), failures.Load(), peak.Load())
}
