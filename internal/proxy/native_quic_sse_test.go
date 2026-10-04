package proxy

import (
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/require"
)

func TestNativeQUICSSEStreamingTrailers(t *testing.T) {
	for _, version := range []quic.Version{quic.Version1, quic.Version2} {
		t.Run(version.String(), func(t *testing.T) {
			finish := make(chan struct{})
			var once sync.Once
			release := func() { once.Do(func() { close(finish) }) }
			_, addr, target, roots, _ := quicFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				w.Header().Set("Trailer", "X-Stream-Result")
				if _, err := io.WriteString(w, "data: first\n\n"); err != nil {
					return // Client cancellation is permitted during test cleanup.
				}
				if err := http.NewResponseController(w).Flush(); err != nil {
					return
				}
				select {
				case <-finish:
				case <-r.Context().Done():
					return
				}
				w.Header().Set("X-Stream-Result", "complete")
			}))
			defer release()
			client := quicClient(t, addr, target, strings.Repeat("a", 64), roots, version)
			response, err := client.Get("https://localhost/events")
			require.NoError(t, err)
			defer response.Body.Close()
			require.Equal(t, "HTTP/3.0", response.Proto)
			require.Equal(t, http.StatusOK, response.StatusCode)
			first := make([]byte, len("data: first\n\n"))
			_, err = io.ReadFull(response.Body, first)
			require.NoError(t, err, "event must arrive before upstream finishes")
			require.Equal(t, "data: first\n\n", string(first))
			release()
			remaining, err := io.ReadAll(response.Body)
			require.NoError(t, err)
			require.Empty(t, remaining)
			require.Equal(t, "complete", response.Trailer.Get("X-Stream-Result"))
		})
	}
}
