package proxy

import (
	"io"
	"net/http"
)

// HTTP/3 replaces Request.Trailer after consuming its trailing HEADERS frame.
// Publish the final map at EOF, before the upstream transport writes trailers.
type forwardTrailerBody struct {
	io.ReadCloser
	source, destination *http.Request
}

func (b *forwardTrailerBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err == io.EOF {
		b.destination.Trailer = b.source.Trailer
	}
	return n, err
}
