package proxy

import (
	"io"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCountingReader_CountsBytesRead(t *testing.T) {
	var count int64
	reader := &countingReader{reader: strings.NewReader("hello, proxy"), count: &count}

	data, err := io.ReadAll(reader)

	require.NoError(t, err)
	require.Equal(t, "hello, proxy", string(data))
	require.Equal(t, int64(len("hello, proxy")), atomic.LoadInt64(&count))
}
