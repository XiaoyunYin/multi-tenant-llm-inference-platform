package gateway

import (
	"io"
	"sync"
)

// The event marks initiation of the owned body's close, before the close can
// cause a native abort. It does not claim remote processing or engine release.
// Every handler/reader/cancellation close shares this single owner.
type capturedUpstreamBody struct {
	io.ReadCloser
	closing func()
	once    sync.Once
	err     error
}

func (b *capturedUpstreamBody) Close() error {
	b.once.Do(func() {
		b.closing()
		b.err = b.ReadCloser.Close()
	})
	return b.err
}
