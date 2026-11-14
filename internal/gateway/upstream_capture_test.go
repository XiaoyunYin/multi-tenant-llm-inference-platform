package gateway

import (
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

type countedUpstream struct {
	*strings.Reader
	calls        atomic.Int32
	observations *atomic.Int32
	err          error
}

func (b *countedUpstream) Close() error {
	if b.observations.Load() != 1 {
		return errors.New("close effect preceded source event")
	}
	b.calls.Add(1)
	return b.err
}

func TestUpstreamCloseCaptureConcurrentOwnersAndResult(t *testing.T) {
	var observations atomic.Int32
	expected := errors.New("original close result")
	inner := &countedUpstream{Reader: strings.NewReader("bytes"), observations: &observations, err: expected}
	body := &capturedUpstreamBody{ReadCloser: inner, closing: func() { observations.Add(1) }}
	var workers sync.WaitGroup
	for range 20 {
		workers.Go(func() {
			if err := body.Close(); err != expected {
				t.Errorf("close result changed: %v", err)
			}
		})
	}
	workers.Wait()
	if observations.Load() != 1 || inner.calls.Load() != 1 {
		t.Fatalf("duplicate effects/events: %d/%d", inner.calls.Load(), observations.Load())
	}
}
