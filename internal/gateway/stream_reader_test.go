package gateway

import (
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
)

func collectStreamEvents(body string, limit int) []streamEvent {
	var events []streamEvent
	for event := range streamEvents(context.Background(), io.NopCloser(strings.NewReader(body)), limit) {
		events = append(events, event)
	}
	return events
}

func TestStreamReaderRetainsPayloadAndBoundsAcrossReuse(t *testing.T) {
	payload := strings.Repeat("x", 60<<10)
	first := collectStreamEvents("data: "+payload+"\n\ndata: [DONE]\n\n", DefaultConfig().MaxEventBytes)
	if len(first) != 2 || string(first[0].data) != payload || !first[1].done {
		t.Fatal("large valid payload rejected")
	}
	for range 100 {
		next := collectStreamEvents("data: next\n\ndata: [DONE]\n\n", DefaultConfig().MaxEventBytes)
		if len(next) != 2 || string(next[0].data) != "next" || !next[1].done {
			t.Fatal("stale reader payload")
		}
	}
	if string(first[0].data) != payload {
		t.Fatal("retained event aliased a reused reader")
	}
	for _, limit := range []int{DefaultConfig().MaxEventBytes, 128} {
		events := collectStreamEvents("data: "+strings.Repeat("y", limit)+"\n\n", limit)
		if len(events) != 1 || events[0].err == nil || events[0].done {
			t.Fatalf("oversized event accepted at limit %d", limit)
		}
	}
}

func TestStreamReadersAreIsolatedConcurrently(t *testing.T) {
	var wg sync.WaitGroup
	for i := range 64 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			want := fmt.Sprintf("stream-%d-%s", i, strings.Repeat("z", 8192))
			for range 10 {
				events := collectStreamEvents("data: "+want+"\n\ndata: [DONE]\n\n", DefaultConfig().MaxEventBytes)
				if len(events) != 2 || string(events[0].data) != want || !events[1].done {
					t.Errorf("stream %d contamination", i)
					return
				}
			}
		}(i)
	}
	wg.Wait()
}
