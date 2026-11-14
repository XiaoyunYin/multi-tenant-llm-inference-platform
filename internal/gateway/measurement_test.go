package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
)

func TestMeasurementConcurrentDurableOrderAndLoss(t *testing.T) {
	var buf bytes.Buffer
	r := NewMeasurementRecorder(&buf, func() error { return nil }, "pod-boot")
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			for range 50 {
				r.Record("test", map[string]any{"value": 1})
			}
		})
	}
	workers.Wait()
	lines := bytes.Split(bytes.TrimSpace(buf.Bytes()), []byte("\n"))
	if len(lines) != 400 || r.Err() != nil {
		t.Fatalf("capture: %d, %v", len(lines), r.Err())
	}
	for index, line := range lines {
		var row struct {
			Sequence int    `json:"sequence"`
			Boot     string `json:"boot_id"`
		}
		if err := json.Unmarshal(line, &row); err != nil || row.Sequence != index || row.Boot != "pod-boot" {
			t.Fatalf("line %d: %s %v", index, line, err)
		}
	}
	failed := NewMeasurementRecorder(io.Discard, func() error { return errors.New("disk lost") }, "boot")
	failed.Record("a", nil)
	failed.sync = func() error { return nil }
	failed.Record("b", nil)
	if failed.Err() == nil || failed.seq != 0 {
		t.Fatal("capture recovered after a lost write")
	}
}

func TestMeasurementHTTPResumeAndRestartRefusal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capture.jsonl")
	r, err := OpenMeasurementRecorder(path, "pod")
	defer r.Close()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenMeasurementRecorder(path, "new-boot"); err == nil {
		t.Fatal("restart overwrote evidence")
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/?offset=0", nil))
	if w.Code != 200 || w.Header().Get("X-Capture-Next") == "" || !bytes.Contains(w.Body.Bytes(), []byte("capture_start")) {
		t.Fatalf("first capture: %v", w)
	}
	next := w.Header().Get("X-Capture-Next")
	r.Record("health", map[string]any{"members": []string{}})
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/?offset="+next, nil))
	if w.Code != 200 || bytes.Contains(w.Body.Bytes(), []byte("capture_start")) || !bytes.Contains(w.Body.Bytes(), []byte("health")) {
		t.Fatalf("resumed capture: %v", w)
	}
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/?offset=1", nil))
	if w.Code != 400 {
		t.Fatal("unaligned offset accepted")
	}
	w = httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest("GET", "/?clock=1", nil))
	if w.Code != 200 || !bytes.Contains(w.Body.Bytes(), []byte("mono_ns")) {
		t.Fatal("clock mapping absent")
	}
}
