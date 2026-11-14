package gateway

// Measurement capture is opt-in. Its output is secured raw evidence, never a
// public response. A sticky write error makes the evidence unfit; it must not
// affect admission, retry an inference, or claim a successful observation.
import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"
)

type MeasurementRecorder struct {
	mu        sync.Mutex
	w         io.Writer
	sync      func() error
	boot      string
	start     time.Time
	seq       uint64
	err       error
	path      string
	closeFile func() error
}

func NewMeasurementRecorder(w io.Writer, syncFile func() error, boot string) *MeasurementRecorder {
	return &MeasurementRecorder{w: w, sync: syncFile, boot: boot, start: time.Now()}
}

func OpenMeasurementRecorder(path, boot string) (*MeasurementRecorder, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, err
	}
	r := NewMeasurementRecorder(f, f.Sync, boot)
	r.path = path
	r.closeFile = f.Close
	r.Record("capture_start", map[string]any{})
	return r, r.Err()
}

func (r *MeasurementRecorder) Close() error {
	if r == nil {
		return nil
	}
	r.Record("capture_end", map[string]any{})
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closeFile == nil {
		return r.err
	}
	err := r.closeFile()
	r.closeFile = nil
	return errors.Join(r.err, err)
}

func (r *MeasurementRecorder) Record(event string, data map[string]any) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return
	}
	now := time.Now()
	row := map[string]any{"schema": "gateway-measurement-v1", "sequence": r.seq, "boot_id": r.boot,
		"mono_ns": now.Sub(r.start).Nanoseconds(), "wall_ns": now.UnixNano(), "event": event, "data": data}
	line, err := json.Marshal(row)
	if err == nil {
		line = append(line, '\n')
		var n int
		n, err = r.w.Write(line)
		if err == nil && n != len(line) {
			err = io.ErrShortWrite
		}
	}
	if err == nil && r.sync != nil {
		err = r.sync()
	}
	if err != nil {
		r.err = errors.Join(errors.New("measurement_capture_lost"), err)
		return
	}
	r.seq++
}

func (r *MeasurementRecorder) Err() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.err
}

func (r *Registry) SetMeasurementRecorder(recorder *MeasurementRecorder) {
	r.backendMu.Lock()
	defer r.backendMu.Unlock()
	r.measurement = recorder
}

func (r *Registry) measurementTime() int64 {
	r.backendMu.RLock()
	defer r.backendMu.RUnlock()
	if r.measurement == nil {
		return 0
	}
	return time.Since(r.measurement.start).Nanoseconds()
}

func (g *Gateway) SetMeasurementRecorder(recorder *MeasurementRecorder) { g.measurement = recorder }

func (r *MeasurementRecorder) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if r == nil || req.Method != http.MethodGet {
		http.NotFound(w, req)
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		http.Error(w, "measurement_capture_lost", 503)
		return
	}
	if req.URL.Query().Get("clock") == "1" {
		now := time.Now()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"boot_id": r.boot, "mono_ns": now.Sub(r.start).Nanoseconds(), "wall_ns": now.UnixNano()})
		return
	}
	offset, err := strconv.ParseInt(req.URL.Query().Get("offset"), 10, 64)
	if err != nil || offset < 0 || r.path == "" {
		http.Error(w, "invalid_capture_offset", 400)
		return
	}
	f, err := os.Open(r.path)
	if err != nil {
		http.Error(w, "capture_unavailable", 503)
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || offset > info.Size() {
		http.Error(w, "capture_truncated", 409)
		return
	}
	if offset > 0 {
		var previous [1]byte
		if _, err = f.ReadAt(previous[:], offset-1); err != nil || previous[0] != '\n' {
			http.Error(w, "unaligned_capture_offset", 400)
			return
		}
	}
	if _, err = f.Seek(offset, 0); err != nil {
		http.Error(w, "capture_seek", 503)
		return
	}
	data, err := io.ReadAll(io.LimitReader(f, 1<<20))
	if err != nil {
		http.Error(w, "capture_read", 503)
		return
	}
	end := len(data)
	for end > 0 && data[end-1] != '\n' {
		end--
	}
	if end == 0 && len(data) != 0 {
		http.Error(w, "capture_torn_or_oversize", 503)
		return
	}
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("X-Capture-Boot", r.boot)
	w.Header().Set("X-Capture-Next", strconv.FormatInt(offset+int64(end), 10))
	_, _ = w.Write(data[:end])
}

func (r *Registry) measurementSnapshot(event string, fields map[string]any) {
	r.backendMu.RLock()
	defer r.backendMu.RUnlock()
	if r.measurement == nil {
		return
	}
	members := make([]map[string]any, 0, len(r.backends))
	for _, b := range r.backends {
		members = append(members, map[string]any{"name": b.ID, "uid": b.Generation,
			"sampled": b.checked.Load() > 0, "healthy": b.Healthy(), "ready": b.Ready()})
	}
	fields["members"] = members
	fields["membership_known"] = !r.discoveryUnknown.Load()
	r.measurement.Record(event, fields)
}
