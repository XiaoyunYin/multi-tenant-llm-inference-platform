// Command cpu-bench supplies local vLLM-shaped mocks and an open-loop SSE probe.
// It is not an inference runtime. Production gateways are separate processes.
package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptrace"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const content = "hello world"
const payload = `{"model":"test-model","messages":[{"role":"user","content":"cpu-probe"}],"stream":true,"max_tokens":2}`

type row struct {
	Phase          string `json:"phase"`
	Ordinal        int    `json:"ordinal"`
	Target         int    `json:"target"`
	PlannedNS      int64  `json:"planned_ns"`
	DispatchNS     int64  `json:"dispatch_ns"`
	EndNS          int64  `json:"end_ns"`
	FirstContentNS int64  `json:"first_content_ns"`
	Status         int    `json:"status"`
	Outcome        string `json:"outcome"`
	Error          string `json:"error,omitempty"`
	Reused         bool   `json:"connection_reused"`
	LocalPort      string `json:"local_port,omitempty"`
}

// Validate the actual content and complete protocol, not just a trailing DONE.
func consume(reader io.Reader) (first time.Time, complete bool, hadContent bool) {
	scanner := bufio.NewScanner(reader)
	var text strings.Builder
	finish, usage, done, invalid, stage := 0, 0, 0, false, 0
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		data := strings.TrimPrefix(line, "data: ")
		if stage == 3 {
			invalid = true
		}
		if data == "[DONE]" {
			done++
			if stage != 2 {
				invalid = true
			}
			stage = 3
			continue
		}
		var event struct {
			Error   json.RawMessage `json:"error"`
			Choices []struct {
				Delta struct {
					Content string `json:"content"`
				} `json:"delta"`
				Finish *string `json:"finish_reason"`
			} `json:"choices"`
			Usage *struct {
				Prompt     int `json:"prompt_tokens"`
				Completion int `json:"completion_tokens"`
				Total      int `json:"total_tokens"`
			} `json:"usage"`
		}
		if json.Unmarshal([]byte(data), &event) != nil || len(event.Error) != 0 {
			invalid = true
			continue
		}
		for _, choice := range event.Choices {
			if choice.Delta.Content != "" {
				if stage != 0 {
					invalid = true
				}
				if first.IsZero() {
					first = time.Now()
				}
				text.WriteString(choice.Delta.Content)
			}
			if choice.Finish != nil {
				finish++
				if *choice.Finish != "stop" || stage != 0 {
					invalid = true
				}
				stage = 1
			}
		}
		if event.Usage != nil {
			usage++
			if stage != 1 || event.Usage.Prompt != 4 || event.Usage.Completion != 2 || event.Usage.Total != 6 {
				invalid = true
			}
			stage = 2
		}
	}
	return first, scanner.Err() == nil && !invalid && text.String() == content && finish == 1 && usage == 1 && done == 1, text.Len() > 0
}

func request(client *http.Client, targets []string, origin time.Time, phase string, ordinal int, planned time.Duration) row {
	r := row{Phase: phase, Ordinal: ordinal, Target: ordinal % len(targets), PlannedNS: int64(planned)}
	req, _ := http.NewRequest(http.MethodPost, targets[r.Target]+"/v1/chat/completions", bytes.NewBufferString(payload))
	req.Header.Set("Authorization", "Bearer local-dev-token")
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) {
		r.Reused = info.Reused
		_, r.LocalPort, _ = net.SplitHostPort(info.Conn.LocalAddr().String())
	}}))
	r.DispatchNS = int64(time.Since(origin))
	resp, err := client.Do(req)
	if err != nil {
		r.Outcome, r.Error = "failed", "transport"
	} else {
		r.Status = resp.StatusCode
		if resp.StatusCode == 200 {
			first, complete, hadContent := consume(resp.Body)
			if !first.IsZero() {
				r.FirstContentNS = int64(first.Sub(origin))
			}
			switch {
			case complete:
				r.Outcome = "completed"
			case hadContent:
				r.Outcome = "partial"
			default:
				r.Outcome = "failed"
			}
			if !complete {
				r.Error = "protocol_or_transport"
			}
		} else {
			r.Outcome, r.Error = "failed", "http"
			var body struct {
				Error struct {
					Code string `json:"code"`
				} `json:"error"`
			}
			if json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&body) == nil && body.Error.Code != "" {
				r.Error = body.Error.Code
			}
			_, _ = io.Copy(io.Discard, resp.Body)
		}
		resp.Body.Close()
	}
	r.EndNS = int64(time.Since(origin))
	return r
}

func openLoop(client *http.Client, targets []string, phase string, rate int, seconds float64, precise bool) ([]row, map[string]any) {
	n := int(float64(rate) * seconds)
	rows := make([]row, n)
	origin := time.Now()
	var wg sync.WaitGroup
	var active, peak atomic.Int64
	slots := make(chan struct{}, 4096)
	for i := range n {
		planned := time.Duration(float64(i) * float64(time.Second) / float64(rate))
		deadline := origin.Add(planned)
		if precise {
			// A dedicated dispatcher uses up to one of the generator's four
			// CPU cores to avoid sleep/wakeup jitter. This is an explicit,
			// separately reported measurement condition, not a default change.
			for time.Now().Before(deadline) {
			}
		} else if wait := time.Until(deadline); wait > 0 {
			time.Sleep(wait)
		}
		select {
		case slots <- struct{}{}:
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() { <-slots; active.Add(-1) }()
				a := active.Add(1)
				for old := peak.Load(); a > old && !peak.CompareAndSwap(old, a); old = peak.Load() {
				}
				rows[i] = request(client, targets, origin, phase, i, planned)
			}()
		default:
			rows[i] = row{Phase: phase, Ordinal: i, Target: i % len(targets), PlannedNS: int64(planned), Outcome: "not_dispatched", Error: "generator_slots"}
		}
	}
	if wait := time.Until(origin.Add(time.Duration(seconds * float64(time.Second)))); wait > 0 {
		time.Sleep(wait)
	}
	wg.Wait()
	return rows, map[string]any{"start_unix_ns": origin.UnixNano(), "end_unix_ns": time.Now().UnixNano(), "offered_seconds": seconds, "peak_in_flight": peak.Load()}
}

func closedLoop(client *http.Client, targets []string, concurrency int, seconds float64) ([]row, map[string]any) {
	origin := time.Now()
	deadline := origin.Add(time.Duration(seconds * float64(time.Second)))
	var rows []row
	var mu sync.Mutex
	var counter atomic.Int64
	var wg sync.WaitGroup
	for range concurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(deadline) {
				ordinal := int(counter.Add(1) - 1)
				r := request(client, targets, origin, "measurement", ordinal, time.Since(origin))
				mu.Lock()
				rows = append(rows, r)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	sort.Slice(rows, func(i, j int) bool { return rows[i].Ordinal < rows[j].Ordinal })
	return rows, map[string]any{"start_unix_ns": origin.UnixNano(), "end_unix_ns": time.Now().UnixNano(), "offered_seconds": seconds, "concurrency": concurrency}
}

func quantile(values []float64, p float64) any {
	if len(values) < int(math.Ceil(20/(1-p)-1e-9)) {
		return nil
	}
	sort.Float64s(values)
	return values[int(math.Ceil(p*float64(len(values))))-1]
}

func distribution(values []float64) map[string]any {
	if len(values) == 0 {
		return map[string]any{"n": 0, "p50": nil, "p99": nil}
	}
	sort.Float64s(values)
	sum := 0.0
	for _, v := range values {
		sum += v
	}
	return map[string]any{"n": len(values), "min": values[0], "mean": sum / float64(len(values)), "max": values[len(values)-1], "p50": quantile(values, .5), "p99": quantile(values, .99)}
}

func summary(rows []row) map[string]any {
	counts := map[string]int{"completed": 0, "failed": 0, "partial": 0, "not_dispatched": 0}
	errors := map[string]int{}
	status := map[int]int{}
	targets := map[int]int{}
	connections := map[string]bool{}
	var execution, arrival, first, lag []float64
	reused := 0
	for _, r := range rows {
		counts[r.Outcome]++
		if r.Error != "" {
			errors[r.Error]++
		}
		status[r.Status]++
		targets[r.Target]++
		if r.Outcome != "not_dispatched" {
			lag = append(lag, float64(r.DispatchNS-r.PlannedNS)/1e6)
		}
		if r.LocalPort != "" {
			connections[fmt.Sprint(r.Target)+":"+r.LocalPort] = true
		}
		if r.Reused {
			reused++
		}
		if r.Outcome == "completed" {
			execution = append(execution, float64(r.EndNS-r.DispatchNS)/1e6)
			arrival = append(arrival, float64(r.EndNS-r.PlannedNS)/1e6)
			first = append(first, float64(r.FirstContentNS-r.DispatchNS)/1e6)
		}
	}
	return map[string]any{"counts": counts, "error_codes": errors, "http_statuses": status, "targets": targets, "execution_ms": distribution(execution), "arrival_ms": distribution(arrival), "first_content_ms": distribution(first), "dispatch_lag_ms": distribution(lag), "reused_connections": reused, "distinct_target_local_ports": len(connections)}
}

func fake(address, id string, delay time.Duration) {
	var requests, active, peak atomic.Int64
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"backend_id":%q,"healthy":true,"ready":true}`, id)
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "vllm:num_requests_running %d\nvllm:num_requests_waiting 0\nvllm:kv_cache_usage_perc 0\n", active.Load())
	})
	mux.HandleFunc("/bench/stats", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]int64{"requests": requests.Load(), "active": active.Load(), "peak": peak.Load()})
	})
	mux.HandleFunc("/v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Model  string `json:"model"`
			Stream bool   `json:"stream"`
		}
		if json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req) != nil || req.Model != "test-model" || !req.Stream {
			http.Error(w, "invalid mock request", 400)
			return
		}
		requests.Add(1)
		a := active.Add(1)
		defer active.Add(-1)
		for old := peak.Load(); a > old && !peak.CompareAndSwap(old, a); old = peak.Load() {
		}
		select {
		case <-time.After(delay):
		case <-r.Context().Done():
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		for _, event := range []string{
			`{"choices":[{"delta":{"role":"assistant"},"finish_reason":null}]}`,
			`{"choices":[{"delta":{"content":"hello"},"finish_reason":null}]}`,
			`{"choices":[{"delta":{"content":" world"},"finish_reason":null}]}`,
			`{"choices":[{"delta":{},"finish_reason":"stop"}]}`,
			`{"choices":[],"usage":{"prompt_tokens":4,"completion_tokens":2,"total_tokens":6}}`, "[DONE]",
		} {
			if event != "[DONE]" {
				event = strings.Replace(event, "{", `{"object":"chat.completion.chunk","model":"test-model","created":0,"id":"cpu-probe",`, 1)
			}
			fmt.Fprintf(w, "data: %s\n\n", event)
			w.(http.Flusher).Flush()
		}
	})
	if err := http.ListenAndServe(address, mux); err != nil {
		panic(err)
	}
}

func main() {
	mode := flag.String("mode", "load", "fakes or load")
	addresses := flag.String("addresses", "", "comma-separated literal loopback addresses/URLs")
	rate := flag.Int("rate", 100, "open-loop offered requests/s")
	seconds := flag.Float64("seconds", 24, "measurement duration")
	concurrency := flag.Int("concurrency", 0, "closed-loop diagnostic workers; zero uses open loop")
	delay := flag.Duration("delay", 5*time.Millisecond, "fake first-content delay")
	output := flag.String("output", "", "gzip JSONL request output")
	precise := flag.Bool("precise-dispatch", false, "busy-wait planned arrivals; consumes a generator CPU core")
	flag.Parse()
	parts := strings.Split(*addresses, ",")
	if len(parts) != 2 || *seconds <= 0 || *rate <= 0 {
		panic("requires two targets and positive duration/rate")
	}
	if *mode == "fakes" {
		for i, address := range parts {
			go fake(address, fmt.Sprintf("fake-%d", i), *delay)
		}
		select {}
	}
	transport := &http.Transport{MaxIdleConns: 8192, MaxIdleConnsPerHost: 4096, IdleConnTimeout: 60 * time.Second, DisableCompression: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	warm, warmTiming := openLoop(client, parts, "warmup", *rate, 2, *precise)
	var rows []row
	var timing map[string]any
	if *concurrency > 0 {
		rows, timing = closedLoop(client, parts, *concurrency, *seconds)
	} else {
		rows, timing = openLoop(client, parts, "measurement", *rate, *seconds, *precise)
	}
	file, err := os.Create(*output)
	if err != nil {
		panic(err)
	}
	zip := gzip.NewWriter(file)
	encoder := json.NewEncoder(zip)
	for _, r := range append(warm, rows...) {
		if err := encoder.Encode(r); err != nil {
			panic(err)
		}
	}
	if err := zip.Close(); err != nil {
		panic(err)
	}
	if err := file.Close(); err != nil {
		panic(err)
	}
	_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"warmup": summary(warm), "warmup_timing": warmTiming, "measurement": summary(rows), "timing": timing})
}
