package gateway

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	redis "github.com/redis/go-redis/v9"
	"multi-tenant-llm-inference-platform/internal/admission"
)

// Local synthetic oracle only; no slice 4 deployment values are selected.
const m5WithholdingWindow = 3100 * time.Millisecond

type m5Pod struct {
	server   *httptest.Server
	uid      string
	hold     atomic.Bool
	badDone  atomic.Bool
	active   atomic.Int64
	contacts atomic.Int64
	release  chan struct{}
	once     sync.Once
}

func (p *m5Pod) unblock() { p.once.Do(func() { close(p.release) }) }

type m5Report struct {
	N     int64
	Known bool
}

type m5Admission struct {
	MS   int64
	B    int64
	Code string
}

type m5Coordinator struct {
	admission.Coordinator
	mu      sync.Mutex
	start   time.Time
	history []m5Admission
	after   func()
}

func (c *m5Coordinator) Admit(ctx context.Context, r admission.Request) (admission.Result, error) {
	result, err := c.Coordinator.Admit(ctx, r)
	c.mu.Lock()
	c.history = append(c.history, m5Admission{time.Since(c.start).Milliseconds(), result.Capacity, result.Decision.Code()})
	after := c.after
	c.after = nil
	c.mu.Unlock()
	if err == nil && result.Decision == admission.Allowed && after != nil {
		after()
	}
	return result, err
}

type m5Gateway struct {
	g         *Gateway
	r         *Registry
	d         *EndpointSliceDiscovery
	c         *m5Coordinator
	server    *httptest.Server
	ingress   *httptest.Server
	mu        sync.Mutex
	reports   []m5Report
	lastKnown time.Time // before the successful Redis publication: conservative age
}

type m5Rehearsal struct {
	t         *testing.T
	ctx       context.Context
	client    *redis.Client
	prefix    string
	gateways  [2]*m5Gateway
	pods      []*m5Pod
	api       *httptest.Server
	mu        sync.Mutex
	body      string
	status    int
	dials     map[string]string
	transport *http.Transport
	serial    int
	start     time.Time
}

func newM5Rehearsal(t *testing.T, ttl time.Duration) *m5Rehearsal {
	t.Helper()
	address := os.Getenv("REDIS_TEST_ADDR")
	if address == "" {
		t.Skip("REDIS_TEST_ADDR is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	h := &m5Rehearsal{t: t, ctx: ctx, status: 200, dials: map[string]string{}, start: time.Now()}
	namespace := fmt.Sprintf("m5-rehearsal:%x", time.Now().UnixNano())
	h.prefix = namespace + ":{admission}:"
	h.client = redis.NewClient(&redis.Options{Addr: address, Protocol: 2, MaxRetries: -1})
	if err := h.client.Ping(ctx).Err(); err != nil {
		t.Fatal(err)
	}
	// Disable connection reuse to make the synthetic IP/UID remap explicit;
	// already established streams retain their original TCP socket.
	h.transport = &http.Transport{DisableKeepAlives: true, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		h.mu.Lock()
		destination := h.dials[address]
		h.mu.Unlock()
		if destination == "" {
			return nil, fmt.Errorf("non-pod direct route %q", address)
		}
		return (&net.Dialer{}).DialContext(ctx, network, destination)
	}}
	h.api = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/apis/discovery.k8s.io/v1/namespaces/test/endpointslices" || r.URL.Query().Get("labelSelector") != "kubernetes.io/service-name=fake" || r.Header.Get("Authorization") != "Bearer fixture" {
			t.Error("rehearsal API scope/credential mismatch")
			w.WriteHeader(400)
			return
		}
		h.mu.Lock()
		defer h.mu.Unlock()
		w.WriteHeader(h.status)
		fmt.Fprint(w, h.body)
	}))
	t.Cleanup(func() {
		for _, p := range h.pods {
			p.unblock()
		}
		cancel()
		for _, g := range h.gateways {
			if g != nil {
				g.ingress.Close()
				g.server.Close()
			}
		}
		for _, p := range h.pods {
			p.server.Close()
		}
		h.api.Close()
		h.transport.CloseIdleConnections()
		keys := h.client.Keys(context.Background(), namespace+":*").Val()
		if len(keys) > 0 {
			h.client.Del(context.Background(), keys...)
		}
		h.client.Close()
	})
	for i := range h.gateways {
		// Separate production coordinators, sharing only Redis and config.
		c, err := admission.NewRedisCoordinator(h.client, admission.RedisConfig{Namespace: namespace, GlobalCapacity: 99, LeaseDuration: time.Minute, TombstoneTTL: time.Minute, DynamicCapacity: &admission.DynamicCapacityConfig{Running: 2, Waiting: 1, ReportTTL: ttl, HoldDown: 50 * time.Millisecond}})
		if err != nil {
			t.Fatal(err)
		}
		r, err := NewDiscoveryRegistry(&http.Client{Transport: h.transport}, 250*time.Millisecond)
		if err != nil {
			t.Fatal(err)
		}
		g := &m5Gateway{r: r, c: &m5Coordinator{Coordinator: c, start: h.start}}
		id := fmt.Sprintf("gateway-%d", i)
		r.SetCapacityReporter(func(ctx context.Context, n int64, known bool) error {
			sent := time.Now()
			g.mu.Lock()
			g.reports = append(g.reports, m5Report{n, known})
			g.mu.Unlock()
			err := c.ReportHealthy(ctx, id, n, known)
			if known && err == nil {
				g.mu.Lock()
				g.lastKnown = sent
				g.mu.Unlock()
			}
			return err
		})
		g.d, err = NewEndpointSliceDiscovery(DiscoveryConfig{"test", "fake", 250 * time.Millisecond}, r, h.api.Client(), h.api.URL, func() (string, error) { return "fixture", nil }, nil)
		if err != nil {
			t.Fatal(err)
		}
		g.g, err = New(DefaultConfig(), r, &http.Client{Transport: h.transport}, nil, WithTenantRegistry(testTenantRegistry(t)), WithAdmissionCoordinator(g.c))
		if err != nil {
			t.Fatal(err)
		}
		g.server = httptest.NewServer(g.g.Handler())
		target, _ := url.Parse(g.server.URL)
		proxy := httputil.NewSingleHostReverseProxy(target)
		proxy.FlushInterval = -1 // ingress stand-in: flush every SSE write
		g.ingress = httptest.NewServer(proxy)
		g.ingress.Client().Timeout = 8 * time.Second
		h.gateways[i] = g
	}
	t.Logf("SYNTHETIC test-oracle R=2 W=1 TTL=%s hold=50ms; real Redis TIME; no deployment choices", ttl)
	return h
}

func (h *m5Rehearsal) pod(uid, ip string) *m5Pod {
	p := &m5Pod{uid: uid, release: make(chan struct{})}
	p.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			fmt.Fprint(w, `{"healthy":true,"ready":true}`)
			return
		}
		if r.URL.Path != "/v1/chat/completions" || r.Host != ip+":8000" {
			h.t.Error("direct pod path/Host lost")
		}
		p.contacts.Add(1)
		p.active.Add(1)
		defer p.active.Add(-1)
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, roleEvent+strings.ReplaceAll(contentEvent, "hello", uid))
		w.(http.Flusher).Flush()
		if p.hold.Load() {
			select {
			case <-p.release:
			case <-r.Context().Done():
				return
			}
		}
		if !p.badDone.Load() {
			fmt.Fprint(w, finishEvent+usageEvent)
		}
		fmt.Fprint(w, doneEvent)
	}))
	h.pods = append(h.pods, p)
	h.mu.Lock()
	h.dials[ip+":8000"] = p.server.Listener.Addr().String()
	h.mu.Unlock()
	return p
}

func (h *m5Rehearsal) apiState(status int, members ...map[string]any) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.status, h.body = status, slicePayload(members...)
}

func (h *m5Rehearsal) discover(ok bool) {
	h.t.Helper()
	for _, g := range h.gateways {
		if err := g.d.Poll(h.ctx); (err == nil) != ok {
			h.t.Fatalf("EndpointSlice poll success=%v err=%v", ok, err)
		}
	}
}

func (h *m5Rehearsal) health() {
	for _, g := range h.gateways {
		g.r.Poll(h.ctx)
	}
}

func (h *m5Rehearsal) reports(n int64, known bool) {
	h.t.Helper()
	for i, g := range h.gateways {
		g.mu.Lock()
		last := g.reports[len(g.reports)-1]
		g.mu.Unlock()
		// The count of an unknown report is deliberately ignored by Redis.
		if last.Known != known || (known && last.N != n) {
			h.t.Fatalf("rehearsal report completeness gateway=%d last=%+v want N=%d known=%v", i, last, n, known)
		}
	}
}

func (h *m5Rehearsal) capacity(phase string, want int64, code string) {
	h.t.Helper()
	h.serial++
	r := admission.Request{TenantID: "oracle", ReservationID: fmt.Sprintf("rsv_%032x", h.serial), Limits: admission.Limits{RequestLimit: 10000, RequestWindow: time.Minute, MaxConcurrent: 128}}
	got, err := h.gateways[0].c.Coordinator.Admit(h.ctx, r)
	if err != nil || got.Capacity != want || got.Decision.Code() != code {
		h.t.Fatalf("rehearsal B/TTL %s B=%d code=%s err=%v want=%d/%s", phase, got.Capacity, got.Decision.Code(), err, want, code)
	}
	if got.Decision == admission.Allowed {
		if err := h.gateways[0].c.Release(h.ctx, r.TenantID, r.ReservationID); err != nil {
			h.t.Fatal(err)
		}
	}
	h.t.Logf("t=%dms phase=%s effective B=%d code=%s", time.Since(h.start).Milliseconds(), phase, got.Capacity, code)
}

func (h *m5Rehearsal) request(i int, code string) string {
	h.t.Helper()
	g := h.gateways[i]
	response := requestGateway(h.t, g.ingress.Client(), g.ingress.URL)
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		h.t.Fatal(err)
	}
	status := 503
	if code == "completed" || code == "stream_interrupted" {
		status = 200
	} else if code == "system_capacity" {
		status = 429
	}
	if response.StatusCode != status || (code == "completed" && !containsBytes(body, "[DONE]")) || (code != "completed" && !containsBytes(body, code)) || (code == "stream_interrupted" && containsBytes(body, "[DONE]")) || (code == "capacity_reports_expired" && response.Header.Get("Retry-After") != "") {
		h.t.Fatalf("rehearsal HTTP/SSE gateway=%d want=%s status=%d body=%s", i, code, response.StatusCode, body)
	}
	return string(body)
}

// All five refusal families are asserted even when their expected count is zero.
func m5Counts(g *Gateway) [8]uint64 {
	m := g.Metrics()
	return [8]uint64{m.DiscoveryUnknown, m.DiscoveryUnknownAfterAdmit, m.BackendChangedAfterAdmit, m.CapacityReportsExpired, m.SystemCapacityLimited, m.Completed, m.Partial, m.Failed}
}

func (h *m5Rehearsal) event(name string, want [2][8]uint64, action func()) {
	h.t.Helper()
	var before [2][8]uint64
	var initial [2]m5Report
	var reportStart, admitStart [2]int
	var contacts int64
	for _, p := range h.pods {
		contacts += p.contacts.Load()
	}
	for i, g := range h.gateways {
		before[i] = m5Counts(g.g)
		g.mu.Lock()
		reportStart[i] = len(g.reports)
		if len(g.reports) > 0 {
			initial[i] = g.reports[len(g.reports)-1]
		}
		g.mu.Unlock()
		g.c.mu.Lock()
		admitStart[i] = len(g.c.history)
		g.c.mu.Unlock()
	}
	action()
	for i, g := range h.gateways {
		got := m5Counts(g.g)
		for j := range got {
			got[j] -= before[i][j]
		}
		g.mu.Lock()
		h.t.Logf("event=%s gateway=%d report before=%+v sequence=%+v final=%+v", name, i, initial[i], g.reports[reportStart[i]:], g.reports[len(g.reports)-1])
		g.mu.Unlock()
		g.c.mu.Lock()
		h.t.Logf("event=%s gateway=%d admission B/time/code=%+v", name, i, g.c.history[admitStart[i]:])
		g.c.mu.Unlock()
		h.t.Logf("event=%s gateway=%d distribution [unknown after changed expired system complete partial failed]=%v", name, i, got)
		if got != want[i] {
			h.t.Fatalf("rehearsal event distribution %s gateway=%d got=%v want=%v", name, i, got, want[i])
		}
	}
	var finalContacts int64
	for _, p := range h.pods {
		finalContacts += p.contacts.Load()
	}
	if got, expected := finalContacts-contacts, int64(want[0][5]+want[0][6]+want[1][5]+want[1][6]); got != expected {
		h.t.Fatalf("rehearsal upstream contact distribution after %s: got=%d want=%d", name, got, expected)
	}
	if n := h.client.ZCard(h.ctx, h.prefix+"global:active").Val(); n != 0 {
		h.t.Fatalf("rehearsal reservation leak after %s: active=%d", name, n)
	}
}

func (h *m5Rehearsal) startup() {
	h.event("startup", [2][8]uint64{{2, 0, 0, 0, 1, 1}, {2, 0, 0, 0, 1, 1}}, func() {
		h.capacity("no reports", 0, "capacity_reports_expired")
		for i := range h.gateways {
			h.request(i, "discovery_unknown")
		}
		h.discover(true)
		h.reports(0, false)
		for i := range h.gateways {
			h.request(i, "discovery_unknown")
		}
		h.health()
		h.reports(2, true)
		h.capacity("startup agreement starts", 0, "system_capacity")
		for i := range h.gateways {
			h.request(i, "system_capacity")
		}
		time.Sleep(60 * time.Millisecond)
		h.health()
		h.capacity("startup agreement complete", 6, "allowed")
		for i := range h.gateways {
			h.request(i, "completed")
		}
	})
}

func TestRedisM5RehearsalTTLControls(t *testing.T) {
	for _, negative := range []bool{false, true} {
		t.Run(fmt.Sprintf("shortTTL=%v", negative), func(t *testing.T) {
			ttl := 5 * time.Second
			if negative {
				ttl = 100 * time.Millisecond
			}
			h := newM5Rehearsal(t, ttl)
			h.pod("uid-a", "10.0.0.2")
			h.pod("uid-b", "10.0.0.3")
			a, b := podEndpoint("fake-0", "uid-a", "10.0.0.2", true, false), podEndpoint("fake-1", "uid-b", "10.0.0.3", true, false)
			h.apiState(200, a, b)
			h.startup()
			h.pod("uid-c", "10.0.0.4")
			// Bound prior-report age and then withhold for the entire registered
			// code budget. Retained members receive real health checks meanwhile.
			h.health()
			var prior [2]time.Time
			for i, g := range h.gateways {
				g.mu.Lock()
				prior[i] = g.lastKnown
				g.mu.Unlock()
			}
			time.Sleep(20 * time.Millisecond)
			h.apiState(200, a, b, podEndpoint("fake-2", "uid-c", "10.0.0.4", true, false))
			want := [2][8]uint64{{0, 0, 0, 0, 0, 12}, {0, 0, 0, 0, 0, 12}}
			if negative {
				want = [2][8]uint64{{0, 0, 0, 12}, {0, 0, 0, 12}}
			}
			h.event("steady-addition-withheld", want, func() {
				h.discover(true)
				for i := range prior {
					age := time.Since(prior[i])
					if age > 250*time.Millisecond {
						t.Fatalf("prior-report age exceeds registered fixture bound: gateway=%d age=%s", i, age)
					}
					t.Logf("gateway=%d conservative prior-report age=%s bound=250ms", i, age)
				}
				h.reports(0, false)
				installed := time.Now()
				for step := range 12 {
					// Fixed observation offsets span the 3.1 s withholding window.
					time.Sleep(time.Until(installed.Add(time.Duration(step+1) * m5WithholdingWindow / 12)))
					for _, g := range h.gateways {
						for _, member := range g.r.Backends() {
							if member.Generation != "uid-c" {
								g.r.check(h.ctx, member)
							}
						}
						if err := g.r.ReportCapacity(h.ctx); err != nil {
							t.Fatal(err)
						}
					}
					h.reports(0, false)
					code := "allowed"
					if negative {
						code = "capacity_reports_expired"
					}
					h.capacity(fmt.Sprintf("addition step %d", step), 6, code)
					for i := range h.gateways {
						requestCode := "completed"
						if negative {
							requestCode = code
						}
						h.request(i, requestCode)
					}
				}
				h.health()
				h.reports(3, true)
				h.capacity("addition independently sampled", 6, "allowed")
			})
		})
	}
}

// Read a content event through the ingress before changing membership. This
// fails if the proxy buffers until EOF and proves nonzero live SSE coverage.
func (h *m5Rehearsal) live(i int, uid string) (*http.Response, *bufio.Reader) {
	h.t.Helper()
	g := h.gateways[i]
	response := requestGateway(h.t, g.ingress.Client(), g.ingress.URL)
	reader := bufio.NewReader(response.Body)
	var prefix strings.Builder
	for !strings.Contains(prefix.String(), uid) {
		line, err := reader.ReadString('\n')
		if err != nil {
			h.t.Fatalf("ingress live content before drain: %v body=%s", err, prefix.String())
		}
		prefix.WriteString(line)
	}
	if response.StatusCode != 200 {
		h.t.Fatalf("live SSE status=%d", response.StatusCode)
	}
	return response, reader
}

func (h *m5Rehearsal) drain(response *http.Response, reader io.Reader) {
	h.t.Helper()
	defer response.Body.Close()
	body, err := io.ReadAll(reader)
	if err != nil || !containsBytes(body, "[DONE]") || containsBytes(body, "stream_interrupted") {
		h.t.Fatalf("rehearsal drain completion err=%v body=%s", err, body)
	}
}

func TestRedisM5RehearsalReplacementFailureRollback(t *testing.T) {
	h := newM5Rehearsal(t, 5*time.Second)
	old := h.pod("uid-old", "10.0.0.2")
	h.pod("uid-peer", "10.0.0.3")
	a := podEndpoint("fake-0", "uid-old", "10.0.0.2", true, false)
	b := podEndpoint("fake-1", "uid-peer", "10.0.0.3", true, false)
	h.apiState(200, a, b)
	h.startup()
	// Controlled selection targets the old pod on both gateways; production
	// admission, candidate filtering, dispatch validation and forwarding remain.
	for _, g := range h.gateways {
		g.g.backendSelection.router = &revalidationRaceRouter{after: func(*Backend) {}}
	}
	h.event("replacement-live-drain", [2][8]uint64{{0, 0, 0, 0, 0, 3}, {0, 0, 0, 0, 0, 3}}, func() {
		old.hold.Store(true)
		var responses [2]*http.Response
		var readers [2]*bufio.Reader
		for i := range h.gateways {
			responses[i], readers[i] = h.live(i, old.uid)
		}
		if old.active.Load() != 2 {
			t.Fatal("rehearsal drain lacks nonzero old-pod streams on both gateways")
		}
		contacts := old.contacts.Load()
		terminating := podEndpoint("fake-0", "uid-old", "10.0.0.2", true, true)
		h.apiState(200, terminating, b)
		h.discover(true)
		for _, g := range h.gateways {
			if members := g.r.Backends(); len(members) != 1 || members[0].Generation != "uid-peer" {
				t.Fatal("rehearsal terminating membership did not exclude old UID")
			}
		}
		h.reports(1, true)
		h.capacity("old terminating with two active streams", 3, "allowed")
		for i := range h.gateways {
			if body := h.request(i, "completed"); !strings.Contains(body, "uid-peer") {
				t.Fatal("rehearsal terminating direct route did not exclude old UID")
			}
		}
		if old.contacts.Load() != contacts || old.active.Load() != 2 {
			t.Fatal("rehearsal terminating old contacts changed or live streams revoked")
		}
		h.pod("uid-new", "10.0.0.2") // same slot/IP, different socket/UID
		a = podEndpoint("fake-0", "uid-new", "10.0.0.2", true, false)
		h.apiState(200, a, b)
		h.discover(true)
		h.reports(0, false)
		for _, g := range h.gateways {
			members := g.r.Backends()
			if len(members) != 2 || members[0].Generation != "uid-new" || members[0].checked.Load() != 0 || members[0].Healthy() {
				t.Fatal("rehearsal replacement inherited old UID health")
			}
		}
		h.health()
		h.reports(2, true)
		h.capacity("new UID known; retained N=1 low", 3, "allowed")
		old.unblock()
		for i := range h.gateways {
			h.drain(responses[i], readers[i])
			if body := h.request(i, "completed"); !strings.Contains(body, "uid-new") {
				t.Fatal("rehearsal new UID not directly routed after sampling")
			}
		}
	})
	// The retained low must expire and THEN a full restoration interval elapse.
	time.Sleep(5100 * time.Millisecond)
	h.health()
	h.capacity("low expired; restoration starts", 3, "allowed")
	time.Sleep(60 * time.Millisecond)
	h.health()
	h.capacity("restoration complete", 6, "allowed")
	h.event("API-failure-and-recovery", [2][8]uint64{{2, 0, 0, 0, 0, 2}, {2, 0, 0, 0, 0, 2}}, func() {
		// Keep an established stream on each gateway across the unknown gap.
		current := h.pods[len(h.pods)-1]
		current.hold.Store(true)
		var responses [2]*http.Response
		var readers [2]*bufio.Reader
		for i := range h.gateways {
			responses[i], readers[i] = h.live(i, current.uid)
		}
		h.apiState(403)
		h.discover(false)
		h.reports(0, false)
		h.capacity("unknown preserves prior capacity until TTL", 6, "allowed")
		for i, g := range h.gateways {
			if len(g.r.Backends()) != 0 {
				t.Fatal("rehearsal API failure retained routes")
			}
			h.request(i, "discovery_unknown")
		}
		h.apiState(200, a, b)
		h.discover(true)
		h.reports(0, false)
		for i := range h.gateways {
			h.request(i, "discovery_unknown")
		}
		h.health()
		h.reports(2, true)
		h.capacity("API recovery independently known", 6, "allowed")
		current.unblock()
		for i := range h.gateways {
			h.drain(responses[i], readers[i])
			h.request(i, "completed")
		}
	})
	h.event("discovery-after-admit-race", [2][8]uint64{{0, 1}, {}}, func() {
		g := h.gateways[0]
		g.c.mu.Lock()
		g.c.after = func() {
			h.apiState(403)
			h.discover(false)
		}
		g.c.mu.Unlock()
		h.request(0, "discovery_unknown_after_admit")
		h.apiState(200, a, b)
		h.discover(true)
		h.reports(0, false)
		h.health()
		h.reports(2, true)
		h.capacity("after-admit recovery known", 6, "allowed")
	})
	h.event("membership-after-selection-race", [2][8]uint64{{0, 0, 1}, {}}, func() {
		h.gateways[0].g.backendSelection.router = &revalidationRaceRouter{after: func(*Backend) {
			h.apiState(200, b)
			if err := h.gateways[0].d.Poll(h.ctx); err != nil {
				t.Error(err)
			}
		}}
		h.request(0, "backend_membership_changed_after_admit")
		h.capacity("selected UID removed", 3, "allowed")
		h.gateways[0].g.backendSelection.router = &revalidationRaceRouter{after: func(*Backend) {}}
	})
	h.event("rollback-fresh-UID-and-SSE-control", [2][8]uint64{{0, 0, 0, 0, 0, 1, 1, 1}, {0, 0, 0, 0, 0, 1, 1, 1}}, func() {
		rollback := h.pod("uid-rollback", "10.0.0.2")
		a = podEndpoint("fake-0", "uid-rollback", "10.0.0.2", true, false)
		h.apiState(200, a, b)
		h.discover(true)
		for _, g := range h.gateways {
			members := g.r.Backends()
			if len(members) != 2 || members[0].Generation != rollback.uid || members[0].checked.Load() != 0 {
				t.Fatal("rehearsal rollback inherited UID health")
			}
		}
		h.reports(0, false)
		h.health()
		h.reports(2, true)
		h.capacity("rollback known; retained low", 3, "allowed")
		for i := range h.gateways {
			if body := h.request(i, "completed"); !strings.Contains(body, "uid-rollback") {
				t.Fatal("rehearsal rollback direct UID not observed")
			}
		}
		// DONE without finish+usage is not successful, even through ingress.
		rollback.badDone.Store(true)
		for i := range h.gateways {
			h.request(i, "stream_interrupted")
		}
	})
	h.event("known-zero", [2][8]uint64{{0, 0, 0, 0, 1}, {0, 0, 0, 0, 1}}, func() {
		h.apiState(200)
		h.discover(true)
		h.reports(0, true)
		h.capacity("known empty", 0, "system_capacity")
		for i := range h.gateways {
			h.request(i, "system_capacity")
		}
	})
	// Also assert the recorded startup prefix, not only the final count.
	for i, g := range h.gateways {
		g.mu.Lock()
		prefix := append([]m5Report(nil), g.reports[:2]...)
		g.mu.Unlock()
		if !reflect.DeepEqual(prefix, []m5Report{{0, false}, {2, true}}) {
			t.Fatalf("gateway=%d report sequence prefix=%+v", i, prefix)
		}
	}
}
