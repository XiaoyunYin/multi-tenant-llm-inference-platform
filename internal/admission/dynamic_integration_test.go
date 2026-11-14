package admission

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	redis "github.com/redis/go-redis/v9"
)

// Replay only Redis TIME's response, as in redis_ttl_integration_test.go.
// Every report, reconciliation, reservation and result executes in real Redis.
const redisTimeLine = "local server_time = redis.call('TIME')"

type phaseExpectationMismatch struct {
	phase int
	got   string
	want  string
}

func (e *phaseExpectationMismatch) Error() string {
	return fmt.Sprintf("phase %d: %s; want %s", e.phase, e.got, e.want)
}

func replayPhaseTime(source string, args []any, at int64) (string, []any, int, int, error) {
	if strings.Count(source, redisTimeLine) != 1 {
		return "", nil, 0, 0, fmt.Errorf("Redis TIME replay point missing or ambiguous")
	}
	replayIndex := len(args) + 1 // Lua ARGV indexes are one-based.
	args = append(args, 100000+at, 900000000)
	callerIndex := replayIndex + 1
	if replayIndex != len(args)-1 || callerIndex != len(args) {
		return "", nil, 0, 0, fmt.Errorf("replay clock argument count mismatch")
	}
	replay := fmt.Sprintf(
		"local server_time = {math.floor(tonumber(ARGV[%d])/1000), (tonumber(ARGV[%d])%%1000)*1000}",
		replayIndex,
		replayIndex,
	)
	return strings.Replace(source, redisTimeLine, replay, 1), args, replayIndex, callerIndex, nil
}

type capacityPhase struct {
	at          int64
	op, gateway string
	n, b        int64
	code        string
}

func runCapacityPhases(t *testing.T, source string, phases []capacityPhase, trace bool) error {
	t.Helper()
	client := redisIntegrationClient(t)
	c, _ := redisTestCoordinator(t, client, 99, 10*time.Second)
	c.config.DynamicCapacity = &DynamicCapacityConfig{Running: 2, Waiting: 1, ReportTTL: time.Second, HoldDown: 500 * time.Millisecond}
	ctx := context.Background()
	for i, p := range phases {
		id := fmt.Sprintf("rsv_%032x", i+1)
		tp := c.keyPrefix + "tenant:phase:"
		keys := []string{tp + "reservation:" + id, tp + "active", c.globalMemberKey, tp + "rate", c.keyPrefix + "config:global", tp + "config", c.keyPrefix + "capacity:reports", c.keyPrefix + "capacity:lows", c.keyPrefix + "capacity:state", c.keyPrefix + "capacity:report:" + p.gateway}
		args := []any{id, "phase:" + id, 1000, 60000, 1000, 99, 10000, 10000, 30000}
		args = append(args, c.capacityArgs(p.op, p.gateway, p.n)...)
		scriptSource, args, _, _, err := replayPhaseTime(source, args, p.at)
		if err != nil {
			return err
		}
		script := redis.NewScript(scriptSource)
		value, err := script.Run(ctx, client, keys, args...).Result()
		if err != nil {
			return fmt.Errorf("phase %d: %w", i, err)
		}
		got, err := parseAdmissionResult(value)
		if err != nil {
			return err
		}
		if trace {
			t.Logf("t=%d op=%s gateway=%s N=%d B=%d code=%s", p.at, p.op, p.gateway, p.n, got.Capacity, got.Decision.Code())
		}
		if got.Capacity != p.b || got.Decision.Code() != p.code {
			return &phaseExpectationMismatch{
				phase: i,
				got:   fmt.Sprintf("t=%d B=%d code=%s", p.at, got.Capacity, got.Decision.Code()),
				want:  fmt.Sprintf("t=%d B=%d code=%s", p.at, p.b, p.code),
			}
		}
		// Phase probes do not occupy slots. Separate fixtures assert drain/no revocation.
		if p.op == "admit" && got.Decision == Allowed {
			if err := c.Release(ctx, "phase", id); err != nil {
				return err
			}
		}
	}
	return nil
}

var participantExpiryPhases = []capacityPhase{
	{0, "report", "a", 2, 0, "allowed"}, {0, "report", "b", 2, 0, "allowed"},
	{300, "report", "b", 3, 0, "allowed"}, {700, "report", "b", 2, 0, "allowed"},
	{1000, "admit", "", 0, 0, "system_capacity"}, {1200, "admit", "", 0, 0, "system_capacity"},
	{1499, "admit", "", 0, 0, "system_capacity"}, {1500, "admit", "", 0, 6, "allowed"},
}

func TestRedisDynamicCapacityPhases(t *testing.T) {
	cases := []struct {
		name   string
		phases []capacityPhase
	}{
		{"candidate_ends_at_earliest_participant_expiry", participantExpiryPhases},
		{"fresh_agreement_and_asymmetric_minimum", []capacityPhase{
			{0, "report", "a", 2, 0, "allowed"}, {0, "report", "b", 2, 0, "allowed"},
			{499, "admit", "", 0, 0, "system_capacity"}, {500, "admit", "", 0, 6, "allowed"},
			{600, "report", "b", 1, 3, "allowed"}, {600, "admit", "", 0, 3, "allowed"},
		}},
		{"retained_low_disappearance_sole_fresh_and_full_recovery", []capacityPhase{
			{0, "report", "a", 1, 0, "allowed"}, {0, "report", "b", 1, 0, "allowed"}, {500, "admit", "", 0, 3, "allowed"},
			{600, "report", "b", 2, 3, "allowed"}, {999, "admit", "", 0, 3, "allowed"},
			{1000, "admit", "", 0, 3, "allowed"}, // equality: a expires; retained low remains
			{1400, "report", "b", 2, 3, "allowed"}, {1500, "admit", "", 0, 3, "allowed"},
			{1999, "admit", "", 0, 3, "allowed"}, {2000, "admit", "", 0, 6, "allowed"},
		}},
		{"all_expired_even_during_hold_down_and_restart", []capacityPhase{
			{0, "report", "a", 1, 0, "allowed"}, {500, "admit", "", 0, 3, "allowed"},
			{999, "admit", "", 0, 3, "allowed"}, {1000, "admit", "", 0, 3, "capacity_reports_expired"},
			{1100, "report", "b", 2, 3, "allowed"}, {1500, "admit", "", 0, 3, "allowed"},
			{1999, "admit", "", 0, 3, "allowed"}, {2000, "admit", "", 0, 6, "allowed"},
		}},
		{"unknown_low_interrupts_until_report_and_retention_end", []capacityPhase{
			{0, "report", "a", 1, 0, "allowed"}, {0, "report", "b", 1, 0, "allowed"}, {500, "admit", "", 0, 3, "allowed"},
			{600, "report", "b", 2, 3, "allowed"}, {700, "unknown", "a", 0, 3, "allowed"},
			{1000, "admit", "", 0, 3, "allowed"}, {1400, "report", "b", 2, 3, "allowed"},
			{1499, "unknown", "a", 0, 3, "allowed"}, {1500, "admit", "", 0, 3, "allowed"},
			{1700, "unknown", "a", 0, 3, "allowed"}, // DEC-071: no longer resets candidate
			{1999, "admit", "", 0, 3, "allowed"}, {2000, "admit", "", 0, 6, "allowed"},
		}},
		{"unknown_positive_interrupts_candidate_then_vanishes", []capacityPhase{
			{0, "report", "a", 2, 0, "allowed"}, {0, "report", "b", 2, 0, "allowed"},
			{400, "unknown", "a", 0, 0, "allowed"}, {500, "admit", "", 0, 0, "system_capacity"},
			{900, "report", "b", 2, 0, "allowed"}, {1000, "admit", "", 0, 0, "system_capacity"},
			{1200, "unknown", "a", 0, 0, "allowed"}, {1499, "admit", "", 0, 0, "system_capacity"},
			{1500, "admit", "", 0, 6, "allowed"},
		}},
		{"known_zero_is_real_and_higher_overwrite_retains_low", []capacityPhase{
			{0, "report", "a", 0, 0, "allowed"}, {0, "admit", "", 0, 0, "system_capacity"},
			{100, "report", "a", 2, 0, "allowed"}, {1000, "report", "a", 2, 0, "allowed"},
			{1500, "admit", "", 0, 0, "system_capacity"}, {1800, "report", "a", 2, 0, "allowed"},
			{2000, "admit", "", 0, 6, "allowed"},
		}},
		{"freshness_gap_cannot_restore_on_renewal", []capacityPhase{
			{0, "report", "a", 2, 0, "allowed"},
			{1200, "report", "a", 2, 0, "allowed"}, {1699, "admit", "", 0, 0, "system_capacity"},
			{1700, "admit", "", 0, 6, "allowed"},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := runCapacityPhases(t, admitLua, tc.phases, true); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRedisDynamicMutationSelfCheck(t *testing.T) {
	phases := []capacityPhase{{0, "report", "a", 2, 0, "allowed"}, {499, "admit", "", 0, 0, "system_capacity"}, {500, "admit", "", 0, 6, "allowed"}}
	fixture := &RedisCoordinator{config: RedisConfig{DynamicCapacity: &DynamicCapacityConfig{
		Running: 2, Waiting: 1, ReportTTL: time.Second, HoldDown: 500 * time.Millisecond,
	}}}
	args := []any{"rsv_fixture", "phase:rsv_fixture", 1000, 60000, 1000, 99, 10000, 10000, 30000}
	args = append(args, fixture.capacityArgs("admit", "", 0)...)
	_, _, _, callerClockIndex, err := replayPhaseTime(admitLua, args, 0)
	if err != nil {
		t.Fatal(err)
	}
	mutants := map[string]string{
		"no_until_check":        strings.Replace(admitLua, "candidate ~= minimum or now_ms >= until_ms", "candidate ~= minimum", 1),
		"caller_clock":          strings.Replace(admitLua, "local now_ms = tonumber(server_time[1]) * 1000 + math.floor(tonumber(server_time[2]) / 1000)", fmt.Sprintf("local now_ms = tonumber(ARGV[%d])", callerClockIndex), 1),
		"skip_restoration_hold": strings.Replace(admitLua, "now_ms - since >= hold", "now_ms - since >= 0", 1),
	}
	for name, source := range mutants {
		t.Run(name, func(t *testing.T) {
			if source == admitLua {
				t.Fatal("mutation point missing")
			}
			mutantPhases := phases
			if name == "no_until_check" {
				mutantPhases = participantExpiryPhases
			}
			err := runCapacityPhases(t, source, mutantPhases, false)
			var mismatch *phaseExpectationMismatch
			if !errors.As(err, &mismatch) {
				t.Fatal("mutant survived")
			} else {
				t.Logf("KILLED %s: %v", name, err)
			}
		})
	}
}

func TestRedisCoordinatorWithheldMarkerBlocksRestoration(t *testing.T) {
	client := redisIntegrationClient(t)
	c, _ := redisTestCoordinator(t, client, 99, 10*time.Second)
	c.config.DynamicCapacity = &DynamicCapacityConfig{Running: 2, Waiting: 1, ReportTTL: time.Second, HoldDown: 100 * time.Millisecond}
	// Replay only Redis TIME, as in the phase fixtures above. Unlike those
	// fixtures, every operation enters through the real Go coordinator, so a
	// dropped ReportHealthy(known=false) cannot bypass the behavioral oracle.
	clockKey := c.keyPrefix + "test:clock"
	clockLine := fmt.Sprintf("local test_ms = tonumber(redis.call('GET', '%s')); local server_time = {math.floor(test_ms/1000), (test_ms%%1000)*1000}", clockKey)
	if strings.Count(admitLua, redisTimeLine) != 1 {
		t.Fatal("Redis TIME replay point missing or ambiguous")
	}
	c.admitScript = redis.NewScript(strings.Replace(admitLua, redisTimeLine, clockLine, 1))
	ctx := context.Background()
	at := func(ms int64) {
		t.Helper()
		if err := client.Set(ctx, clockKey, 100000+ms, 0).Err(); err != nil {
			t.Fatal(err)
		}
	}
	report := func(gateway string, n int64, known bool) {
		t.Helper()
		if err := c.ReportHealthy(ctx, gateway, n, known); err != nil {
			t.Fatal(err)
		}
	}
	sequence := 0
	probe := func(want int64, phase string) {
		t.Helper()
		sequence++
		request := Request{TenantID: "withheld", ReservationID: fmt.Sprintf("rsv_%032x", sequence), Limits: Limits{RequestLimit: 100, RequestWindow: time.Minute, MaxConcurrent: 100}}
		got, err := c.Admit(ctx, request)
		if err != nil || got.Capacity != want || got.Decision != Allowed {
			t.Fatalf("%s: B=%d code=%s err=%v; want B=%d allowed", phase, got.Capacity, got.Decision.Code(), err, want)
		}
		if err := c.Release(ctx, request.TenantID, request.ReservationID); err != nil {
			t.Fatal(err)
		}
		t.Logf("%s: B=%d allowed", phase, got.Capacity)
	}
	at(0)
	report("a", 2, true)
	report("b", 2, true)
	at(100)
	probe(6, "initial agreement")
	at(200)
	report("a", 1, true)
	probe(3, "retained low")
	at(1100)
	report("a", 2, true) // fresh until 2100; old low retained until 1300
	report("b", 2, true)
	at(1150)
	report("a", 0, false)
	at(1300)
	report("b", 2, true)
	probe(3, "low expired, withheld report fresh")
	at(1400)
	probe(3, "fresh withheld marker must block restoration")
	at(2000)
	report("b", 2, true)
	at(2100) // equality expires a; b alone begins a new full agreement
	probe(3, "withheld report expired, hold starts")
	report("a", 0, false) // expired unknown must not restart agreement
	at(2199)
	probe(3, "post-expiry full hold not elapsed")
	at(2200)
	probe(6, "restored after withheld expiry and full hold")
	if client.ZCard(ctx, c.globalMemberKey).Val() != 0 {
		t.Fatal("withheld restoration probes leaked reservations")
	}
}

func TestRedisDynamicRealTimeDrainAndConcurrentClients(t *testing.T) {
	client := redisIntegrationClient(t)
	c, namespace := redisTestCoordinator(t, client, 99, 5*time.Second)
	config := c.config
	config.DynamicCapacity = &DynamicCapacityConfig{Running: 2, Waiting: 1, ReportTTL: 2 * time.Second, HoldDown: 40 * time.Millisecond}
	c, err := NewRedisCoordinator(client, config)
	if err != nil {
		t.Fatal(err)
	}
	other, err := NewRedisCoordinator(redisIntegrationClient(t), config)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	report := func(n int64) {
		t.Helper()
		if err := c.ReportHealthy(ctx, "a", n, true); err != nil {
			t.Fatal(err)
		}
	}
	report(2)
	time.Sleep(60 * time.Millisecond)
	var accepted atomic.Int64
	var wg sync.WaitGroup
	var mu sync.Mutex
	var admitted []Request
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			request := Request{TenantID: "drain", ReservationID: fmt.Sprintf("rsv_%032x", i+1), Limits: Limits{RequestLimit: 100, RequestWindow: time.Minute, MaxConcurrent: 100}}
			coord := c
			if i%2 == 1 {
				coord = other
			}
			got, err := coord.Admit(ctx, request)
			if err != nil {
				t.Error(err)
				return
			}
			if got.Capacity != 6 {
				t.Errorf("B=%d want6", got.Capacity)
			}
			if got.Decision == Allowed {
				accepted.Add(1)
				mu.Lock()
				admitted = append(admitted, request)
				mu.Unlock()
			} else if got.Decision != SystemCapacityLimited {
				t.Errorf("code=%s", got.Decision.Code())
			}
		}()
	}
	wg.Wait()
	if accepted.Load() != 6 {
		t.Fatalf("accepted=%d", accepted.Load())
	}
	report(1)
	probe := Request{TenantID: "drain", ReservationID: fmt.Sprintf("rsv_%032x", 100), Limits: admitted[0].Limits}
	got, err := c.Admit(ctx, probe)
	if err != nil || got.Capacity != 3 || got.Decision != SystemCapacityLimited || client.ZCard(ctx, c.globalMemberKey).Val() != 6 {
		t.Fatalf("drop revoked or oversubscribed: %+v %v", got, err)
	}
	t.Logf("drop B=%d code=%s active=6", got.Capacity, got.Decision.Code())
	// Withholding neither refreshes nor deletes the actual per-gateway TTL key.
	key := namespace + ":{admission}:capacity:report:a"
	before := client.PTTL(ctx, key).Val()
	if err := c.ReportHealthy(ctx, "a", 0, false); err != nil {
		t.Fatal(err)
	}
	after := client.PTTL(ctx, key).Val()
	if after > before || after <= 0 || client.Get(ctx, key).Val() != "1" {
		t.Fatal("unknown refreshed/deleted report")
	}
	time.Sleep(2100 * time.Millisecond)
	got, err = c.Admit(ctx, probe)
	if err != nil || got.Decision != CapacityReportsExpired || client.ZCard(ctx, c.globalMemberKey).Val() != 6 {
		t.Fatalf("expiry revoked or admitted: %+v %v", got, err)
	}
	t.Logf("expired B=%d code=%s active=6", got.Capacity, got.Decision.Code())
	// Renewing an existing reservation is permitted even with all reports expired.
	got, err = c.Admit(ctx, admitted[0])
	if err != nil || !got.Idempotent {
		t.Fatalf("drain renewal: %+v %v", got, err)
	}
	for _, request := range admitted {
		if err := c.Release(ctx, request.TenantID, request.ReservationID); err != nil {
			t.Fatal(err)
		}
	}
	if client.ZCard(ctx, c.globalMemberKey).Val() != 0 {
		t.Fatal("drain leaked")
	}
	t.Log("drained active=0; post-expiry new admissions refused")
}

func TestRedisDynamicConfigurationAndReportValidation(t *testing.T) {
	client := redisIntegrationClient(t)
	c, _ := redisTestCoordinator(t, client, 99, time.Second)
	config := c.config
	config.DynamicCapacity = &DynamicCapacityConfig{Running: 2, Waiting: 1, ReportTTL: time.Second, HoldDown: 500 * time.Millisecond}
	c, err := NewRedisCoordinator(client, config)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := c.ReportHealthy(ctx, "a", 2, true); err != nil {
		t.Fatal(err)
	}
	if client.PTTL(ctx, c.keyPrefix+"config:global").Val() != -1 {
		t.Fatal("dynamic config can expire")
	}
	for _, mutate := range []func(*RedisConfig){
		func(c *RedisConfig) { c.DynamicCapacity.Running++ }, func(c *RedisConfig) { c.DynamicCapacity.Waiting++ },
		func(c *RedisConfig) { c.DynamicCapacity.ReportTTL += time.Millisecond }, func(c *RedisConfig) { c.DynamicCapacity.HoldDown += time.Millisecond },
		func(c *RedisConfig) { c.DynamicCapacity = nil },
	} {
		changed := config
		d := *config.DynamicCapacity
		changed.DynamicCapacity = &d
		mutate(&changed)
		other, err := NewRedisCoordinator(client, changed)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := other.Admit(ctx, testRequest("config", 1)); err != ErrConfigurationMismatch {
			t.Fatalf("configuration crossed namespace: %v", err)
		}
	}
	for _, n := range []int64{-1, 1000001} {
		if err := c.ReportHealthy(ctx, "a", n, true); err == nil {
			t.Fatal("invalid healthy count accepted")
		}
	}
	if err := c.ReportHealthy(ctx, "bad id", 0, false); err == nil {
		t.Fatal("invalid gateway accepted")
	}
	for _, d := range []DynamicCapacityConfig{{}, {Running: 2, Waiting: 0, ReportTTL: time.Second, HoldDown: time.Second}, {Running: 2, Waiting: 1, ReportTTL: time.Nanosecond, HoldDown: time.Second}} {
		changed := config
		changed.DynamicCapacity = &d
		if _, err := NewRedisCoordinator(client, changed); err == nil {
			t.Fatalf("invalid dynamic inputs: %+v", d)
		}
	}
}
