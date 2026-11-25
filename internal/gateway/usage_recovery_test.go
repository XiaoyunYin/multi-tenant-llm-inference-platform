package gateway

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"

	"multi-tenant-llm-inference-platform/internal/admission"

	"github.com/redis/go-redis/v9"
)

type persistedMeterRedis struct {
	name, address string
	client        *redis.Client
}

func newPersistedMeterRedis(t *testing.T) persistedMeterRedis {
	t.Helper()
	if os.Getenv("METERING_TEST_DURABILITY") != "1" || os.Getenv("REDIS_TEST_ADDR") == "" {
		t.Skip("requires the routine durable Redis and Docker environment")
	}
	var pins struct {
		RedisImage string `json:"redis_image"`
	}
	raw, err := os.ReadFile("../../deploy/package-a/pins.json")
	if err != nil || json.Unmarshal(raw, &pins) != nil || pins.RedisImage == "" {
		t.Fatal("cannot read pinned Redis image", err)
	}
	name := newID("metering")
	// Docker can assign a different port to an ephemeral publish on start.
	// Choose the loopback port here and put the explicit binding in the
	// container config so the same gateways can reconnect after the outage.
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	dockerMeter(t, "run", "-d", "--name", name, "-p", address+":6379", pins.RedisImage,
		"redis-server", "--appendonly", "yes", "--appendfsync", "always", "--maxmemory-policy", "noeviction")
	t.Cleanup(func() { dockerMeter(t, "rm", "-fv", name) })
	client := redis.NewClient(&redis.Options{Addr: address, Protocol: 2, MaxRetries: -1,
		ReadTimeout: time.Second, WriteTimeout: time.Second, DialTimeout: time.Second, ContextTimeoutEnabled: true})
	t.Cleanup(func() { client.Close() })
	result := persistedMeterRedis{name: name, address: address, client: client}
	result.ready(t)
	return result
}

func dockerMeter(t *testing.T, args ...string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	raw, err := exec.CommandContext(ctx, "docker", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("fixture docker %s: %v (%s)", args[0], err, raw)
	}
	return strings.TrimSpace(string(raw))
}

func (r persistedMeterRedis) ready(t *testing.T) {
	t.Helper()
	if got := dockerMeter(t, "port", r.name, "6379/tcp"); got != r.address {
		t.Fatal("Redis fixture loopback publish changed across restart")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for r.client.Ping(ctx).Err() != nil && ctx.Err() == nil {
		time.Sleep(20 * time.Millisecond)
	}
	if err := admission.CheckUsageDurability(ctx, r.client); err != nil {
		t.Fatalf("Redis fixture not ready (container %s): %v",
			dockerMeter(t, "inspect", "--format", "{{.State.Status}}", r.name), err)
	}
}

func (r persistedMeterRedis) restart(t *testing.T) {
	t.Helper()
	dockerMeter(t, "stop", "--time", "1", r.name)
	dockerMeter(t, "start", r.name)
	r.ready(t)
}

func meterStore(t *testing.T, client *redis.Client, config admission.RedisConfig) *admission.RedisCoordinator {
	t.Helper()
	result, err := admission.NewRedisCoordinator(client, config)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

type crashUsageGateway struct {
	*admission.RedisCoordinator
	at string
}

func (c crashUsageGateway) Admit(ctx context.Context, req admission.Request) (admission.Result, error) {
	result, err := c.RedisCoordinator.Admit(ctx, req)
	if c.at == "before_intent" && err == nil && result.Decision == admission.Allowed {
		killUsageFixture()
	}
	return result, err
}

func (c crashUsageGateway) BeginUsageDispatch(ctx context.Context, attempt admission.UsageAttempt, pins admission.UsagePins) error {
	err := c.RedisCoordinator.BeginUsageDispatch(ctx, attempt, pins)
	if c.at == "intent_before_write" && err == nil {
		killUsageFixture()
	}
	return err
}

func (c crashUsageGateway) CheckpointUsage(ctx context.Context, attempt admission.UsageAttempt, point admission.UsageCheckpoint) error {
	err := c.RedisCoordinator.CheckpointUsage(ctx, attempt, point)
	if c.at == "usage_before_done" && err == nil {
		killUsageFixture()
	}
	return err
}

func (c crashUsageGateway) FinalizeUsage(ctx context.Context, attempt admission.UsageAttempt, pins admission.UsagePins, outcome string, committed bool) (admission.UsageTerminal, error) {
	row, err := c.RedisCoordinator.FinalizeUsage(ctx, attempt, pins, outcome, committed)
	if c.at == "terminal_before_ack" && err == nil {
		killUsageFixture()
	}
	return row, err
}

func killUsageFixture() {
	self, err := os.FindProcess(os.Getpid())
	if err == nil {
		_ = self.Kill()
	}
	os.Exit(87)
}

func crashUsageChild(t *testing.T, boundary string) {
	client := redis.NewClient(&redis.Options{Addr: os.Getenv("METERING_DURABLE_FIXTURE_ADDR"), Protocol: 2, MaxRetries: -1})
	config := crashMeterConfig(os.Getenv("METERING_DURABLE_FIXTURE_NAMESPACE"))
	store := meterStore(t, client, config)
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusOK)
			return
		}
		fmt.Println("inference_reached")
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, contentEvent)
		w.(http.Flusher).Flush()
		if boundary == "mid_stream" {
			<-r.Context().Done()
			return
		}
		_, _ = io.WriteString(w, finishEvent+usageEvent+doneEvent)
	})
	_, server := newTestGatewayWithAdmission(t, DefaultConfig(), nil, testTenantRegistry(t), crashUsageGateway{store, boundary}, backend)
	fmt.Println(server.URL)
	select {}
}

func crashMeterConfig(namespace string) admission.RedisConfig {
	return admission.RedisConfig{Namespace: namespace, GlobalCapacity: 1, Metering: true,
		LeaseDuration: 250 * time.Millisecond, TombstoneTTL: 500 * time.Millisecond}
}

func driveUsageCrash(t *testing.T, config admission.RedisConfig, address, boundary string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child := exec.CommandContext(ctx, executable, "-test.run", "^TestMeterRecoveryAfterKill$")
	child.Env = append(os.Environ(), "METERING_DURABLE_FIXTURE_ADDR="+address,
		"METERING_DURABLE_FIXTURE_NAMESPACE="+config.Namespace, "METERING_FIXTURE_BOUNDARY="+boundary)
	child.Stderr = os.Stderr
	stdout, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	defer func() {
		cancel()
		if !waited {
			_ = child.Wait()
		}
	}()
	scanner := bufio.NewScanner(stdout)
	if !scanner.Scan() || !strings.HasPrefix(scanner.Text(), "http://127.0.0.1:") {
		t.Fatal("fixture gateway did not open a loopback listener")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, scanner.Text()+"/v1/chat/completions", strings.NewReader(managedBody))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+testCredential)
	response, err := http.DefaultClient.Do(req)
	if boundary == "mid_stream" {
		if err != nil || response.StatusCode != 200 {
			t.Fatalf("midstream fixture did not start: %v", err)
		}
		if _, err := io.ReadFull(response.Body, make([]byte, 1)); err != nil {
			t.Fatal(err)
		}
		if err := child.Process.Kill(); err != nil {
			t.Fatal(err)
		}
	} else if response != nil {
		_, _ = io.Copy(io.Discard, response.Body)
	}
	if response != nil {
		response.Body.Close()
	}
	contacts := 0
	for scanner.Scan() {
		if scanner.Text() == "inference_reached" {
			contacts++
		}
	}
	waited = true
	var exit *exec.ExitError
	if err := child.Wait(); !errors.As(err, &exit) || exit.ExitCode() != -1 || ctx.Err() != nil {
		t.Fatalf("fixture gateway was not killed at its boundary: %v", err)
	}
	want := 1
	if boundary == "before_intent" || boundary == "intent_before_write" {
		want = 0
	}
	if contacts != want {
		t.Fatalf("inference contacts at %s: got %d, want %d", boundary, contacts, want)
	}
}

func shiftUsageDeadline(t *testing.T, client *redis.Client, store *admission.RedisCoordinator, key string, offset time.Duration, open bool) {
	t.Helper()
	ctx := context.Background()
	now, err := client.Time(ctx).Result()
	if err != nil {
		t.Fatal(err)
	}
	prefix := strings.TrimSuffix(store.CredentialKey(""), "credential:")
	deadline := redis.Z{Member: key, Score: float64(now.Add(offset).UnixMilli())}
	if err := client.ZAdd(ctx, prefix+"usage:deadlines", deadline).Err(); err != nil {
		t.Fatal(err)
	}
	if open {
		if err := client.ZAdd(ctx, prefix+"usage:open-deadlines", deadline).Err(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestMeterRecoveryAfterKill(t *testing.T) {
	if boundary := os.Getenv("METERING_FIXTURE_BOUNDARY"); boundary != "" {
		crashUsageChild(t, boundary)
		return
	}
	r := newPersistedMeterRedis(t)
	ctx := context.Background()
	for _, tc := range []struct{ at, classification string }{
		{"before_intent", "exact"},
		{"intent_before_write", "unknown"},
		{"mid_stream", "unknown"},
		{"usage_before_done", "observed_partial"},
		{"terminal_before_ack", "exact"},
	} {
		t.Run(tc.at, func(t *testing.T) {
			config := crashMeterConfig(newID("recovery"))
			driveUsageCrash(t, config, r.address, tc.at)
			r.restart(t)
			store := meterStore(t, r.client, config)
			if err := store.PrepareUsageMaintenance(ctx); err != nil {
				t.Fatal(err)
			}
			report := meterReport(t, store)
			if report.Admitted != 1 {
				t.Fatalf("AOF did not retain the single obligation: %+v", report)
			}
			if tc.at != "terminal_before_ack" {
				if len(report.Missing) != 1 {
					t.Fatalf("crashed attempt already has a terminal: %+v", report)
				}
				key := report.Missing[0]
				shiftUsageDeadline(t, r.client, store, key, -59*time.Second, true)
				if n, err := store.SweepUsage(ctx, 1); err != nil || n != 0 {
					t.Fatalf("sweep ran before grace: %d %v", n, err)
				}
				shiftUsageDeadline(t, r.client, store, key, -61*time.Second, true)
				if n, err := store.SweepUsage(ctx, 1); err != nil || n != 1 {
					t.Fatalf("restarted sweep: %d %v", n, err)
				}
				report = meterReport(t, store)
			}
			if report.Terminal != 1 || len(report.Rows) != 1 || len(report.Missing)+len(report.Orphaned)+len(report.Mismatched) != 0 {
				t.Fatalf("closed sets differ: %+v", report)
			}
			row := report.Rows[0]
			if row.Prompt.Classification != tc.classification || row.Completion.Classification != tc.classification ||
				row.DispatchIntent == (tc.at == "before_intent") ||
				(tc.at == "before_intent" && row.Prompt.Source != "no_dispatch") {
				t.Fatalf("incorrect recovered count: %+v", row)
			}
			pins := admission.UsagePins{Model: "test-model"}
			if tc.at == "terminal_before_ack" {
				replay, err := store.FinalizeUsage(ctx, row.UsageAttempt, pins, "completed", true)
				if err != nil || !reflect.DeepEqual(replay, row) {
					t.Fatalf("terminal acknowledgement replay: %+v %v", replay, err)
				}
			} else {
				if row.Outcome != "owner_lost" {
					t.Fatalf("recovered row cause: %+v", row)
				}
				if err := store.BeginUsageDispatch(ctx, row.UsageAttempt, pins); !errors.Is(err, admission.ErrUsageConflict) {
					t.Fatalf("stale dispatch owner was not fenced: %v", err)
				}
			}
			if n, err := store.SweepUsage(ctx, 1); err != nil || n != 0 {
				t.Fatalf("sweep was not idempotent: %d %v", n, err)
			}
			if row.AdmittedUnixMS == nil {
				t.Fatal("missing durable admission timestamp")
			}
			now, err := r.client.Time(ctx).Result()
			if err != nil {
				t.Fatal(err)
			}
			time.Sleep(max(0, time.UnixMilli(*row.AdmittedUnixMS).Add(config.LeaseDuration).Sub(now)))
			// A real replacement gateway can use the released or expired lease
			// while the first admitted identity remains in the ledger.
			_, alternate := newTestGatewayWithAdmission(t, DefaultConfig(), nil, testTenantRegistry(t), store,
				streamHandler(contentEvent+finishEvent+usageEvent+doneEvent))
			if status := managedRequest(t, alternate.URL, testCredential, managedBody); status != 200 {
				t.Fatalf("replacement gateway status %d", status)
			}
			final := meterReport(t, store)
			if final.Admitted != 2 || final.Terminal != 2 || len(final.Rows) != 2 {
				t.Fatalf("replacement cohort does not reconcile: %+v", final)
			}
		})
	}
	t.Run("legacy_obligations", func(t *testing.T) {
		config := crashMeterConfig(newID("legacy"))
		store := meterStore(t, r.client, config)
		prefix := strings.TrimSuffix(store.CredentialKey(""), "credential:")
		known := fixtureMeterAttempt("tenant-one", newID("rsv"), newID("owner"))
		unknown := fixtureMeterAttempt("tenant-two", newID("rsv"), newID("owner"))
		knownKey, unknownKey := known.TenantID+":"+known.ReservationID, unknown.TenantID+":"+unknown.ReservationID
		now, err := r.client.Time(ctx).Result()
		if err != nil {
			t.Fatal(err)
		}
		at := now.Add(-2 * time.Minute).UnixMilli()
		if err := r.client.HSet(ctx, prefix+"usage:admitted", knownKey, known.RequestID, unknownKey, unknown.RequestID).Err(); err != nil {
			t.Fatal(err)
		}
		if err := r.client.HSet(ctx, prefix+"usage:admitted-at", knownKey, at).Err(); err != nil {
			t.Fatal(err)
		}
		if err := store.PrepareUsageMaintenance(ctx); err != nil {
			t.Fatal(err)
		}
		if n, err := store.SweepUsage(ctx, 1); err != nil || n != 1 {
			t.Fatalf("known legacy deadline: %d %v", n, err)
		}
		report := meterReport(t, store)
		if len(report.Rows) != 1 || report.Rows[0].AdmissionDeadlineUnixMS == nil ||
			*report.Rows[0].AdmissionDeadlineUnixMS != at+config.LeaseDuration.Milliseconds() ||
			len(report.Missing) != 1 || report.Missing[0] != unknownKey {
			t.Fatalf("legacy deadline migration: %+v", report)
		}
		if err := r.client.ZAdd(ctx, prefix+"usage:open-deadlines", redis.Z{Member: unknownKey, Score: float64(now.Add(-2 * time.Minute).UnixMilli())}).Err(); err != nil {
			t.Fatal(err)
		}
		if n, err := store.SweepUsage(ctx, 1); err != nil || n != 1 {
			t.Fatalf("conservative legacy wait: %d %v", n, err)
		}
		report = meterReport(t, store)
		if len(report.Rows) != 2 || report.Rows[1].AdmissionDeadlineUnixMS != nil || report.Rows[1].Prompt.Source != "no_dispatch" {
			t.Fatalf("unknown legacy time was invented: %+v", report)
		}
	})
}
