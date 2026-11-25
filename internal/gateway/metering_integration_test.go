package gateway

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"multi-tenant-llm-inference-platform/internal/admission"

	"github.com/redis/go-redis/v9"
)

type afterGrant struct {
	*admission.RedisCoordinator
	after func(context.Context, admission.Request) error
}

var fixtureUnknownDecision = errors.New("fixture unknown grant reply")

func (c afterGrant) Admit(ctx context.Context, request admission.Request) (admission.Result, error) {
	result, err := c.RedisCoordinator.Admit(ctx, request)
	if err == nil && result.Decision == admission.Allowed {
		if err := c.after(ctx, request); err != nil {
			if errors.Is(err, fixtureUnknownDecision) {
				return admission.Result{Decision: admission.Decision(255)}, nil
			}
			return admission.Result{}, err
		}
	}
	return result, err
}

func TestMeteredAdmissionObligationAcrossGateways(t *testing.T) {
	if namespace := os.Getenv("METERING_CRASH_NAMESPACE"); namespace != "" {
		runMeteringCrashGateway(t, namespace)
		return
	}
	for _, scenario := range []string{"lost reply", "unknown decision", "duplicate grant", "pre-dispatch crash", "denial"} {
		t.Run(scenario, func(t *testing.T) {
			client, config := gatewayRedis(t)
			config.Metering = true
			if os.Getenv("METERING_TEST_DURABILITY") == "1" {
				if err := admission.CheckUsageDurability(context.Background(), client); err != nil {
					t.Fatal(err)
				}
			}
			config.GlobalCapacity = 1
			first, err := admission.NewRedisCoordinator(client, config)
			if err != nil {
				t.Fatal(err)
			}
			second, err := admission.NewRedisCoordinator(client, config)
			if err != nil {
				t.Fatal(err)
			}
			var dispatched atomic.Int64
			backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/health" {
					dispatched.Add(1)
				}
				streamHandler(contentEvent+finishEvent+doneEvent)(w, r)
			})
			var expectedKey atomic.Pointer[string]
			firstCoordinator := afterGrant{first, func(ctx context.Context, request admission.Request) error {
				key := request.TenantID + ":" + request.ReservationID
				expectedKey.Store(&key)
				switch scenario {
				case "lost reply":
					return errors.New("fixture lost reply after journal commit")
				case "unknown decision":
					return fixtureUnknownDecision
				case "duplicate grant":
					value, err := second.Admit(ctx, request)
					if err != nil || value.Decision != admission.Allowed || !value.Idempotent {
						t.Error("cross-gateway retry failed", value, err)
					}
				}
				return nil
			}}
			gatewayURL := ""
			if scenario != "pre-dispatch crash" {
				_, a := newTestGatewayWithAdmission(t, DefaultConfig(), nil, testTenantRegistry(t), firstCoordinator, backend)
				gatewayURL = a.URL
			}
			_, b := newTestGatewayWithAdmission(t, DefaultConfig(), nil, testTenantRegistry(t), second, backend)
			if scenario == "denial" {
				// Hold a single real grant across both replicas until the denial returns.
				held, err := second.Admit(context.Background(), admission.Request{TenantID: "tenant-test",
					ReservationID: "rsv_00000000000000000000000000000001", RequestID: "req_00000000000000000000000000000001",
					Limits: admission.Limits{RequestLimit: 10000, RequestWindow: time.Second, MaxConcurrent: 128}})
				if err != nil || held.Decision != admission.Allowed {
					t.Fatal("setup grant failed", held, err)
				}
				if status := managedRequest(t, gatewayURL, testCredential, managedBody); status != 429 {
					t.Fatalf("denial status %d", status)
				}
				if status := managedRequest(t, b.URL, testCredential, managedBody); status != 429 {
					t.Fatalf("second denial status %d", status)
				}
			} else if scenario == "pre-dispatch crash" {
				crashMeteringGateway(t, config.Namespace)
			} else {
				want := http.StatusOK
				if scenario == "lost reply" || scenario == "unknown decision" {
					want = http.StatusServiceUnavailable
				}
				if got := managedRequest(t, gatewayURL, testCredential, managedBody); got != want {
					t.Fatalf("status %d, want %d", got, want)
				}
			}
			report, err := second.ReconcileUsage(context.Background(), 10)
			if err != nil || report.Admitted != 1 || len(report.Orphaned) != 0 || len(report.Mismatched) != 0 {
				t.Fatalf("cohort report: %+v, %v", report, err)
			}
			expectedCalls := int64(0)
			if scenario == "duplicate grant" {
				expectedCalls = 1
				if report.Terminal != 1 || len(report.Missing) != 0 || len(report.Rows) != 1 ||
					!report.Rows[0].DispatchIntent || report.Rows[0].TenantID+":"+report.Rows[0].ReservationID != *expectedKey.Load() {
					t.Fatalf("closed cohort: %+v", report)
				}
			} else if scenario == "lost reply" || scenario == "unknown decision" {
				if len(report.Rows) != 1 || report.Terminal != 1 || len(report.Missing) != 0 ||
					report.Rows[0].DispatchIntent || report.Rows[0].StreamCommitted ||
					report.Rows[0].Outcome != "rejected" ||
					report.Rows[0].Prompt.Source != "no_dispatch" ||
					report.Totals["tenant-test"].Prompt.KnownZeroRows != 1 ||
					report.Totals["tenant-test"].Completion.KnownZeroRows != 1 {
					t.Fatalf("lost grant reply did not settle at exact zero: %+v", report)
				}
			} else {
				if report.Terminal != 0 || len(report.Missing) != 1 {
					t.Fatalf("open cohort: %+v", report)
				}
				if expected := expectedKey.Load(); expected != nil && *expected != report.Missing[0] {
					t.Fatal("journal join does not match the granted tenant and reservation")
				}
			}
			if dispatched.Load() != expectedCalls {
				t.Fatalf("upstream dispatches %d, want %d", dispatched.Load(), expectedCalls)
			}
		})
	}
}

func runMeteringCrashGateway(t *testing.T, namespace string) {
	client := redis.NewClient(&redis.Options{Addr: os.Getenv("REDIS_TEST_ADDR"), Protocol: 2, MaxRetries: -1})
	coordinator, err := admission.NewRedisCoordinator(client, admission.RedisConfig{
		Namespace: namespace, GlobalCapacity: 1, LeaseDuration: time.Second,
		TombstoneTTL: 2 * time.Second, Metering: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	crashing := afterGrant{coordinator, func(context.Context, admission.Request) error {
		os.Exit(71)
		return nil
	}}
	_, server := newTestGatewayWithAdmission(t, DefaultConfig(), nil, testTenantRegistry(t), crashing, streamHandler(contentEvent+finishEvent+doneEvent))
	fmt.Println(server.URL)
	select {}
}

func crashMeteringGateway(t *testing.T, namespace string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child := exec.CommandContext(ctx, executable, "-test.run", "^TestMeteredAdmissionObligationAcrossGateways$")
	child.Env = append(os.Environ(), "METERING_CRASH_NAMESPACE="+namespace)
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
		t.Fatal("crash gateway did not report its loopback listener")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, scanner.Text()+"/v1/chat/completions", strings.NewReader(managedBody))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+testCredential)
	response, err := http.DefaultClient.Do(request)
	if response != nil {
		response.Body.Close()
	}
	if err == nil {
		t.Fatal("crash fixture returned an HTTP response")
	}
	wait := child.Wait()
	waited = true
	var exit *exec.ExitError
	if !errors.As(wait, &exit) || exit.ExitCode() != 71 {
		t.Fatalf("crash gateway did not exit at the post-grant boundary: %v", wait)
	}
}
