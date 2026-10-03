package admission

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	redis "github.com/redis/go-redis/v9"
)

func redisIntegrationClient(t *testing.T) *redis.Client {
	t.Helper()
	address := os.Getenv("REDIS_TEST_ADDR")
	if address == "" {
		t.Skip("REDIS_TEST_ADDR is not set; real Redis integration is opt-in")
	}
	client := redis.NewClient(&redis.Options{
		Addr: address, Protocol: 2, MaxRetries: -1,
		DialTimeout: time.Second, ReadTimeout: time.Second, WriteTimeout: time.Second,
		ContextTimeoutEnabled: true,
	})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		client.Close()
		t.Fatalf("Redis integration endpoint is unavailable: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func redisTestCoordinator(t *testing.T, client *redis.Client, capacity int64, lease time.Duration) (*RedisCoordinator, string) {
	t.Helper()
	namespace := fmt.Sprintf("test:%x", time.Now().UnixNano())
	coordinator, err := NewRedisCoordinator(client, RedisConfig{
		Namespace: namespace, GlobalCapacity: capacity,
		LeaseDuration: lease, TombstoneTTL: max(lease, 2*time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		keys, _ := client.Keys(ctx, namespace+":*").Result()
		if len(keys) > 0 {
			_ = client.Del(ctx, keys...).Err()
		}
	})
	return coordinator, namespace
}

func TestRedisCoordinatorAtomicLimitsIdempotencyAndLeaseRecovery(t *testing.T) {
	client := redisIntegrationClient(t)
	coordinator, _ := redisTestCoordinator(t, client, 2, 120*time.Millisecond)
	ctx := context.Background()
	first := testRequest("tenant-a", 1)
	first.Limits = Limits{RequestLimit: 2, RequestWindow: time.Second, MaxConcurrent: 1}
	if result, err := coordinator.Admit(ctx, first); err != nil || result.Decision != Allowed || result.Idempotent {
		t.Fatalf("first admission mismatch: %+v %v", result, err)
	}
	if result, err := coordinator.Admit(ctx, first); err != nil || result.Decision != Allowed || !result.Idempotent {
		t.Fatalf("idempotent admission mismatch: %+v %v", result, err)
	}
	second := testRequest("tenant-a", 2)
	second.Limits = first.Limits
	if result, err := coordinator.Admit(ctx, second); err != nil || result.Decision != TenantConcurrencyLimited {
		t.Fatalf("tenant concurrency mismatch: %+v %v", result, err)
	}
	if err := coordinator.Release(ctx, first.TenantID, first.ReservationID); err != nil {
		t.Fatal(err)
	}
	if err := coordinator.Release(ctx, first.TenantID, first.ReservationID); err != nil {
		t.Fatalf("duplicate release failed: %v", err)
	}
	if _, err := coordinator.Admit(ctx, first); !errors.Is(err, ErrReservationReleased) {
		t.Fatalf("tombstone did not block delayed admit: %v", err)
	}
	if result, err := coordinator.Admit(ctx, second); err != nil || result.Decision != Allowed {
		t.Fatalf("released capacity was not reusable: %+v %v", result, err)
	}
	third := testRequest("tenant-a", 3)
	third.Limits = first.Limits
	if result, err := coordinator.Admit(ctx, third); err != nil || result.Decision != TenantRateLimited {
		t.Fatalf("rate charge was refunded by release: %+v %v", result, err)
	}
	leaseFirst := testRequest("tenant-lease", 4)
	leaseFirst.Limits = Limits{RequestLimit: 10, RequestWindow: time.Second, MaxConcurrent: 1}
	leaseSecond := testRequest("tenant-lease", 5)
	leaseSecond.Limits = leaseFirst.Limits
	if result, err := coordinator.Admit(ctx, leaseFirst); err != nil || result.Decision != Allowed {
		t.Fatalf("lease test admission mismatch: %+v %v", result, err)
	}
	if result, err := coordinator.Admit(ctx, leaseSecond); err != nil || result.Decision != TenantConcurrencyLimited {
		t.Fatalf("active lease was not counted: %+v %v", result, err)
	}
	time.Sleep(180 * time.Millisecond)
	if result, err := coordinator.Admit(ctx, leaseSecond); err != nil || result.Decision != Allowed {
		t.Fatalf("expired lease did not reclaim concurrency: %+v %v", result, err)
	}
}

func TestRedisCoordinatorSharesGlobalCapacityAcrossClientsAndScopesRelease(t *testing.T) {
	firstClient := redisIntegrationClient(t)
	secondClient := redisIntegrationClient(t)
	first, namespace := redisTestCoordinator(t, firstClient, 1, 2*time.Second)
	second, err := NewRedisCoordinator(secondClient, RedisConfig{
		Namespace: namespace, GlobalCapacity: 1, LeaseDuration: 2 * time.Second, TombstoneTTL: 2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	a := testRequest("tenant-a", 1)
	b := testRequest("tenant-b", 2)
	if result, err := first.Admit(ctx, a); err != nil || result.Decision != Allowed {
		t.Fatalf("first client admission mismatch: %+v %v", result, err)
	}
	if result, err := second.Admit(ctx, b); err != nil || result.Decision != SystemCapacityLimited {
		t.Fatalf("second client exceeded shared capacity: %+v %v", result, err)
	}
	if err := second.Release(ctx, "tenant-b", a.ReservationID); err != nil {
		t.Fatal(err)
	}
	if result, err := second.Admit(ctx, b); err != nil || result.Decision != SystemCapacityLimited {
		t.Fatalf("cross-tenant release freed capacity: %+v %v", result, err)
	}
	if err := first.Release(ctx, a.TenantID, a.ReservationID); err != nil {
		t.Fatal(err)
	}
	if result, err := second.Admit(ctx, b); err != nil || result.Decision != Allowed {
		t.Fatalf("valid release was not shared: %+v %v", result, err)
	}
}

func TestRedisCoordinatorConcurrentClientsDoNotOversubscribeTenant(t *testing.T) {
	firstClient := redisIntegrationClient(t)
	secondClient := redisIntegrationClient(t)
	first, namespace := redisTestCoordinator(t, firstClient, 10, 2*time.Second)
	second, err := NewRedisCoordinator(secondClient, RedisConfig{
		Namespace: namespace, GlobalCapacity: 10, LeaseDuration: 2 * time.Second, TombstoneTTL: 2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	coordinators := []*RedisCoordinator{first, second}
	const requestCount = 40
	start := make(chan struct{})
	var wait sync.WaitGroup
	var allowed atomic.Int32
	var denied atomic.Int32
	var failures atomic.Int32
	var admittedMu sync.Mutex
	admitted := make([]Request, 0, 3)
	for index := range requestCount {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			request := testRequest("tenant-shared", byte(index))
			request.ReservationID = fmt.Sprintf("rsv_%032x", index+1)
			request.Limits = Limits{RequestLimit: 100, RequestWindow: time.Second, MaxConcurrent: 3}
			result, err := coordinators[index%len(coordinators)].Admit(context.Background(), request)
			if err != nil {
				failures.Add(1)
				return
			}
			switch result.Decision {
			case Allowed:
				allowed.Add(1)
				admittedMu.Lock()
				admitted = append(admitted, request)
				admittedMu.Unlock()
			case TenantConcurrencyLimited:
				denied.Add(1)
			default:
				failures.Add(1)
			}
		}()
	}
	close(start)
	wait.Wait()
	if allowed.Load() != 3 || denied.Load() != requestCount-3 || failures.Load() != 0 {
		t.Fatalf("shared tenant bound violated: allowed=%d denied=%d failures=%d", allowed.Load(), denied.Load(), failures.Load())
	}
	for _, request := range admitted {
		if err := first.Release(context.Background(), request.TenantID, request.ReservationID); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRedisCoordinatorConcurrentClientsDoNotOversubscribeGlobalCapacity(t *testing.T) {
	firstClient := redisIntegrationClient(t)
	secondClient := redisIntegrationClient(t)
	first, namespace := redisTestCoordinator(t, firstClient, 3, 2*time.Second)
	second, err := NewRedisCoordinator(secondClient, RedisConfig{
		Namespace: namespace, GlobalCapacity: 3, LeaseDuration: 2 * time.Second, TombstoneTTL: 2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	coordinators := []*RedisCoordinator{first, second}
	const requestCount = 40
	start := make(chan struct{})
	var wait sync.WaitGroup
	var allowed atomic.Int32
	var denied atomic.Int32
	var failures atomic.Int32
	for index := range requestCount {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			request := testRequest(fmt.Sprintf("tenant-%d", index), byte(index))
			request.ReservationID = fmt.Sprintf("rsv_%032x", index+1)
			request.Limits = Limits{RequestLimit: 10, RequestWindow: time.Second, MaxConcurrent: 1}
			result, err := coordinators[index%len(coordinators)].Admit(context.Background(), request)
			if err != nil {
				failures.Add(1)
				return
			}
			switch result.Decision {
			case Allowed:
				allowed.Add(1)
			case SystemCapacityLimited:
				denied.Add(1)
			default:
				failures.Add(1)
			}
		}()
	}
	close(start)
	wait.Wait()
	if allowed.Load() != 3 || denied.Load() != requestCount-3 || failures.Load() != 0 {
		t.Fatalf("shared global bound violated: allowed=%d denied=%d failures=%d", allowed.Load(), denied.Load(), failures.Load())
	}
}

type dropSuccessfulReply struct {
	redis.Scripter
	dropped atomic.Bool
}

func (d *dropSuccessfulReply) Eval(ctx context.Context, script string, keys []string, args ...any) *redis.Cmd {
	return d.drop(d.Scripter.Eval(ctx, script, keys, args...))
}

func (d *dropSuccessfulReply) EvalSha(ctx context.Context, sha string, keys []string, args ...any) *redis.Cmd {
	return d.drop(d.Scripter.EvalSha(ctx, sha, keys, args...))
}

func (d *dropSuccessfulReply) drop(command *redis.Cmd) *redis.Cmd {
	_, err := command.Result()
	if err == nil && d.dropped.CompareAndSwap(false, true) {
		return redis.NewCmdResult(nil, context.DeadlineExceeded)
	}
	return command
}

func TestRedisCoordinatorUnknownResultIsReclaimableAndConfigurationMismatchFailsClosed(t *testing.T) {
	client := redisIntegrationClient(t)
	namespace := fmt.Sprintf("test:%x", time.Now().UnixNano())
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		keys, _ := client.Keys(ctx, namespace+":*").Result()
		if len(keys) > 0 {
			_ = client.Del(ctx, keys...).Err()
		}
	})
	dropper := &dropSuccessfulReply{Scripter: client}
	uncertain, err := NewRedisCoordinator(dropper, RedisConfig{
		Namespace: namespace, GlobalCapacity: 1, LeaseDuration: time.Second, TombstoneTTL: 2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := testRequest("tenant-a", 1)
	if _, err := uncertain.Admit(context.Background(), request); err == nil {
		t.Fatal("dropped successful reply was reported as a known admission result")
	}
	normal, err := NewRedisCoordinator(client, RedisConfig{
		Namespace: namespace, GlobalCapacity: 1, LeaseDuration: time.Second, TombstoneTTL: 2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := normal.Release(context.Background(), request.TenantID, request.ReservationID); err != nil {
		t.Fatalf("unknown result could not be reclaimed: %v", err)
	}
	if _, err := normal.Admit(context.Background(), request); !errors.Is(err, ErrReservationReleased) {
		t.Fatalf("release did not tombstone a late retry: %v", err)
	}
	mismatched, err := NewRedisCoordinator(client, RedisConfig{
		Namespace: namespace, GlobalCapacity: 2, LeaseDuration: time.Second, TombstoneTTL: 2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	other := testRequest("tenant-b", 2)
	if _, err := mismatched.Admit(context.Background(), other); !errors.Is(err, ErrConfigurationMismatch) {
		t.Fatalf("configuration mismatch did not fail closed: %v", err)
	}
	tenantMismatch := testRequest("tenant-a", 3)
	tenantMismatch.Limits.MaxConcurrent++
	if _, err := normal.Admit(context.Background(), tenantMismatch); !errors.Is(err, ErrConfigurationMismatch) {
		t.Fatalf("tenant configuration mismatch did not fail closed: %v", err)
	}
}

func TestRedisCoordinatorRefreshesNamespaceStateTTLs(t *testing.T) {
	client := redisIntegrationClient(t)
	coordinator, namespace := redisTestCoordinator(t, client, 2, time.Second)
	request := testRequest("tenant-ttl", 1)
	request.Limits = Limits{RequestLimit: 10, RequestWindow: time.Second, MaxConcurrent: 1}
	if result, err := coordinator.Admit(context.Background(), request); err != nil || result.Decision != Allowed {
		t.Fatalf("initial TTL admission failed: %+v %v", result, err)
	}
	ctx := context.Background()
	keys, err := client.Keys(ctx, namespace+":*").Result()
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range keys {
		ttl, ttlErr := client.PTTL(ctx, key).Result()
		if ttlErr != nil {
			t.Fatal(ttlErr)
		}
		if ttl <= 0 {
			t.Fatalf("state key %q has no bounded TTL: %s", key, ttl)
		}
	}
	configKey := namespace + ":{admission}:config:global"
	firstTTL, err := client.PTTL(ctx, configKey).Result()
	if err != nil {
		t.Fatal(err)
	}
	const stateTTL = 6 * time.Second // 3 * max(one-second lease, two-second tombstone)
	const refreshDelay = 80 * time.Millisecond
	time.Sleep(refreshDelay)
	if result, err := coordinator.Admit(ctx, request); err != nil || result.Decision != Allowed || !result.Idempotent {
		t.Fatalf("TTL refresh admission failed: %+v %v", result, err)
	}
	secondTTL, err := client.PTTL(ctx, configKey).Result()
	if err != nil {
		t.Fatal(err)
	}
	const ttlPrecisionAndSchedulingTolerance = 50 * time.Millisecond
	if secondTTL < stateTTL-ttlPrecisionAndSchedulingTolerance {
		t.Fatalf("state TTL was not refreshed near its configured bound: before=%dms after=%dms; expected at least %dms after %s delay", firstTTL.Milliseconds(), secondTTL.Milliseconds(), (stateTTL - ttlPrecisionAndSchedulingTolerance).Milliseconds(), refreshDelay)
	}
}
