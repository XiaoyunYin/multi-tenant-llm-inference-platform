package admission

import (
	"context"
	"strings"
	"testing"
	"time"

	redis "github.com/redis/go-redis/v9"
)

func TestRedisRateTTLBoundary(t *testing.T) {
	client := redisIntegrationClient(t)
	// Replay a Redis PTTL boundary deterministically in the real embedded Lua.
	// Only the external clock response changes; all admission mutations and
	// parsing execute against real Redis. Timing a live last millisecond would
	// make this regression probabilistic.
	expression := "local rate_ttl = redis.call('PTTL', KEYS[4])"
	if strings.Count(admitLua, expression) != 1 {
		t.Fatal("PTTL injection point changed")
	}
	script := strings.Replace(admitLua, expression, "local rate_ttl = tonumber(ARGV[10])", 1)
	for _, tc := range []struct {
		name    string
		ttl     int64
		limit   int64
		want    Decision
		invalid bool
	}{
		{"zero_below_quota", 0, 2, Allowed, false},
		{"zero_at_quota", 0, 1, TenantRateLimited, false},
		{"persistent_positive_count", -1, 2, 0, true},
		{"missing_positive_count", -2, 2, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := redisTestCoordinator(t, client, 2, time.Second)
			request := testRequest("ttl-boundary", 1)
			request.Limits = Limits{RequestLimit: tc.limit, RequestWindow: time.Second, MaxConcurrent: 1}
			prefix := c.keyPrefix + "tenant:" + request.TenantID + ":"
			if err := client.Set(context.Background(), prefix+"rate", 1, time.Second).Err(); err != nil {
				t.Fatal(err)
			}
			keys := []string{prefix + "reservation:" + request.ReservationID, prefix + "active", c.globalMemberKey, prefix + "rate", c.keyPrefix + "config:global", prefix + "config"}
			value, err := redis.NewScript(script).Run(context.Background(), client, keys,
				request.ReservationID, request.TenantID+":"+request.ReservationID,
				request.Limits.RequestLimit, durationMilliseconds(request.Limits.RequestWindow),
				request.Limits.MaxConcurrent, c.config.GlobalCapacity,
				durationMilliseconds(c.config.LeaseDuration), durationMilliseconds(c.config.TombstoneTTL), c.stateTTLMS, tc.ttl).Result()
			if tc.invalid {
				if err == nil || !strings.Contains(err.Error(), "invalid rate state") {
					t.Fatalf("invalid state admitted: %v %v", value, err)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				result, err := parseAdmissionResult(value)
				if err != nil || result.Decision != tc.want {
					t.Fatalf("boundary result: %+v %v", result, err)
				}
			}
			active, err := client.ZCard(context.Background(), c.globalMemberKey).Result()
			want := int64(0)
			if !tc.invalid && tc.want == Allowed {
				want = 1
			}
			if err != nil || active != want {
				t.Fatalf("active=%d want=%d err=%v", active, want, err)
			}
			if active != 0 {
				if err := c.Release(context.Background(), request.TenantID, request.ReservationID); err != nil {
					t.Fatal(err)
				}
				if n := client.ZCard(context.Background(), c.globalMemberKey).Val(); n != 0 {
					t.Fatalf("reservation leaked: %d", n)
				}
			}
		})
	}
}
