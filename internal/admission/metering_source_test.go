package admission

import (
	"strings"
	"testing"
)

func TestMeteredAdmissionSourceReplacements(t *testing.T) {
	for i := 0; i < len(meteringReplacements); i += 2 {
		target := meteringReplacements[i]
		if count := strings.Count(admitLua, target); count != 1 {
			t.Errorf("replacement %d matches %d sites: %q", i/2, count, target)
		}
	}
	metered := admissionSource(true)
	for _, guard := range []string{
		"local usage_key = KEYS[11]",
		"local usage_id = ARGV[22]",
		"if prior_usage and prior_usage ~= usage_id then return {'config_mismatch', 0, 0} end",
		"global_config = global_config .. '|metered'",
		"\nredis.call('PERSIST', KEYS[5])\n",
		"if not prior_usage then return {'config_mismatch', 0, 0} end",
		"if prior_usage then return {'released', 0, 0} end",
		"redis.call('HSET', usage_key, ARGV[2], usage_id)",
		"redis.call('HGET', KEYS[12], ARGV[2])",
		"redis.call('HSET', KEYS[12], ARGV[2], now_ms)",
		"redis.call('ZADD', KEYS[13], usage_deadline, ARGV[2])",
		"redis.call('ZADD', KEYS[14], usage_deadline, ARGV[2])",
		"redis.call('HEXISTS', KEYS[15], ARGV[2])",
	} {
		if count := strings.Count(metered, guard); count != 1 {
			t.Errorf("metered guard %q appears %d times", guard, count)
		}
	}
	if strings.Contains(metered, "redis.call('PEXPIRE', KEYS[5],") {
		t.Error("metered global config still expires")
	}
}
