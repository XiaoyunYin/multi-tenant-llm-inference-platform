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
	} {
		if count := strings.Count(metered, guard); count != 1 {
			t.Errorf("metered guard %q appears %d times", guard, count)
		}
	}
	if strings.Contains(metered, "redis.call('PEXPIRE', KEYS[5],") {
		t.Error("metered global config still expires")
	}
}
