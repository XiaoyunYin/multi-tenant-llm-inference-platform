package admission

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/redis/go-redis/v9"
)

const usagePreflight = `
local usage_key = KEYS[11]
local usage_id = ARGV[22]
local prior_usage
if ARGV[15] == 'admit' then
  prior_usage = redis.call('HGET', usage_key, ARGV[2])
  if prior_usage and prior_usage ~= usage_id then return {'config_mismatch', 0, 0} end
end
`

const globalConfigExpiry = "if not dynamic and not managed then redis.call('PEXPIRE', KEYS[5], ARGV[9]) end\n"

// Each target identifies a single site in the original script.
var meteringReplacements = []string{
	"local dynamic = ", usagePreflight + "\nlocal dynamic = ",
	"if managed then global_config = global_config .. '|managed' end", "if managed then global_config = global_config .. '|managed' end\nglobal_config = global_config .. '|metered'",
	"if managed then redis.call('PERSIST', KEYS[5]) end", "redis.call('PERSIST', KEYS[5])",
	"redis.call('SETNX', KEYS[6], tenant_config)\n" + globalConfigExpiry,
	"redis.call('SETNX', KEYS[6], tenant_config)\n",
	globalConfigExpiry + "redis.call('PEXPIRE', KEYS[6], ARGV[9])\nredis.call('PEXPIRE', KEYS[2], ARGV[9])",
	"redis.call('PEXPIRE', KEYS[6], ARGV[9])\nredis.call('PEXPIRE', KEYS[2], ARGV[9])",
	"if reservation_state == 'active' then", "if reservation_state == 'active' then\n  if not prior_usage then return {'config_mismatch', 0, 0} end",
	"local new_rate_count = ", "if prior_usage then return {'released', 0, 0} end\nredis.call('HSET', usage_key, ARGV[2], usage_id)\nlocal new_rate_count = ",
}

// Select the original script directly for every mode-off operation. The metered
// version is derived from the same grant logic, including its denial branches.
func admissionSource(metering bool) string {
	if !metering {
		return admitLua
	}
	return strings.NewReplacer(meteringReplacements...).Replace(admitLua)
}

// CheckUsageDurability verifies the supported single-primary persistence mode.
func CheckUsageDurability(ctx context.Context, client *redis.Client) error {
	for key, want := range map[string]string{"appendonly": "yes", "appendfsync": "always", "maxmemory-policy": "noeviction"} {
		settings, err := client.ConfigGet(ctx, key).Result()
		if err != nil {
			return fmt.Errorf("read metering persistence settings: %w", err)
		}
		if settings[key] != want {
			return errors.New("metering requires Redis AOF, appendfsync always and noeviction")
		}
	}
	return nil
}

type UsageReconciliation struct {
	Admitted   int
	Terminal   int
	Missing    []string
	Orphaned   []string
	Mismatched []string
}

// The namespace is one cohort. The terminal hash is reserved for the next
// slice. No synthetic success is written to cover a missing terminal record.
var readUsage = redis.NewScript(`
if redis.call('HLEN', KEYS[1]) + redis.call('HLEN', KEYS[2]) > tonumber(ARGV[1]) then
  return redis.error_reply('usage reconciliation exceeds row limit')
end
return {redis.call('HGETALL', KEYS[1]), redis.call('HGETALL', KEYS[2])}`)

func (c *RedisCoordinator) ReconcileUsage(ctx context.Context, limit int) (UsageReconciliation, error) {
	if !c.config.Metering || limit < 1 || limit > 10000 {
		return UsageReconciliation{}, errors.New("metering and bounded reconciliation limit required")
	}
	raw, err := readUsage.Run(ctx, c.client, []string{c.keyPrefix + "usage:admitted", c.keyPrefix + "usage:terminal"}, limit).Slice()
	if err != nil {
		return UsageReconciliation{}, err
	}
	rows := [2]map[string]string{}
	for i, list := range raw {
		values := list.([]any)
		rows[i] = make(map[string]string, len(values)/2)
		for j := 0; j < len(values); j += 2 {
			rows[i][values[j].(string)] = values[j+1].(string)
		}
	}
	admitted, terminal := rows[0], rows[1]
	result := UsageReconciliation{Admitted: len(admitted), Terminal: len(terminal)}
	for key, id := range admitted {
		value, ok := terminal[key]
		if !ok {
			result.Missing = append(result.Missing, key)
		} else if value != id {
			result.Mismatched = append(result.Mismatched, key)
		}
	}
	for key := range terminal {
		if _, ok := admitted[key]; !ok {
			result.Orphaned = append(result.Orphaned, key)
		}
	}
	sort.Strings(result.Missing)
	sort.Strings(result.Orphaned)
	sort.Strings(result.Mismatched)
	return result, nil
}
