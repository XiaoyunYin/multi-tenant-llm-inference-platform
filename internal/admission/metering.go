package admission

import (
	"context"
	"encoding/json"
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
  -- Preflight the timestamp hash before the first grant mutates either hash.
  redis.call('HGET', KEYS[12], ARGV[2])
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
	"local new_rate_count = ", "if prior_usage then return {'released', 0, 0} end\nredis.call('HSET', usage_key, ARGV[2], usage_id)\nredis.call('HSET', KEYS[12], ARGV[2], now_ms)\nlocal new_rate_count = ",
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
	Admitted      int
	Terminal      int
	Missing       []string
	Orphaned      []string
	Mismatched    []string
	Rows          []UsageTerminal
	Totals        map[string]UsageTotals
	Discrepancies []UsageDiscrepancy
}

type UsageDiscrepancy struct {
	TenantID   string `json:"tenant_id"`
	AttemptKey string `json:"attempt_key"`
	Cause      string `json:"cause"`
}

type UsageFieldTotals struct {
	ExactTokens           int64
	ExactRows             int
	KnownZeroRows         int
	UnknownRows           int
	ObservedPartialRows   int
	ObservedPartialTokens int64
	EstimateRows          int
	EstimateTokens        int64
}

type UsageTotals struct {
	Prompt        UsageFieldTotals
	Completion    UsageFieldTotals
	Discrepancies int
}

func (total *UsageFieldTotals) add(count UsageCount, estimate *int64) {
	switch count.Classification {
	case "exact":
		total.ExactRows++
		total.ExactTokens += *count.Tokens
		if *count.Tokens == 0 {
			total.KnownZeroRows++
		}
	case "observed_partial":
		total.ObservedPartialRows++
		total.ObservedPartialTokens += *count.Tokens
	case "unknown":
		total.UnknownRows++
	}
	if estimate != nil {
		total.EstimateRows++
		total.EstimateTokens += *estimate
	}
}

func validUsageCount(count UsageCount) bool {
	switch count.Classification {
	case "exact", "observed_partial":
		return count.Tokens != nil && *count.Tokens >= 0 && *count.Tokens <= 1<<31-1
	case "unknown":
		return count.Tokens == nil
	default:
		return false
	}
}

// Read a bounded snapshot of the cohort without mutating open or closed rows.
var readUsage = redis.NewScript(`
local limit = tonumber(ARGV[1])
if redis.call('HLEN', KEYS[1]) + redis.call('HLEN', KEYS[2]) > limit
  or redis.call('HLEN', KEYS[3]) > limit or redis.call('HLEN', KEYS[4]) > limit then
  return redis.error_reply('usage reconciliation exceeds row limit')
end
return {redis.call('HGETALL', KEYS[1]), redis.call('HGETALL', KEYS[2]),
  redis.call('HGETALL', KEYS[3]), redis.call('HGETALL', KEYS[4])}`)

func (c *RedisCoordinator) ReconcileUsage(ctx context.Context, limit int) (UsageReconciliation, error) {
	if !c.config.Metering || limit < 1 || limit > 10000 {
		return UsageReconciliation{}, errors.New("metering and bounded reconciliation limit required")
	}
	keys := []string{
		c.keyPrefix + "usage:admitted", c.keyPrefix + "usage:terminal",
		c.keyPrefix + "usage:progress", c.keyPrefix + "usage:discrepancies",
	}
	raw, err := readUsage.Run(ctx, c.client, keys, limit).Slice()
	if err != nil {
		return UsageReconciliation{}, err
	}
	rows := [4]map[string]string{}
	for i, list := range raw {
		values := list.([]any)
		rows[i] = make(map[string]string, len(values)/2)
		for j := 0; j < len(values); j += 2 {
			rows[i][values[j].(string)] = values[j+1].(string)
		}
	}
	admitted, terminal, progress, disputes := rows[0], rows[1], rows[2], rows[3]
	result := UsageReconciliation{Admitted: len(admitted), Terminal: len(terminal), Totals: make(map[string]UsageTotals)}
	report := func(tenant, key, cause string) {
		result.Discrepancies = append(result.Discrepancies, UsageDiscrepancy{TenantID: tenant, AttemptKey: key, Cause: cause})
		total := result.Totals[tenant]
		total.Discrepancies++
		result.Totals[tenant] = total
	}
	for key, id := range admitted {
		tenant, reservation, _ := strings.Cut(key, ":")
		value, ok := terminal[key]
		if !ok {
			result.Missing = append(result.Missing, key)
			cause := "terminal_missing_without_intent"
			if _, sent := progress[key]; sent {
				cause = "terminal_missing_after_intent"
			}
			report(tenant, key, cause)
			continue
		}
		var row UsageTerminal
		var cause string
		if json.Unmarshal([]byte(value), &row) != nil || row.Version != 1 ||
			!validUsageCount(row.Prompt) || !validUsageCount(row.Completion) {
			cause = "terminal_record_invalid"
		} else if row.TenantID != tenant {
			cause = "terminal_tenant_mismatch"
		} else if row.ReservationID != reservation || row.RequestID != id {
			cause = "terminal_identity_mismatch"
		}
		if cause != "" {
			result.Mismatched = append(result.Mismatched, key)
			report(tenant, key, cause)
			continue
		}
		result.Rows = append(result.Rows, row)
		total := result.Totals[tenant]
		var promptEstimate, completionEstimate *int64
		if row.Checkpoint != nil && row.Checkpoint.Estimate != nil {
			promptEstimate, completionEstimate = &row.Checkpoint.Estimate.Prompt, &row.Checkpoint.Estimate.Completion
		}
		total.Prompt.add(row.Prompt, promptEstimate)
		total.Completion.add(row.Completion, completionEstimate)
		result.Totals[tenant] = total
	}
	for key := range terminal {
		if _, ok := admitted[key]; !ok {
			result.Orphaned = append(result.Orphaned, key)
			tenant, _, _ := strings.Cut(key, ":")
			report(tenant, key, "terminal_without_admission")
		}
	}
	for _, raw := range disputes {
		var item UsageDiscrepancy
		if json.Unmarshal([]byte(raw), &item) != nil || item.AttemptKey == "" || item.Cause == "" {
			return UsageReconciliation{}, ErrUsageBinding
		}
		report(item.TenantID, item.AttemptKey, item.Cause)
	}
	sort.Strings(result.Missing)
	sort.Strings(result.Orphaned)
	sort.Strings(result.Mismatched)
	sort.Slice(result.Rows, func(i, j int) bool {
		a, b := result.Rows[i], result.Rows[j]
		if a.TenantID != b.TenantID {
			return a.TenantID < b.TenantID
		}
		return a.ReservationID < b.ReservationID
	})
	sort.Slice(result.Discrepancies, func(i, j int) bool {
		a, b := result.Discrepancies[i], result.Discrepancies[j]
		if a.AttemptKey != b.AttemptKey {
			return a.AttemptKey < b.AttemptKey
		}
		return a.Cause < b.Cause
	})
	return result, nil
}
