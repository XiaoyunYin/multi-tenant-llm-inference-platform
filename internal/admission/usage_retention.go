package admission

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/redis/go-redis/v9"
)

//go:embed scripts/usage_retention.lua
var usageRetentionLua string

var rotateUsage = redis.NewScript(usageCommonLua + "\n" + usageRetentionLua)

const maxArchiveAttempts = 128

// UsageArchive contains exact journal bytes. The digest is kept separately by
// the operator so retirement can verify the persisted export before its CAS.
type UsageArchive struct {
	Schema    int    `json:"schema"`
	Namespace string `json:"namespace"`
	Journal   string `json:"journal"`
}

// ExportUsageCohort captures a bounded batch past the correction window.
// Every included obligation has a reconciled terminal and all its event and
// discrepancy records. Exceptions arriving after retirement are exportable too.
func (c *RedisCoordinator) ExportUsageCohort(ctx context.Context, limit int) ([]byte, string, error) {
	if !c.config.Metering || limit < 1 || limit > maxArchiveAttempts {
		return nil, "", ErrUsageBinding
	}
	reply, err := rotateUsage.Run(ctx, c.client, c.usageKeys(), "export", limit).StringSlice()
	if err != nil {
		return nil, "", err
	}
	if len(reply) != 2 || reply[0] != "exported" || !validArchiveJournal(reply[1]) {
		return nil, "", ErrUsageConflict
	}
	if reply[1] == "[[],[],[]]" {
		return nil, "", nil
	}
	data, err := json.Marshal(UsageArchive{Schema: 1, Namespace: c.config.Namespace, Journal: reply[1]})
	if err != nil {
		return nil, "", err
	}
	return data, fmt.Sprintf("%x", sha256.Sum256(data)), nil
}

// RetireUsageCohort verifies the exported bytes and atomically compares every
// archived field against the primary. Newly arrived evidence forces re-export.
func (c *RedisCoordinator) RetireUsageCohort(ctx context.Context, data []byte, digest string) (int, error) {
	sum := sha256.Sum256(data)
	if !c.config.Metering || hex.EncodeToString(sum[:]) != digest {
		return 0, ErrUsageBinding
	}
	var archive UsageArchive
	if json.Unmarshal(data, &archive) != nil || archive.Schema != 1 ||
		archive.Namespace != c.config.Namespace || !validArchiveJournal(archive.Journal) {
		return 0, ErrUsageBinding
	}
	reply, err := rotateUsage.Run(ctx, c.client, c.usageKeys(), "retire", maxArchiveAttempts, archive.Journal).StringSlice()
	if err != nil {
		return 0, err
	}
	if len(reply) != 2 || reply[0] != "retired" {
		return 0, ErrUsageConflict
	}
	return strconv.Atoi(reply[1])
}

func validArchiveJournal(journal string) bool {
	var parts [][][]string
	if json.Unmarshal([]byte(journal), &parts) != nil || len(parts) != 3 || len(parts[0]) > maxArchiveAttempts {
		return false
	}
	seen := make(map[string]bool, len(parts[0]))
	for _, record := range parts[0] {
		if len(record) != 6 || seen[record[0]] {
			return false
		}
		seen[record[0]] = true
		var row UsageTerminal
		if json.Unmarshal([]byte(record[5]), &row) != nil || row.RequestID != record[1] ||
			row.TenantID+":"+row.ReservationID != record[0] || row.Version < 1 ||
			!validUsageCount(row.Prompt) || !validUsageCount(row.Completion) {
			return false
		}
	}
	for _, event := range parts[1] {
		if len(event) != 2 || !usageDigest.MatchString(event[1]) || !seen[attemptFromEvent(event[0])] {
			return false
		}
	}
	for _, item := range parts[2] {
		if len(item) != 2 {
			return false
		}
		var discrepancy UsageDiscrepancy
		if json.Unmarshal([]byte(item[1]), &discrepancy) != nil ||
			discrepancy.AttemptKey != attemptFromEvent(item[0]) || discrepancy.Cause == "" {
			return false
		}
	}
	return true
}

func attemptFromEvent(event string) string {
	key, _, _ := strings.Cut(event, "|")
	return key
}
