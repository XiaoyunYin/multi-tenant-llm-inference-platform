package admission

import (
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"

	"github.com/redis/go-redis/v9"
)

// UsageAttempt binds ledger events to the tenant and reservation admitted by Redis.
type UsageAttempt struct {
	TenantID      string `json:"tenant_id"`
	ReservationID string `json:"reservation_id"`
	RequestID     string `json:"request_id"`
	OwnerEpoch    string `json:"owner_epoch"`
}

type UsagePins struct {
	Model     string `json:"model"`
	ModelPin  string `json:"model_pin"`
	Engine    string `json:"engine"`
	Tokenizer string `json:"tokenizer"`
}

type UsageTokens struct {
	Prompt     int64 `json:"prompt"`
	Completion int64 `json:"completion"`
}

// UsageCheckpoint is an absolute observation. A tokenizer estimate, when
// available, remains distinct from the engine's runtime usage.
type UsageCheckpoint struct {
	Sequence int64        `json:"sequence"`
	Runtime  *UsageTokens `json:"runtime,omitempty"`
	Estimate *UsageTokens `json:"estimate,omitempty"`
}

type UsageCount struct {
	Classification string `json:"classification"`
	Tokens         *int64 `json:"tokens,omitempty"`
	Source         string `json:"source"`
}

type UsageTerminal struct {
	UsageAttempt
	AdmittedUnixMS          *int64                  `json:"admitted_unix_ms,omitempty"`
	AdmissionDeadlineUnixMS *int64                  `json:"admission_deadline_unix_ms,omitempty"`
	Pins                    UsagePins               `json:"pins"`
	DispatchIntent          bool                    `json:"dispatch_intent"`
	StreamCommitted         bool                    `json:"stream_committed"`
	Outcome                 string                  `json:"outcome"`
	Version                 int                     `json:"version"`
	Checkpoint              *UsageCheckpoint        `json:"checkpoint,omitempty"`
	Prompt                  UsageCount              `json:"prompt"`
	Completion              UsageCount              `json:"completion"`
	Correction              *UsageCorrectionReceipt `json:"correction,omitempty"`
	History                 []UsageTerminal         `json:"history,omitempty"`
}

// UsageCorrection carries a reviewed engine observation and binds its evidence.
// The previous outcome remains the record of the original client stream.
type UsageCorrection struct {
	UsageAttempt
	ExpectedVersion int             `json:"expected_version"`
	Checkpoint      UsageCheckpoint `json:"checkpoint"`
	EvidenceSHA256  string          `json:"evidence_sha256"`
	Reason          string          `json:"reason"`
}

type UsageCorrectionReceipt struct {
	ArrivalUnixMS  int64  `json:"arrival_unix_ms"`
	EvidenceSHA256 string `json:"evidence_sha256"`
	Reason         string `json:"reason"`
}

type usageEvent struct {
	UsageAttempt
	Pins            *UsagePins       `json:"pins,omitempty"`
	Checkpoint      *UsageCheckpoint `json:"checkpoint,omitempty"`
	Outcome         string           `json:"outcome,omitempty"`
	StreamCommitted bool             `json:"stream_committed,omitempty"`
}

var (
	ErrUsageConflict     = errors.New("metering event conflicts with the ledger")
	ErrUsageBinding      = errors.New("metering event lacks a matching admitted attempt or dispatch")
	ErrUsageWindowClosed = errors.New("metering correction window is closed or unverified")
	usageOwner           = regexp.MustCompile(`^owner_[0-9a-f]{32}$`)
	usageModel           = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_./:-]{0,191}$`)
	usagePin             = regexp.MustCompile(`^(?:[0-9a-f]{40}|sha256:[0-9a-f]{64})?$`)
	usageDigest          = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

//go:embed scripts/usage_common.lua
var usageCommonLua string

//go:embed scripts/usage.lua
var usageLua string

//go:embed scripts/usage_maintenance.lua
var usageMaintenanceLua string

var (
	updateUsage   = redis.NewScript(usageCommonLua + "\n" + usageLua)
	maintainUsage = redis.NewScript(usageCommonLua + "\n" + usageMaintenanceLua)
)

func (c *RedisCoordinator) usageKeys() []string {
	return []string{
		c.keyPrefix + "usage:admitted", c.keyPrefix + "usage:admitted-at",
		c.keyPrefix + "usage:progress", c.keyPrefix + "usage:terminal",
		c.keyPrefix + "usage:events", c.keyPrefix + "usage:discrepancies",
		c.keyPrefix + "usage:deadlines", c.keyPrefix + "usage:open-deadlines",
		c.keyPrefix + "usage:retired",
	}
}

func (c *RedisCoordinator) UsageMeteringEnabled() bool { return c.config.Metering }

func ValidUsagePins(pins UsagePins) bool {
	return usageModel.MatchString(pins.Model) && usagePin.MatchString(pins.ModelPin) &&
		usagePin.MatchString(pins.Engine) && usagePin.MatchString(pins.Tokenizer)
}

func (c *RedisCoordinator) BeginUsageDispatch(ctx context.Context, attempt UsageAttempt, pins UsagePins) error {
	if !ValidUsagePins(pins) {
		return ErrUsageBinding
	}
	_, err := c.recordUsage(ctx, attempt, "dispatch", "dispatch", usageEvent{UsageAttempt: attempt, Pins: &pins})
	return err
}

func (c *RedisCoordinator) CheckpointUsage(ctx context.Context, attempt UsageAttempt, point UsageCheckpoint) error {
	if !validUsageCheckpoint(point) {
		return ErrUsageBinding
	}
	_, err := c.recordUsage(ctx, attempt, "checkpoint", "checkpoint:"+strconv.FormatInt(point.Sequence, 10), usageEvent{UsageAttempt: attempt, Checkpoint: &point})
	return err
}

func validUsageCheckpoint(point UsageCheckpoint) bool {
	if point.Sequence < 1 || point.Sequence > 1<<31-1 || (point.Runtime == nil && point.Estimate == nil) {
		return false
	}
	for _, counts := range []*UsageTokens{point.Runtime, point.Estimate} {
		if counts != nil && (counts.Prompt < 0 || counts.Completion < 0 || counts.Prompt > 1<<31-1 || counts.Completion > 1<<31-1) {
			return false
		}
	}
	return true
}

func (c *RedisCoordinator) FinalizeUsage(ctx context.Context, attempt UsageAttempt, pins UsagePins, outcome string, committed bool) (UsageTerminal, error) {
	switch outcome {
	case "completed", "rejected", "client_cancelled", "upstream_failure", "upstream_protocol_error",
		"timeout", "stream_interrupted", "write_failure", "shutdown", "internal_error":
	default:
		return UsageTerminal{}, ErrUsageBinding
	}
	if !ValidUsagePins(pins) || (outcome == "completed" && !committed) {
		return UsageTerminal{}, ErrUsageBinding
	}
	return parseUsageTerminal(c.recordUsage(ctx, attempt, "terminal", "terminal:1", usageEvent{UsageAttempt: attempt, Pins: &pins, Outcome: outcome, StreamCommitted: committed}))
}

// CorrectUsage accepts one absolute, verified runtime observation by CAS. It
// does not upgrade incomplete client output to a completed stream.
func (c *RedisCoordinator) CorrectUsage(ctx context.Context, correction UsageCorrection) (UsageTerminal, error) {
	if correction.ExpectedVersion < 1 || correction.ExpectedVersion >= 1<<31-1 ||
		!usageDigest.MatchString(correction.EvidenceSHA256) || !validUsageCheckpoint(correction.Checkpoint) ||
		correction.Checkpoint.Runtime == nil || (correction.Reason != "verified_engine_usage" && correction.Reason != "verified_usage_recount") {
		return UsageTerminal{}, ErrUsageBinding
	}
	return parseUsageTerminal(c.recordUsage(ctx, correction.UsageAttempt, "correction",
		"correction:"+strconv.Itoa(correction.ExpectedVersion), correction))
}

func parseUsageTerminal(value string, err error) (UsageTerminal, error) {
	if err != nil {
		return UsageTerminal{}, err
	}
	var terminal UsageTerminal
	if err := json.Unmarshal([]byte(value), &terminal); err != nil {
		return UsageTerminal{}, ErrUsageBinding
	}
	return terminal, nil
}

func (c *RedisCoordinator) recordUsage(ctx context.Context, attempt UsageAttempt, operation, id string, payload any) (string, error) {
	if !c.config.Metering || validateIdentity(attempt.TenantID, attempt.ReservationID) != nil ||
		!requestIDPattern.MatchString(attempt.RequestID) || !usageOwner.MatchString(attempt.OwnerEpoch) {
		return "", ErrUsageBinding
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	key := attempt.TenantID + ":" + attempt.ReservationID
	reply, err := updateUsage.Run(ctx, c.client, c.usageKeys(), key, attempt.RequestID, attempt.OwnerEpoch,
		operation, key+"|"+attempt.OwnerEpoch+"|"+id, fmt.Sprintf("%x", sha256.Sum256(body)), body).StringSlice()
	if err != nil {
		return "", fmt.Errorf("persist metered usage: %w", err)
	}
	if len(reply) != 2 {
		return "", ErrUsageBinding
	}
	switch reply[0] {
	case "written", "replayed":
		return reply[1], nil
	case "conflict":
		return "", ErrUsageConflict
	case "window_closed":
		return "", ErrUsageWindowClosed
	default:
		return "", ErrUsageBinding
	}
}

// PrepareUsageMaintenance indexes retained slice 1 and 2a obligations once at
// metered gateway startup. New admissions write that index at grant time.
func (c *RedisCoordinator) PrepareUsageMaintenance(ctx context.Context) error {
	if !c.config.Metering {
		return ErrUsageBinding
	}
	return maintainUsage.Run(ctx, c.client, c.usageKeys(), "migrate", 10000, c.config.LeaseDuration.Milliseconds()).Err()
}

// SweepUsage finalizes at most limit overdue open obligations. Release and
// reservation expiry continue to use the original admission scripts.
func (c *RedisCoordinator) SweepUsage(ctx context.Context, limit int) (int, error) {
	if !c.config.Metering || limit < 1 || limit > 128 {
		return 0, ErrUsageBinding
	}
	return maintainUsage.Run(ctx, c.client, c.usageKeys(), "sweep", limit).Int()
}
