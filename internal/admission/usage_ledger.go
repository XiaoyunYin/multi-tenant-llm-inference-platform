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
	AdmittedUnixMS  *int64           `json:"admitted_unix_ms,omitempty"`
	Pins            UsagePins        `json:"pins"`
	DispatchIntent  bool             `json:"dispatch_intent"`
	StreamCommitted bool             `json:"stream_committed"`
	Outcome         string           `json:"outcome"`
	Version         int              `json:"version"`
	Checkpoint      *UsageCheckpoint `json:"checkpoint,omitempty"`
	Prompt          UsageCount       `json:"prompt"`
	Completion      UsageCount       `json:"completion"`
}

type usageEvent struct {
	UsageAttempt
	Pins            *UsagePins       `json:"pins,omitempty"`
	Checkpoint      *UsageCheckpoint `json:"checkpoint,omitempty"`
	Outcome         string           `json:"outcome,omitempty"`
	StreamCommitted bool             `json:"stream_committed,omitempty"`
}

var (
	ErrUsageConflict = errors.New("metering event conflicts with the ledger")
	ErrUsageBinding  = errors.New("metering event lacks a matching admitted attempt or dispatch")
	usageOwner       = regexp.MustCompile(`^owner_[0-9a-f]{32}$`)
	usageModel       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_./:-]{0,191}$`)
	usagePin         = regexp.MustCompile(`^(?:[0-9a-f]{40}|sha256:[0-9a-f]{64})?$`)
)

//go:embed scripts/usage.lua
var usageLua string

var updateUsage = redis.NewScript(usageLua)

func (c *RedisCoordinator) UsageMeteringEnabled() bool { return c.config.Metering }

func ValidUsagePins(pins UsagePins) bool {
	return usageModel.MatchString(pins.Model) && usagePin.MatchString(pins.ModelPin) &&
		usagePin.MatchString(pins.Engine) && usagePin.MatchString(pins.Tokenizer)
}

func (c *RedisCoordinator) BeginUsageDispatch(ctx context.Context, attempt UsageAttempt, pins UsagePins) error {
	if !ValidUsagePins(pins) {
		return ErrUsageBinding
	}
	_, err := c.recordUsage(ctx, "dispatch", "dispatch", usageEvent{UsageAttempt: attempt, Pins: &pins})
	return err
}

func (c *RedisCoordinator) CheckpointUsage(ctx context.Context, attempt UsageAttempt, point UsageCheckpoint) error {
	if point.Sequence < 1 || point.Sequence > 1<<31-1 || (point.Runtime == nil && point.Estimate == nil) {
		return ErrUsageBinding
	}
	for _, counts := range []*UsageTokens{point.Runtime, point.Estimate} {
		if counts != nil && (counts.Prompt < 0 || counts.Completion < 0 || counts.Prompt > 1<<31-1 || counts.Completion > 1<<31-1) {
			return ErrUsageBinding
		}
	}
	_, err := c.recordUsage(ctx, "checkpoint", "checkpoint:"+strconv.FormatInt(point.Sequence, 10), usageEvent{UsageAttempt: attempt, Checkpoint: &point})
	return err
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
	value, err := c.recordUsage(ctx, "terminal", "terminal:1", usageEvent{UsageAttempt: attempt, Pins: &pins, Outcome: outcome, StreamCommitted: committed})
	if err != nil {
		return UsageTerminal{}, err
	}
	var terminal UsageTerminal
	if err := json.Unmarshal([]byte(value), &terminal); err != nil {
		return UsageTerminal{}, ErrUsageBinding
	}
	return terminal, nil
}

func (c *RedisCoordinator) recordUsage(ctx context.Context, operation, id string, event usageEvent) (string, error) {
	if !c.config.Metering || validateIdentity(event.TenantID, event.ReservationID) != nil ||
		!requestIDPattern.MatchString(event.RequestID) || !usageOwner.MatchString(event.OwnerEpoch) {
		return "", ErrUsageBinding
	}
	body, err := json.Marshal(event)
	if err != nil {
		return "", err
	}
	key := event.TenantID + ":" + event.ReservationID
	keys := []string{
		c.keyPrefix + "usage:admitted", c.keyPrefix + "usage:admitted-at",
		c.keyPrefix + "usage:progress", c.keyPrefix + "usage:terminal",
		c.keyPrefix + "usage:events", c.keyPrefix + "usage:discrepancies",
	}
	reply, err := updateUsage.Run(ctx, c.client, keys, key, event.RequestID, event.OwnerEpoch,
		operation, key+"|"+event.OwnerEpoch+"|"+id, fmt.Sprintf("%x", sha256.Sum256(body)), body).StringSlice()
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
	default:
		return "", ErrUsageBinding
	}
}
