package admission

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"time"

	redis "github.com/redis/go-redis/v9"
)

type Decision uint8

const (
	Allowed Decision = iota
	TenantRateLimited
	TenantConcurrencyLimited
	SystemCapacityLimited
)

func (decision Decision) Code() string {
	switch decision {
	case Allowed:
		return "allowed"
	case TenantRateLimited:
		return "tenant_rate_limit"
	case TenantConcurrencyLimited:
		return "tenant_concurrency_limit"
	case SystemCapacityLimited:
		return "system_capacity"
	default:
		return ""
	}
}

type Limits struct {
	RequestLimit  int64
	RequestWindow time.Duration
	MaxConcurrent int64
}

type Request struct {
	TenantID      string
	ReservationID string
	Limits        Limits
}

type Result struct {
	Decision   Decision
	RetryAfter time.Duration
	Idempotent bool
}

type Coordinator interface {
	Admit(context.Context, Request) (Result, error)
	Release(context.Context, string, string) error
}

type RedisConfig struct {
	Namespace      string
	GlobalCapacity int64
	LeaseDuration  time.Duration
	TombstoneTTL   time.Duration
}

var (
	tenantPattern      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,190}$`)
	reservationPattern = regexp.MustCompile(`^rsv_[0-9a-f]{32}$`)
	namespacePattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9:_-]{0,126}$`)

	ErrReservationReleased   = errors.New("reservation was already released")
	ErrConfigurationMismatch = errors.New("admission configuration does not match existing Redis state")
)

//go:embed scripts/admit.lua
var admitLua string

//go:embed scripts/release.lua
var releaseLua string

type RedisCoordinator struct {
	client          redis.Scripter
	config          RedisConfig
	keyPrefix       string
	globalMemberKey string
	stateTTLMS      int64
	admitScript     *redis.Script
	releaseScript   *redis.Script
}

func NewRedisCoordinator(client redis.Scripter, config RedisConfig) (*RedisCoordinator, error) {
	if client == nil {
		return nil, errors.New("Redis script client is required")
	}
	if !namespacePattern.MatchString(config.Namespace) {
		return nil, errors.New("admission namespace must be 1-127 alphanumeric, colon, underscore, or hyphen characters")
	}
	if config.GlobalCapacity <= 0 {
		return nil, errors.New("global capacity must be positive")
	}
	if durationMilliseconds(config.LeaseDuration) <= 0 || durationMilliseconds(config.TombstoneTTL) <= 0 {
		return nil, errors.New("lease and tombstone durations must be at least one millisecond")
	}
	if config.TombstoneTTL < config.LeaseDuration {
		return nil, errors.New("tombstone duration must be at least the lease duration")
	}
	stateTTL := config.TombstoneTTL
	if config.LeaseDuration > stateTTL {
		stateTTL = config.LeaseDuration
	}
	if stateTTL > time.Duration(1<<63-1)/3 {
		return nil, errors.New("lease and tombstone durations are too large")
	}
	stateTTL *= 3
	prefix := config.Namespace + ":{admission}:"
	return &RedisCoordinator{
		client: client, config: config, keyPrefix: prefix,
		globalMemberKey: prefix + "global:active",
		stateTTLMS:      stateTTL.Milliseconds(),
		admitScript:     redis.NewScript(admitLua), releaseScript: redis.NewScript(releaseLua),
	}, nil
}

func (c *RedisCoordinator) Admit(ctx context.Context, request Request) (Result, error) {
	if err := validateRequest(request); err != nil {
		return Result{}, err
	}
	tenantPrefix := c.keyPrefix + "tenant:" + request.TenantID + ":"
	keys := []string{
		tenantPrefix + "reservation:" + request.ReservationID,
		tenantPrefix + "active",
		c.globalMemberKey,
		tenantPrefix + "rate",
		c.keyPrefix + "config:global",
		tenantPrefix + "config",
	}
	globalMember := request.TenantID + ":" + request.ReservationID
	value, err := c.admitScript.Run(
		ctx,
		c.client,
		keys,
		request.ReservationID,
		globalMember,
		request.Limits.RequestLimit,
		durationMilliseconds(request.Limits.RequestWindow),
		request.Limits.MaxConcurrent,
		c.config.GlobalCapacity,
		durationMilliseconds(c.config.LeaseDuration),
		durationMilliseconds(c.config.TombstoneTTL),
		c.stateTTLMS,
	).Result()
	if err != nil {
		return Result{}, fmt.Errorf("atomic admission: %w", err)
	}
	return parseAdmissionResult(value)
}

func (c *RedisCoordinator) Release(ctx context.Context, tenantID, reservationID string) error {
	if err := validateIdentity(tenantID, reservationID); err != nil {
		return err
	}
	tenantPrefix := c.keyPrefix + "tenant:" + tenantID + ":"
	keys := []string{
		tenantPrefix + "reservation:" + reservationID,
		tenantPrefix + "active",
		c.globalMemberKey,
	}
	globalMember := tenantID + ":" + reservationID
	value, err := c.releaseScript.Run(
		ctx,
		c.client,
		keys,
		reservationID,
		globalMember,
		durationMilliseconds(c.config.TombstoneTTL),
	).Result()
	if err != nil {
		return fmt.Errorf("atomic release: %w", err)
	}
	released, conversionErr := responseInt64(value)
	if conversionErr != nil {
		return fmt.Errorf("release response: %w", conversionErr)
	}
	if released != 0 && released != 1 {
		return fmt.Errorf("unexpected release response %d", released)
	}
	return nil
}

func validateRequest(request Request) error {
	if err := validateIdentity(request.TenantID, request.ReservationID); err != nil {
		return err
	}
	if request.Limits.RequestLimit <= 0 || request.Limits.MaxConcurrent <= 0 || durationMilliseconds(request.Limits.RequestWindow) <= 0 {
		return errors.New("tenant admission limits must be positive and the window at least one millisecond")
	}
	return nil
}

func validateIdentity(tenantID, reservationID string) error {
	if !tenantPattern.MatchString(tenantID) {
		return fmt.Errorf("invalid tenant ID %q", tenantID)
	}
	if !reservationPattern.MatchString(reservationID) {
		return errors.New("invalid reservation ID")
	}
	return nil
}

func durationMilliseconds(duration time.Duration) int64 {
	return duration.Milliseconds()
}

func parseAdmissionResult(value any) (Result, error) {
	items, ok := value.([]any)
	if !ok || len(items) != 3 {
		return Result{}, fmt.Errorf("unexpected admission response %T", value)
	}
	code, ok := items[0].(string)
	if !ok {
		return Result{}, errors.New("admission response code is not a string")
	}
	retryMilliseconds, err := responseInt64(items[1])
	if err != nil {
		return Result{}, fmt.Errorf("admission retry value: %w", err)
	}
	if retryMilliseconds < 0 {
		retryMilliseconds = 0
	}
	if retryMilliseconds > (1<<63-1)/int64(time.Millisecond) {
		return Result{}, errors.New("admission retry value exceeds time.Duration")
	}
	result := Result{RetryAfter: time.Duration(retryMilliseconds) * time.Millisecond}
	switch code {
	case "allowed":
		result.Decision = Allowed
		idempotent, conversionErr := responseInt64(items[2])
		if conversionErr != nil {
			return Result{}, fmt.Errorf("admission idempotency value: %w", conversionErr)
		}
		if idempotent != 0 && idempotent != 1 {
			return Result{}, fmt.Errorf("invalid admission idempotency value %d", idempotent)
		}
		result.Idempotent = idempotent == 1
	case "tenant_rate_limit":
		result.Decision = TenantRateLimited
	case "tenant_concurrency_limit":
		result.Decision = TenantConcurrencyLimited
	case "system_capacity":
		result.Decision = SystemCapacityLimited
	case "released":
		return Result{}, ErrReservationReleased
	case "config_mismatch":
		return Result{}, ErrConfigurationMismatch
	default:
		return Result{}, fmt.Errorf("unknown admission response %q", code)
	}
	return result, nil
}

func responseInt64(value any) (int64, error) {
	switch typed := value.(type) {
	case int64:
		return typed, nil
	case string:
		return strconv.ParseInt(typed, 10, 64)
	case []byte:
		return strconv.ParseInt(string(typed), 10, 64)
	default:
		return 0, fmt.Errorf("unexpected integer type %T", value)
	}
}
