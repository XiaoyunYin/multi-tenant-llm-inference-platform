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
	CapacityReportsExpired
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
	case CapacityReportsExpired:
		return "capacity_reports_expired"
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
	Capacity   int64 // Effective B; -1 for legacy three-field responses.
}

type Coordinator interface {
	Admit(context.Context, Request) (Result, error)
	Release(context.Context, string, string) error
}

type RedisConfig struct {
	MeasurementCapture bool // Secured, untrimmed Redis Stream; default off.
	Namespace          string
	GlobalCapacity     int64
	LeaseDuration      time.Duration
	TombstoneTTL       time.Duration
	DynamicCapacity    *DynamicCapacityConfig // nil explicitly retains configured GlobalCapacity.
}

// Values are deployment inputs, frozen in slice 4, never inferred from traffic.
type DynamicCapacityConfig struct {
	Running   int64
	Waiting   int64
	ReportTTL time.Duration
	HoldDown  time.Duration
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
	if config.DynamicCapacity == nil && config.GlobalCapacity <= 0 {
		return nil, errors.New("global capacity must be positive")
	}
	if d := config.DynamicCapacity; d != nil {
		if d.Running <= 0 || d.Waiting <= 0 || d.Running > 1000000 || d.Waiting > 1000000 || d.ReportTTL.Milliseconds() <= 0 || d.HoldDown.Milliseconds() <= 0 {
			return nil, errors.New("dynamic capacity requires positive bounded R/W and millisecond TTL/hold-down")
		}
		copy := *d
		config.DynamicCapacity = &copy
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
		c.keyPrefix + "capacity:reports",
		c.keyPrefix + "capacity:lows",
		c.keyPrefix + "capacity:state",
	}
	globalMember := request.TenantID + ":" + request.ReservationID
	args := []any{
		request.ReservationID, globalMember, request.Limits.RequestLimit,
		durationMilliseconds(request.Limits.RequestWindow), request.Limits.MaxConcurrent,
		c.config.GlobalCapacity, durationMilliseconds(c.config.LeaseDuration),
		durationMilliseconds(c.config.TombstoneTTL), c.stateTTLMS,
	}
	args = append(args, c.capacityArgs("admit", "", 0)...)
	value, err := c.admitScript.Run(
		ctx,
		c.client,
		keys,
		args...,
	).Result()
	if err != nil {
		return Result{}, fmt.Errorf("atomic admission: %w", err)
	}
	return parseAdmissionResult(value)
}

func (c *RedisCoordinator) capacityArgs(operation, gateway string, healthy int64) []any {
	d := c.config.DynamicCapacity
	capture := ""
	if c.config.MeasurementCapture {
		capture = "capture"
	}
	if d == nil {
		return []any{"fixed", 0, 0, 0, 0, operation, gateway, healthy, capture}
	}
	return []any{"dynamic", d.Running, d.Waiting, d.ReportTTL.Milliseconds(), d.HoldDown.Milliseconds(), operation, gateway, healthy, capture}
}

// ReportHealthy withholds the report when known=false: only an unknown marker
// is sent, without changing the old count or expiry. No tenant keys are touched.
func (c *RedisCoordinator) ReportHealthy(ctx context.Context, gateway string, healthy int64, known bool) error {
	if c.config.DynamicCapacity == nil || !tenantPattern.MatchString(gateway) || healthy < 0 || healthy > 1000000 {
		return errors.New("dynamic capacity, valid gateway identity and bounded healthy count required")
	}
	op := "report"
	if !known {
		op = "unknown"
	}
	keys := []string{c.keyPrefix + "unused", c.keyPrefix + "unused", c.globalMemberKey, c.keyPrefix + "unused", c.keyPrefix + "config:global", c.keyPrefix + "unused", c.keyPrefix + "capacity:reports", c.keyPrefix + "capacity:lows", c.keyPrefix + "capacity:state", c.keyPrefix + "capacity:report:" + gateway}
	args := []any{"", "", 1, 1, 1, c.config.GlobalCapacity, c.config.LeaseDuration.Milliseconds(), c.config.TombstoneTTL.Milliseconds(), c.stateTTLMS}
	args = append(args, c.capacityArgs(op, gateway, healthy)...)
	value, err := c.admitScript.Run(ctx, c.client, keys, args...).Result()
	if err != nil {
		return fmt.Errorf("atomic health report: %w", err)
	}
	_, err = parseAdmissionResult(value)
	return err
}

func ValidGatewayID(id string) bool { return tenantPattern.MatchString(id) }

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
	capture := ""
	if c.config.MeasurementCapture {
		capture = "capture"
	}
	globalMember := tenantID + ":" + reservationID
	value, err := c.releaseScript.Run(
		ctx,
		c.client,
		keys,
		reservationID,
		globalMember,
		durationMilliseconds(c.config.TombstoneTTL),
		capture,
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
	if !ok || (len(items) != 3 && len(items) != 4) {
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
	result := Result{RetryAfter: time.Duration(retryMilliseconds) * time.Millisecond, Capacity: -1}
	if len(items) == 4 {
		result.Capacity, err = responseInt64(items[3])
		if err != nil || result.Capacity < 0 {
			return Result{}, errors.New("invalid capacity response")
		}
	}
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
	case "capacity_reports_expired":
		result.Decision = CapacityReportsExpired
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
