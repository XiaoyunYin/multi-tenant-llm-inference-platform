package admission

import (
	"context"
	"errors"
	"strings"
	"time"
)

// Row5Diagnostic uses the production admission coordinator with a dedicated
// rate window. It never publishes capacity reports. Its caller must bind the
// expected configuration to the two live gateway configurations.
type Row5Diagnostic struct{ coordinator *RedisCoordinator }

var ErrRow5DiagnosticConfig = errors.New("row5:diagnostic_config_mismatch")
var ErrRow5DiagnosticID = errors.New("row5:diagnostic_reservation_id")

func NewRow5Diagnostic(c *RedisCoordinator, expected RedisConfig) (*Row5Diagnostic, error) {
	if c == nil || expected.DynamicCapacity == nil || c.config.DynamicCapacity == nil ||
		!expected.MeasurementCapture || !c.config.MeasurementCapture ||
		expected.Namespace != c.config.Namespace || expected.GlobalCapacity != c.config.GlobalCapacity ||
		expected.LeaseDuration != c.config.LeaseDuration || expected.TombstoneTTL != c.config.TombstoneTTL ||
		*expected.DynamicCapacity != *c.config.DynamicCapacity ||
		expected.DynamicCapacity.Running != 4 || expected.DynamicCapacity.Waiting != 1 ||
		expected.DynamicCapacity.ReportTTL != 8*time.Second || expected.DynamicCapacity.HoldDown != 2*time.Second {
		return nil, ErrRow5DiagnosticConfig
	}
	return &Row5Diagnostic{coordinator: c}, nil
}

func (d *Row5Diagnostic) Admit(ctx context.Context, reservationID string) (Result, error) {
	if !reservationPattern.MatchString(reservationID) || !strings.HasPrefix(reservationID, "rsv_d1a6") {
		return Result{}, ErrRow5DiagnosticID
	}
	return d.coordinator.Admit(ctx, Request{TenantID: "row5-diagnostic", ReservationID: reservationID,
		Limits: Limits{RequestLimit: 100, RequestWindow: time.Minute, MaxConcurrent: 1}})
}

func (d *Row5Diagnostic) Release(ctx context.Context, reservationID string) error {
	if !reservationPattern.MatchString(reservationID) || !strings.HasPrefix(reservationID, "rsv_d1a6") {
		return ErrRow5DiagnosticID
	}
	return d.coordinator.Release(ctx, "row5-diagnostic", reservationID)
}
