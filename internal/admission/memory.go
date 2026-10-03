package admission

import (
	"context"
	"errors"
	"sync"
	"time"
)

// MemoryCoordinator is deterministic process-local infrastructure for unit and
// cross-language tests. It does not provide a shared multi-gateway guarantee.
type MemoryCoordinator struct {
	mu             sync.Mutex
	globalCapacity int64
	now            func() time.Time
	tenants        map[string]*memoryTenant
	reservations   map[string]memoryReservation
}

type memoryTenant struct {
	windowStarted time.Time
	rateCount     int64
	active        int64
	limits        Limits
}

type memoryReservation struct {
	tenantID string
	released bool
}

func NewMemoryCoordinator(globalCapacity int64) (*MemoryCoordinator, error) {
	if globalCapacity <= 0 {
		return nil, errors.New("global capacity must be positive")
	}
	return &MemoryCoordinator{
		globalCapacity: globalCapacity,
		now:            time.Now,
		tenants:        make(map[string]*memoryTenant),
		reservations:   make(map[string]memoryReservation),
	}, nil
}

func (c *MemoryCoordinator) Admit(ctx context.Context, request Request) (Result, error) {
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if err := validateRequest(request); err != nil {
		return Result{}, err
	}
	key := request.TenantID + ":" + request.ReservationID
	c.mu.Lock()
	defer c.mu.Unlock()
	if existing, ok := c.reservations[key]; ok {
		if existing.released {
			return Result{}, ErrReservationReleased
		}
		return Result{Decision: Allowed, Idempotent: true}, nil
	}
	now := c.now()
	tenant := c.tenants[request.TenantID]
	if tenant == nil {
		tenant = &memoryTenant{windowStarted: now, limits: request.Limits}
		c.tenants[request.TenantID] = tenant
	} else if tenant.limits != request.Limits {
		return Result{}, ErrConfigurationMismatch
	}
	if !now.Before(tenant.windowStarted.Add(request.Limits.RequestWindow)) {
		tenant.windowStarted = now
		tenant.rateCount = 0
	}
	if tenant.rateCount >= request.Limits.RequestLimit {
		return Result{Decision: TenantRateLimited, RetryAfter: tenant.windowStarted.Add(request.Limits.RequestWindow).Sub(now)}, nil
	}
	if tenant.active >= request.Limits.MaxConcurrent {
		return Result{Decision: TenantConcurrencyLimited}, nil
	}
	var globalActive int64
	for _, current := range c.tenants {
		globalActive += current.active
	}
	if globalActive >= c.globalCapacity {
		return Result{Decision: SystemCapacityLimited}, nil
	}
	tenant.rateCount++
	tenant.active++
	c.reservations[key] = memoryReservation{tenantID: request.TenantID}
	return Result{Decision: Allowed}, nil
}

func (c *MemoryCoordinator) Release(ctx context.Context, tenantID, reservationID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateIdentity(tenantID, reservationID); err != nil {
		return err
	}
	key := tenantID + ":" + reservationID
	c.mu.Lock()
	defer c.mu.Unlock()
	existing, ok := c.reservations[key]
	if ok && !existing.released {
		if tenant := c.tenants[existing.tenantID]; tenant != nil && tenant.active > 0 {
			tenant.active--
		}
	}
	c.reservations[key] = memoryReservation{tenantID: tenantID, released: true}
	return nil
}
