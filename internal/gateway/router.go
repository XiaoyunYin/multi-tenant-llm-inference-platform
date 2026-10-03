package gateway

import (
	cryptorand "crypto/rand"
	"encoding/binary"
	"fmt"
	"math"
	mathrand "math/rand"
	"sync"
	"time"
)

// BackendCandidate is one configured backend and the health, readiness, and
// load snapshot used for a single selection decision.
type BackendCandidate struct {
	Backend *Backend
	Healthy bool
	Ready   bool
	Load    BackendMetricsSnapshot
}

type RoutingPolicy string

const (
	RoutingPolicyNone             RoutingPolicy = "none"
	RoutingPolicyRoundRobin       RoutingPolicy = "round_robin"
	RoutingPolicyLeastLoaded      RoutingPolicy = "least_loaded"
	RoutingPolicyHashAffinity     RoutingPolicy = "hash_affinity"
	RoutingPolicyLearnedPlacement RoutingPolicy = "learned_placement"
	RoutingPolicyPrecise          RoutingPolicy = "precise"
)

var routingPolicies = [...]RoutingPolicy{
	RoutingPolicyRoundRobin,
	RoutingPolicyLeastLoaded,
	RoutingPolicyHashAffinity,
	RoutingPolicyLearnedPlacement,
	RoutingPolicyPrecise,
}

type FallbackReason string

const (
	FallbackReasonNone                  FallbackReason = "none"
	FallbackReasonStale                 FallbackReason = "stale"
	FallbackReasonMissing               FallbackReason = "missing"
	FallbackReasonDown                  FallbackReason = "down"
	FallbackReasonIdentityMismatch      FallbackReason = "identity_mismatch"
	FallbackReasonBackendLoadEscape     FallbackReason = "backend_load_escape"
	FallbackReasonEscapeUnavailable     FallbackReason = "escape_unavailable"
	FallbackReasonRoutingKeyUnavailable FallbackReason = "routing_key_unavailable"
)

var fallbackReasons = [...]FallbackReason{
	FallbackReasonNone,
	FallbackReasonStale,
	FallbackReasonMissing,
	FallbackReasonDown,
	FallbackReasonIdentityMismatch,
	FallbackReasonBackendLoadEscape,
	FallbackReasonEscapeUnavailable,
	FallbackReasonRoutingKeyUnavailable,
}

// BackendDecision records the effective policy and why load-aware routing
// fell back. Policy is the policy that actually selected Backend.
type BackendDecision struct {
	Backend           *Backend
	BackendGeneration string
	Policy            RoutingPolicy
	FallbackReason    FallbackReason
}

// Router selects a backend from candidates already filtered to healthy and
// ready endpoints. Load-dependent routers use the shared freshness checks;
// contextual routers may retain a key-based preference when only the load
// escape, rather than affinity, requires fresh samples.
type Router interface {
	PolicyName() RoutingPolicy
	Select(candidates []BackendCandidate, tieBreaker *TieBreaker) (BackendDecision, error)
	NeedsFreshBackendLoad() bool
}

// ContextualRouter additionally needs validated request-scoped routing input
// and reports whether that input provides an affinity key that can route
// without load samples.
type ContextualRouter interface {
	Router
	AffinityEnabled(routing RoutingContext) (bool, error)
	SelectWithContext(candidates []BackendCandidate, tieBreaker *TieBreaker, routing RoutingContext) (BackendDecision, error)
}

// RoundRobinRouter selects eligible candidates in their configured order.
type RoundRobinRouter struct {
	mu     sync.Mutex
	nextID string
}

func NewRoundRobinRouter() *RoundRobinRouter { return &RoundRobinRouter{} }

func (*RoundRobinRouter) PolicyName() RoutingPolicy { return RoutingPolicyRoundRobin }

func (r *RoundRobinRouter) Select(candidates []BackendCandidate, _ *TieBreaker) (BackendDecision, error) {
	if len(candidates) == 0 {
		return BackendDecision{Policy: RoutingPolicyRoundRobin, FallbackReason: FallbackReasonNone}, ErrNoHealthyBackend
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	index := 0
	if r.nextID != "" {
		for candidateIndex, candidate := range candidates {
			if candidate.Backend != nil && candidate.Backend.ID == r.nextID {
				index = candidateIndex
				break
			}
		}
	}
	backend := candidates[index].Backend
	if backend == nil {
		return BackendDecision{Policy: RoutingPolicyRoundRobin, FallbackReason: FallbackReasonNone}, ErrNoHealthyBackend
	}
	r.nextID = candidates[(index+1)%len(candidates)].Backend.ID
	return BackendDecision{Backend: backend, BackendGeneration: backend.Generation, Policy: RoutingPolicyRoundRobin, FallbackReason: FallbackReasonNone}, nil
}

func (*RoundRobinRouter) NeedsFreshBackendLoad() bool { return false }

// LeastLoadedRouter chooses the eligible backend with the lowest running plus
// waiting request count. KV occupancy is intentionally not part of this score.
type LeastLoadedRouter struct{}

func NewLeastLoadedRouter() *LeastLoadedRouter { return &LeastLoadedRouter{} }

func (*LeastLoadedRouter) PolicyName() RoutingPolicy { return RoutingPolicyLeastLoaded }

func (*LeastLoadedRouter) NeedsFreshBackendLoad() bool { return true }

func (*LeastLoadedRouter) Select(candidates []BackendCandidate, tieBreaker *TieBreaker) (BackendDecision, error) {
	decision := BackendDecision{Policy: RoutingPolicyLeastLoaded, FallbackReason: FallbackReasonNone}
	minimum := math.Inf(1)
	tied := make([]BackendCandidate, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate.Backend == nil {
			continue
		}
		load := candidate.Load.Running + candidate.Load.Waiting
		if math.IsNaN(load) || math.IsInf(load, 0) || load < 0 {
			return decision, fmt.Errorf("backend %q has an invalid running-plus-waiting load", candidate.Backend.ID)
		}
		switch {
		case load < minimum:
			minimum = load
			tied = tied[:0]
			tied = append(tied, candidate)
		case load == minimum:
			tied = append(tied, candidate)
		}
	}
	backend, err := selectRandomTie(tied, tieBreaker)
	if err != nil {
		return decision, err
	}
	decision.Backend = backend
	decision.BackendGeneration = backend.Generation
	return decision, nil
}

// TieBreaker provides concurrency-safe randomized tie selection. Tests can
// supply a fixed seed to make equal-score choices reproducible.
type TieBreaker struct {
	mu  sync.Mutex
	rng *mathrand.Rand
}

func NewSeededTieBreaker(seed int64) *TieBreaker {
	return &TieBreaker{rng: mathrand.New(mathrand.NewSource(seed))}
}

func NewRandomTieBreaker() *TieBreaker {
	var seedBytes [8]byte
	seed := time.Now().UnixNano()
	if _, err := cryptorand.Read(seedBytes[:]); err == nil {
		seed = int64(binary.LittleEndian.Uint64(seedBytes[:]))
	}
	return NewSeededTieBreaker(seed)
}

func (t *TieBreaker) Intn(limit int) int {
	if limit <= 1 {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.rng.Intn(limit)
}

// BackendSelectionBoundary applies the common healthy/ready eligibility rule
// and keeps telemetry freshness separate from endpoint health.
type BackendSelectionBoundary struct {
	router     Router
	roundRobin *RoundRobinRouter
	tieBreaker *TieBreaker
}

func NewBackendSelectionBoundary(router Router, tieBreaker *TieBreaker) *BackendSelectionBoundary {
	if router == nil {
		router = NewRoundRobinRouter()
	}
	if tieBreaker == nil {
		tieBreaker = NewRandomTieBreaker()
	}
	return &BackendSelectionBoundary{
		router: router, roundRobin: NewRoundRobinRouter(), tieBreaker: tieBreaker,
	}
}

func (s *BackendSelectionBoundary) RequiresRoutingContext() bool {
	_, ok := s.router.(ContextualRouter)
	return ok
}

func (s *BackendSelectionBoundary) Select(candidates []BackendCandidate, routing ...RoutingContext) (BackendDecision, error) {
	eligible := eligibleBackends(candidates)
	if len(eligible) == 0 {
		return BackendDecision{Policy: RoutingPolicyNone, FallbackReason: FallbackReasonNone}, ErrNoHealthyBackend
	}
	contextual, isContextual := s.router.(ContextualRouter)
	affinityEnabled := false
	if isContextual {
		if len(routing) != 1 {
			return BackendDecision{Policy: s.router.PolicyName(), FallbackReason: FallbackReasonNone}, ErrRoutingContextRequired
		}
		var err error
		affinityEnabled, err = contextual.AffinityEnabled(routing[0])
		if err != nil {
			return BackendDecision{Policy: s.router.PolicyName(), FallbackReason: FallbackReasonNone}, err
		}
	}
	if s.router.NeedsFreshBackendLoad() {
		fallbackReason := backendLoadFallbackReason(eligible)
		if fallbackReason != FallbackReasonNone && !affinityEnabled {
			decision, err := s.roundRobin.Select(eligible, s.tieBreaker)
			decision.FallbackReason = fallbackReason
			decision = recordBackendGeneration(decision)
			return decision, err
		}
	}
	var decision BackendDecision
	var err error
	if isContextual {
		decision, err = contextual.SelectWithContext(eligible, s.tieBreaker, routing[0])
	} else {
		decision, err = s.router.Select(eligible, s.tieBreaker)
		decision.Policy = s.router.PolicyName()
		decision.FallbackReason = FallbackReasonNone
	}
	if err == nil && decision.Backend == nil {
		return decision, ErrNoHealthyBackend
	}
	return recordBackendGeneration(decision), err
}

func eligibleBackends(candidates []BackendCandidate) []BackendCandidate {
	eligible := make([]BackendCandidate, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate.Backend != nil && candidate.Healthy && candidate.Ready {
			eligible = append(eligible, candidate)
		}
	}
	return eligible
}

// SelectLeastLoadedFallback routes requests whose affinity key could not be
// computed. Fresh telemetry selects by least load; stale telemetry retains the
// shared round-robin selection while preserving the reason the affinity key was
// unavailable.
func (s *BackendSelectionBoundary) SelectLeastLoadedFallback(candidates []BackendCandidate, reason FallbackReason) (BackendDecision, error) {
	eligible := eligibleBackends(candidates)
	if len(eligible) == 0 {
		return BackendDecision{Policy: RoutingPolicyNone, FallbackReason: reason}, ErrNoHealthyBackend
	}
	var decision BackendDecision
	var err error
	if backendLoadFallbackReason(eligible) != FallbackReasonNone {
		decision, err = s.roundRobin.Select(eligible, s.tieBreaker)
	} else {
		decision, err = NewLeastLoadedRouter().Select(eligible, s.tieBreaker)
	}
	decision.FallbackReason = reason
	return recordBackendGeneration(decision), err
}

func recordBackendGeneration(decision BackendDecision) BackendDecision {
	if decision.Backend != nil {
		decision.BackendGeneration = decision.Backend.Generation
	}
	return decision
}

func routingPolicyIndex(policy RoutingPolicy) (int, bool) {
	for index, known := range routingPolicies {
		if policy == known {
			return index, true
		}
	}
	return 0, false
}

func fallbackReasonIndex(reason FallbackReason) (int, bool) {
	for index, known := range fallbackReasons {
		if reason == known {
			return index, true
		}
	}
	return 0, false
}

func backendLoadFallbackReason(candidates []BackendCandidate) FallbackReason {
	missing, down, stale := false, false, false
	for _, candidate := range candidates {
		if !candidate.Load.HasSample {
			missing = true
			continue
		}
		if candidate.Load.BackendID != "" && candidate.Load.BackendID != candidate.Backend.ID {
			return FallbackReasonIdentityMismatch
		}
		if !candidate.Load.Up {
			down = true
			continue
		}
		if !candidate.Load.Fresh {
			stale = true
		}
	}
	// When several replicas have unusable samples, report identity mismatches
	// first, then missing, scrape down, and stale samples in that stable order.
	switch {
	case missing:
		return FallbackReasonMissing
	case down:
		return FallbackReasonDown
	case stale:
		return FallbackReasonStale
	default:
		return FallbackReasonNone
	}
}

func selectRandomTie(candidates []BackendCandidate, tieBreaker *TieBreaker) (*Backend, error) {
	if len(candidates) == 0 {
		return nil, ErrNoHealthyBackend
	}
	if tieBreaker == nil {
		tieBreaker = NewRandomTieBreaker()
	}
	tied := make([]*Backend, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate.Backend != nil {
			tied = append(tied, candidate.Backend)
		}
	}
	if len(tied) == 0 {
		return nil, ErrNoHealthyBackend
	}
	return tied[tieBreaker.Intn(len(tied))], nil
}
