package gateway

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math"
	"sort"
)

var ErrRoutingContextRequired = errors.New("hash-affinity routing context is required")

// RoutingMessage is the validated text-only chat input passed to a model-aware
// tokenizer. Implementations must apply the pinned model's chat template before
// returning token IDs.
type RoutingMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// RoutingKeyTokenizer is the model-specific seam for deriving prompt tokens.
// Production implementations must match the selected model and chat template.
type RoutingKeyTokenizer interface {
	TokenizeChat(ctx context.Context, requestID, model string, messages []RoutingMessage, candidates []BackendCandidate) (RoutingTokenizationResult, error)
}

// RoutingTokenizationResult keeps attempted replica identities bounded to the
// configured backend inventory so the gateway can expose per-replica counters.
type RoutingTokenizationResult struct {
	TokenIDs            []uint32
	AttemptedBackendIDs []string
}

// RoutingContext contains request-scoped, server-authenticated placement input.
// TokenIDs are request-local and are never retained by the router.
type RoutingContext struct {
	TenantID  string
	Model     string
	CacheSalt string
	TokenIDs  []uint32
}

type HashAffinityConfig struct {
	BlockSize    int
	MaxBlocks    int
	EscapeMargin float64
}

type HashAffinityRouter struct {
	blockSize    int
	maxBlocks    int
	escapeMargin float64
}

func NewHashAffinityRouter(config HashAffinityConfig) (*HashAffinityRouter, error) {
	maxInt := int(^uint(0) >> 1)
	if config.BlockSize <= 0 || config.MaxBlocks <= 0 || config.MaxBlocks > maxInt/config.BlockSize {
		return nil, errors.New("hash-affinity block size and maximum blocks must be positive and bounded")
	}
	if config.BlockSize*config.MaxBlocks > 1<<20 {
		return nil, errors.New("hash-affinity maximum routing-key tokens must not exceed 1048576")
	}
	if math.IsNaN(config.EscapeMargin) || math.IsInf(config.EscapeMargin, 0) || config.EscapeMargin < 0 {
		return nil, errors.New("hash-affinity escape margin must be finite and non-negative")
	}
	return &HashAffinityRouter{
		blockSize: config.BlockSize, maxBlocks: config.MaxBlocks, escapeMargin: config.EscapeMargin,
	}, nil
}

func (r *HashAffinityRouter) MaxTokenIDs() int { return r.blockSize * r.maxBlocks }

func (*HashAffinityRouter) PolicyName() RoutingPolicy { return RoutingPolicyHashAffinity }

func (*HashAffinityRouter) NeedsFreshBackendLoad() bool { return true }

func (r *HashAffinityRouter) AffinityEnabled(routing RoutingContext) (bool, error) {
	if routing.TenantID == "" || routing.Model == "" || routing.CacheSalt == "" {
		return false, errors.New("hash-affinity tenant, model, and cache salt are required")
	}
	return len(routing.TokenIDs) >= r.blockSize, nil
}

func (r *HashAffinityRouter) Select(_ []BackendCandidate, _ *TieBreaker) (BackendDecision, error) {
	return BackendDecision{Policy: RoutingPolicyHashAffinity, FallbackReason: FallbackReasonNone}, ErrRoutingContextRequired
}

func (r *HashAffinityRouter) SelectWithContext(candidates []BackendCandidate, tieBreaker *TieBreaker, routing RoutingContext) (BackendDecision, error) {
	decision := BackendDecision{Policy: RoutingPolicyHashAffinity, FallbackReason: FallbackReasonNone}
	key, affinityEnabled, err := r.affinityKey(routing)
	if err != nil {
		return decision, err
	}
	if !affinityEnabled {
		leastLoaded, err := NewLeastLoadedRouter().Select(candidates, tieBreaker)
		leastLoaded.Policy = RoutingPolicyLeastLoaded
		return leastLoaded, err
	}

	preferred, preferredLoad, err := r.preferredBackend(candidates, key)
	if err != nil {
		return decision, err
	}
	if backendLoadFallbackReason(candidates) != FallbackReasonNone {
		decision.Backend = preferred
		decision.BackendGeneration = preferred.Generation
		decision.FallbackReason = FallbackReasonEscapeUnavailable
		return decision, nil
	}
	leastLoaded, err := NewLeastLoadedRouter().Select(candidates, tieBreaker)
	if err != nil {
		return decision, err
	}
	leastLoad := backendLoad(leastLoaded.Backend, candidates)
	if preferredLoad > leastLoad+r.escapeMargin {
		leastLoaded.Policy = RoutingPolicyHashAffinity
		leastLoaded.FallbackReason = FallbackReasonBackendLoadEscape
		leastLoaded.BackendGeneration = leastLoaded.Backend.Generation
		return leastLoaded, nil
	}
	decision.Backend = preferred
	decision.BackendGeneration = preferred.Generation
	return decision, nil
}

func (r *HashAffinityRouter) affinityKey(routing RoutingContext) ([sha256.Size]byte, bool, error) {
	if routing.TenantID == "" || routing.Model == "" || routing.CacheSalt == "" {
		return [sha256.Size]byte{}, false, errors.New("hash-affinity tenant, model, and cache salt are required")
	}
	blocks := len(routing.TokenIDs) / r.blockSize
	if blocks == 0 {
		return scopedTokenDigest(routing.TenantID, routing.Model, routing.CacheSalt, routing.TokenIDs), false, nil
	}
	if blocks > r.maxBlocks {
		blocks = r.maxBlocks
	}
	tokenCount := blocks * r.blockSize
	return scopedTokenDigest(routing.TenantID, routing.Model, routing.CacheSalt, routing.TokenIDs[:tokenCount]), true, nil
}

func scopedTokenDigest(tenantID, model, cacheSalt string, tokenIDs []uint32) [sha256.Size]byte {
	hasher := hmac.New(sha256.New, []byte(cacheSalt))
	writeRoutingField(hasher, []byte("multi-tenant-llm-inference-platform/routing-key/v1"))
	writeRoutingField(hasher, []byte(tenantID))
	writeRoutingField(hasher, []byte(model))
	var count [4]byte
	binary.BigEndian.PutUint32(count[:], uint32(len(tokenIDs)))
	writeRoutingField(hasher, count[:])
	var token [4]byte
	for _, tokenID := range tokenIDs {
		binary.BigEndian.PutUint32(token[:], tokenID)
		_, _ = hasher.Write(token[:])
	}
	var digest [sha256.Size]byte
	copy(digest[:], hasher.Sum(nil))
	return digest
}

type routingFieldWriter interface {
	Write([]byte) (int, error)
}

func writeRoutingField(writer routingFieldWriter, field []byte) {
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(field)))
	_, _ = writer.Write(size[:])
	_, _ = writer.Write(field)
}

func rendezvousScore(key [sha256.Size]byte, backend *Backend) [sha256.Size]byte {
	var identity bytes.Buffer
	writeRoutingField(&identity, key[:])
	writeRoutingField(&identity, []byte(backend.ID))
	return sha256.Sum256(identity.Bytes())
}

func (r *HashAffinityRouter) preferredBackend(candidates []BackendCandidate, key [sha256.Size]byte) (*Backend, float64, error) {
	var preferred *Backend
	var bestScore [sha256.Size]byte
	preferredLoad := math.Inf(1)
	for _, candidate := range candidates {
		backend := candidate.Backend
		if backend == nil {
			continue
		}
		score := rendezvousScore(key, backend)
		identityLess := preferred != nil && backend.ID < preferred.ID
		if preferred == nil || bytes.Compare(score[:], bestScore[:]) > 0 || (score == bestScore && identityLess) {
			preferred = backend
			bestScore = score
			preferredLoad = candidate.Load.Running + candidate.Load.Waiting
		}
	}
	if preferred == nil {
		return nil, 0, ErrNoHealthyBackend
	}
	return preferred, preferredLoad, nil
}

func backendLoad(backend *Backend, candidates []BackendCandidate) float64 {
	for _, candidate := range candidates {
		if candidate.Backend == backend {
			return candidate.Load.Running + candidate.Load.Waiting
		}
	}
	return math.Inf(1)
}

type PopularRoutingKey struct {
	Context    RoutingContext
	Popularity uint64
}

type PlacementAuditRecord struct {
	Seed                       int64          `json:"seed"`
	Popularity                 uint64         `json:"popularity"`
	KeyDigest                  string         `json:"key_digest"`
	AffinityApplied            bool           `json:"affinity_applied"`
	PreferredBackendID         string         `json:"preferred_backend_id,omitempty"`
	PreferredBackendGeneration string         `json:"preferred_backend_generation,omitempty"`
	SelectedBackendID          string         `json:"selected_backend_id"`
	SelectedBackendGeneration  string         `json:"selected_backend_generation"`
	Policy                     RoutingPolicy  `json:"policy"`
	FallbackReason             FallbackReason `json:"fallback_reason"`
}

// AuditPlacements creates a bounded, redacted report for the supplied popular
// keys. The caller supplies the popularity counts and report-size limit.
func (r *HashAffinityRouter) AuditPlacements(candidates []BackendCandidate, popular []PopularRoutingKey, seed int64, maxEntries int) ([]PlacementAuditRecord, error) {
	if maxEntries <= 0 {
		return nil, errors.New("placement audit maximum entries must be positive")
	}
	type auditEntry struct {
		popular PopularRoutingKey
		key     [sha256.Size]byte
		enabled bool
	}
	entries := make([]auditEntry, 0, len(popular))
	for _, entry := range popular {
		if entry.Popularity == 0 {
			return nil, errors.New("placement audit popularity must be positive")
		}
		key, enabled, err := r.affinityKey(entry.Context)
		if err != nil {
			return nil, err
		}
		entries = append(entries, auditEntry{popular: entry, key: key, enabled: enabled})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].popular.Popularity != entries[j].popular.Popularity {
			return entries[i].popular.Popularity > entries[j].popular.Popularity
		}
		return bytes.Compare(entries[i].key[:], entries[j].key[:]) < 0
	})
	if len(entries) > maxEntries {
		entries = entries[:maxEntries]
	}

	eligible := make([]BackendCandidate, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate.Backend != nil && candidate.Healthy && candidate.Ready {
			eligible = append(eligible, candidate)
		}
	}
	selection := NewBackendSelectionBoundary(r, NewSeededTieBreaker(seed))
	records := make([]PlacementAuditRecord, 0, len(entries))
	for _, entry := range entries {
		decision, err := selection.Select(candidates, entry.popular.Context)
		if err != nil {
			return nil, err
		}
		preferredID := ""
		if entry.enabled {
			preferred, _, err := r.preferredBackend(eligible, entry.key)
			if err != nil {
				return nil, err
			}
			preferredID = preferred.ID
		}
		records = append(records, PlacementAuditRecord{
			Seed: seed, Popularity: entry.popular.Popularity, KeyDigest: hex.EncodeToString(entry.key[:]),
			AffinityApplied: entry.enabled, PreferredBackendID: preferredID,
			SelectedBackendID: decision.Backend.ID, SelectedBackendGeneration: decision.BackendGeneration, Policy: decision.Policy,
			FallbackReason: decision.FallbackReason,
		})
		if entry.enabled {
			for _, candidate := range eligible {
				if candidate.Backend.ID == preferredID {
					records[len(records)-1].PreferredBackendGeneration = candidate.Backend.Generation
					break
				}
			}
		}
	}
	return records, nil
}
