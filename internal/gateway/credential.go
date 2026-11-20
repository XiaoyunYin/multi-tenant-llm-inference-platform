package gateway

import (
	"container/list"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"

	"multi-tenant-llm-inference-platform/internal/admission"
)

var (
	errCredentialStore = errors.New("credential authority unavailable")
	credentialID       = regexp.MustCompile(`^[0-9a-f]{32}$`)
)

const (
	credentialCacheCapacity = 1024
	credentialCacheTTL      = 5 * time.Second
	credentialReadLimit     = 8
	credentialReadTimeout   = 250 * time.Millisecond
)

type credentialVerifier struct {
	salt       [16]byte
	verifier   [sha256.Size]byte
	tenant     string
	generation uint64
}

func (v credentialVerifier) matches(secret []byte) bool {
	actual := credentialDigest(v.salt[:], secret)
	return subtle.ConstantTimeCompare(actual[:], v.verifier[:]) == 1
}

type cachedCredential struct {
	id        string
	verifier  credentialVerifier
	expiresAt time.Time
}

type CredentialStore struct {
	primary     *redis.Client
	coordinator *admission.RedisCoordinator
	reads       chan struct{}

	cacheMu sync.Mutex
	cache   map[string]*list.Element
	recent  list.List
}

func NewCredentialStore(primary *redis.Client, coordinator *admission.RedisCoordinator) *CredentialStore {
	return &CredentialStore{
		primary: primary, coordinator: coordinator,
		reads: make(chan struct{}, credentialReadLimit),
		cache: make(map[string]*list.Element),
	}
}

func (s *CredentialStore) cached(id string) (credentialVerifier, bool) {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	if entry := s.cache[id]; entry != nil {
		value := entry.Value.(cachedCredential)
		if time.Now().Before(value.expiresAt) {
			s.recent.MoveToFront(entry)
			return value.verifier, true
		}
		s.remove(entry)
	}
	return credentialVerifier{}, false
}

func (s *CredentialStore) remember(id string, verifier credentialVerifier) {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	if entry := s.cache[id]; entry != nil {
		// A slower read of an older generation must not replace a newer one.
		if entry.Value.(cachedCredential).verifier.generation > verifier.generation {
			return
		}
		s.remove(entry)
	}
	if len(s.cache) == credentialCacheCapacity {
		s.remove(s.recent.Back())
	}
	s.cache[id] = s.recent.PushFront(cachedCredential{id, verifier, time.Now().Add(credentialCacheTTL)})
}

// remove requires cacheMu to be held.
func (s *CredentialStore) remove(entry *list.Element) {
	delete(s.cache, entry.Value.(cachedCredential).id)
	s.recent.Remove(entry)
}

func (s *CredentialStore) evict(id string) {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	if entry := s.cache[id]; entry != nil {
		s.remove(entry)
	}
}

func (s *CredentialStore) read(ctx context.Context, id string) (credentialVerifier, error) {
	select {
	case s.reads <- struct{}{}:
		defer func() { <-s.reads }()
	default:
		return credentialVerifier{}, errCredentialStore
	}

	ctx, cancel := context.WithTimeout(ctx, credentialReadTimeout)
	defer cancel()
	row, err := s.primary.HGetAll(ctx, s.coordinator.CredentialKey(id)).Result()
	if err != nil {
		return credentialVerifier{}, errCredentialStore
	}
	var value credentialVerifier
	salt, saltErr := hex.DecodeString(row["salt"])
	expected, verifierErr := hex.DecodeString(row["verifier"])
	generation, generationErr := strconv.ParseUint(row["generation"], 10, 64)
	if row["key_id"] != id || row["role"] != "inference" ||
		saltErr != nil || len(salt) != len(value.salt) || verifierErr != nil || len(expected) != len(value.verifier) ||
		generationErr != nil || generation == 0 {
		return credentialVerifier{}, ErrUnauthenticated
	}
	copy(value.salt[:], salt)
	copy(value.verifier[:], expected)
	value.tenant, value.generation = row["tenant"], generation
	return value, nil
}

func credentialDigest(salt, secret []byte) [sha256.Size]byte {
	digest := sha256.New()
	digest.Write([]byte("mti-inference-credential-v1\x00"))
	digest.Write(salt)
	digest.Write(secret)
	var value [sha256.Size]byte
	digest.Sum(value[:0])
	return value
}

// issueFixture has no production HTTP route. The caller owns fixture credentials.
func (s *CredentialStore) issueFixture(ctx context.Context, tenant string, active, expires time.Time) (string, error) {
	if !tenantIDPattern.MatchString(tenant) || !expires.After(active) {
		return "", errors.New("invalid fixture tenant or lifetime")
	}
	var idBytes, salt [16]byte
	var secret [32]byte
	rand.Read(idBytes[:])
	rand.Read(salt[:])
	rand.Read(secret[:])
	id := hex.EncodeToString(idBytes[:])
	verifier := credentialDigest(salt[:], secret[:])
	// A single new hash holds both verifier material and the admission fence.
	script := redis.NewScript(`
if redis.call('EXISTS', KEYS[1]) ~= 0 then return 0 end
redis.call('HSET', KEYS[1], 'key_id', ARGV[1], 'tenant', ARGV[2],
  'role', 'inference', 'salt', ARGV[3], 'verifier', ARGV[4], 'generation', '1',
  'active_ms', ARGV[5], 'expiry_ms', ARGV[6], 'revoked_ms', '0')
return 1`)
	created, err := script.Run(ctx, s.primary, []string{s.coordinator.CredentialKey(id)},
		id, tenant, hex.EncodeToString(salt[:]), hex.EncodeToString(verifier[:]),
		active.UnixMilli(), expires.UnixMilli()).Int()
	if err != nil || created != 1 {
		return "", errors.New("could not issue fixture credential")
	}
	return id + "." + hex.EncodeToString(secret[:]), nil
}

func (r *TenantRegistry) authenticateRequest(ctx context.Context, headers []string) (*TenantPolicy, *admission.CredentialFence, error) {
	if r.managed == nil {
		if len(headers) == 0 {
			return nil, nil, ErrUnauthenticated
		}
		policy, err := r.Authenticate(headers[0])
		return policy, nil, err
	}
	if len(headers) != 1 {
		return nil, nil, ErrUnauthenticated
	}
	scheme, bearer, _ := strings.Cut(headers[0], " ")
	id, secretHex, _ := strings.Cut(bearer, ".")
	if !strings.EqualFold(scheme, "Bearer") || !credentialID.MatchString(id) || len(secretHex) != 64 {
		return nil, nil, ErrUnauthenticated
	}
	secret, err := hex.DecodeString(secretHex)
	if err != nil {
		return nil, nil, ErrUnauthenticated
	}
	value, cached := r.managed.cached(id)
	if !cached || !value.matches(secret) {
		value, err = r.managed.read(ctx, id)
		if err != nil {
			return nil, nil, err
		}
		if !value.matches(secret) {
			return nil, nil, ErrUnauthenticated
		}
		r.managed.remember(id, value)
	}
	principal := r.byTenant[value.tenant]
	if principal == nil {
		return nil, nil, ErrUnauthenticated
	}
	// Redis TIME, revocation and the current generation are checked together
	// inside Admit. A local verifier match never authorizes dispatch by itself.
	return principal, &admission.CredentialFence{KeyID: id, Generation: value.generation}, nil
}
