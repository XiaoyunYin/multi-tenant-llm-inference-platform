package gateway

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
)

var (
	ErrUnauthenticated = errors.New("unauthenticated")
	tenantIDPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,190}$`)
)

type TenantSpec struct {
	TenantID         string   `json:"tenant_id"`
	CredentialSHA256 string   `json:"credential_sha256"`
	Models           []string `json:"models"`
	MaxRequestBytes  int64    `json:"max_request_bytes"`
	MaxOutputTokens  int      `json:"max_output_tokens"`
	RequestRateLimit int64    `json:"request_rate_limit"`
	RateWindowMS     int64    `json:"request_rate_window_ms"`
	MaxConcurrent    int64    `json:"max_concurrent"`
}

type tenantDocument struct {
	Tenants []TenantSpec `json:"tenants"`
}

// CacheSaltSecret is a deployment-wide secret used only to derive stable,
// unlinkable backend cache namespaces for tenants.
type CacheSaltSecret [sha256.Size]byte

type TenantPolicy struct {
	ID                string
	MaxRequestBytes   int64
	MaxOutputTokens   int
	RequestRateLimit  int64
	RequestRateWindow time.Duration
	MaxConcurrent     int64
	credentialDigest  [sha256.Size]byte
	models            map[string]struct{}
	cacheSalt         string
}

func (t *TenantPolicy) AllowsModel(model string) bool {
	_, allowed := t.models[model]
	return allowed
}

type TenantRegistry struct {
	byCredential map[[sha256.Size]byte]*TenantPolicy
}

// AdmissionLimits exposes effective limits without credentials, models or cache salts.
func (r *TenantRegistry) AdmissionLimits() map[string]map[string]int64 {
	limits := make(map[string]map[string]int64, len(r.byCredential))
	for _, tenant := range r.byCredential {
		limits[tenant.ID] = map[string]int64{
			"max_concurrent":         tenant.MaxConcurrent,
			"request_rate_limit":     tenant.RequestRateLimit,
			"request_rate_window_ms": tenant.RequestRateWindow.Milliseconds(),
		}
	}
	return limits
}

func CredentialSHA256(credential string) string {
	digest := sha256.Sum256([]byte(credential))
	return hex.EncodeToString(digest[:])
}

func LoadCacheSaltSecret(reader io.Reader) (CacheSaltSecret, error) {
	const encodedSize = 43
	var secret CacheSaltSecret
	payload, err := io.ReadAll(io.LimitReader(reader, encodedSize+3))
	if err != nil {
		return secret, fmt.Errorf("read cache-salt secret: %w", err)
	}
	if bytes.HasSuffix(payload, []byte("\r\n")) {
		payload = payload[:len(payload)-2]
	} else if bytes.HasSuffix(payload, []byte("\n")) {
		payload = payload[:len(payload)-1]
	}
	if len(payload) != encodedSize {
		return secret, errors.New("cache-salt secret must be one canonical unpadded base64url-encoded 32-byte value")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(string(payload))
	if err != nil || len(decoded) != sha256.Size || base64.RawURLEncoding.EncodeToString(decoded) != string(payload) {
		return secret, errors.New("cache-salt secret must be one canonical unpadded base64url-encoded 32-byte value")
	}
	copy(secret[:], decoded)
	return secret, nil
}

func deriveCacheSalt(secret CacheSaltSecret, tenantID string) string {
	digest := hmac.New(sha256.New, secret[:])
	_, _ = digest.Write([]byte("multi-tenant-llm-inference-platform/cache-salt/v1\x00"))
	_, _ = digest.Write([]byte(tenantID))
	return base64.RawURLEncoding.EncodeToString(digest.Sum(nil))
}

func NewTenantRegistry(specs []TenantSpec, cacheSaltSecret CacheSaltSecret) (*TenantRegistry, error) {
	if len(specs) == 0 {
		return nil, errors.New("at least one tenant is required")
	}
	registry := &TenantRegistry{byCredential: make(map[[sha256.Size]byte]*TenantPolicy, len(specs))}
	identities := make(map[string]struct{}, len(specs))
	for _, spec := range specs {
		if !tenantIDPattern.MatchString(spec.TenantID) {
			return nil, fmt.Errorf("invalid tenant_id %q", spec.TenantID)
		}
		if _, exists := identities[spec.TenantID]; exists {
			return nil, fmt.Errorf("duplicate tenant_id %q", spec.TenantID)
		}
		identities[spec.TenantID] = struct{}{}
		digestBytes, err := hex.DecodeString(spec.CredentialSHA256)
		if err != nil || len(digestBytes) != sha256.Size || strings.ToLower(spec.CredentialSHA256) != spec.CredentialSHA256 {
			return nil, fmt.Errorf("tenant %q credential_sha256 must be 64 lowercase hexadecimal characters", spec.TenantID)
		}
		var digest [sha256.Size]byte
		copy(digest[:], digestBytes)
		if _, exists := registry.byCredential[digest]; exists {
			return nil, errors.New("tenant credentials must be unique")
		}
		if len(spec.Models) == 0 {
			return nil, fmt.Errorf("tenant %q must allow at least one model", spec.TenantID)
		}
		models := make(map[string]struct{}, len(spec.Models))
		for _, model := range spec.Models {
			if model == "" || strings.TrimSpace(model) != model {
				return nil, fmt.Errorf("tenant %q has an invalid model", spec.TenantID)
			}
			if _, exists := models[model]; exists {
				return nil, fmt.Errorf("tenant %q has duplicate model %q", spec.TenantID, model)
			}
			models[model] = struct{}{}
		}
		if spec.MaxRequestBytes <= 0 || spec.MaxOutputTokens <= 0 || spec.RequestRateLimit <= 0 || spec.RateWindowMS <= 0 || spec.MaxConcurrent <= 0 {
			return nil, fmt.Errorf("tenant %q limits must be positive", spec.TenantID)
		}
		if spec.RateWindowMS > int64((24*time.Hour)/time.Millisecond) {
			return nil, fmt.Errorf("tenant %q request rate window must not exceed 24 hours", spec.TenantID)
		}
		policy := &TenantPolicy{
			ID: spec.TenantID, MaxRequestBytes: spec.MaxRequestBytes,
			MaxOutputTokens: spec.MaxOutputTokens, RequestRateLimit: spec.RequestRateLimit,
			RequestRateWindow: time.Duration(spec.RateWindowMS) * time.Millisecond,
			MaxConcurrent:     spec.MaxConcurrent, credentialDigest: digest, models: models,
			cacheSalt: deriveCacheSalt(cacheSaltSecret, spec.TenantID),
		}
		registry.byCredential[digest] = policy
	}
	return registry, nil
}

func LoadTenantRegistry(reader io.Reader, cacheSaltSecret CacheSaltSecret) (*TenantRegistry, error) {
	const maxTenantConfigurationBytes = 1 << 20
	payload, err := io.ReadAll(io.LimitReader(reader, maxTenantConfigurationBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read tenant configuration: %w", err)
	}
	if len(payload) > maxTenantConfigurationBytes {
		return nil, fmt.Errorf("tenant configuration exceeds %d bytes", maxTenantConfigurationBytes)
	}
	if !json.Valid(payload) {
		return nil, errors.New("tenant configuration must be valid JSON")
	}
	if err := validateUniqueJSONMembers(payload); err != nil {
		return nil, fmt.Errorf("tenant configuration: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var document tenantDocument
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("decode tenant configuration: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, errors.New("tenant configuration must contain one JSON object")
	}
	return NewTenantRegistry(document.Tenants, cacheSaltSecret)
}

func (r *TenantRegistry) Authenticate(authorization string) (*TenantPolicy, error) {
	if r == nil {
		return nil, ErrUnauthenticated
	}
	scheme, credential, found := strings.Cut(authorization, " ")
	if !found || !strings.EqualFold(scheme, "Bearer") {
		return nil, ErrUnauthenticated
	}
	if credential == "" || strings.TrimSpace(credential) != credential || strings.ContainsAny(credential, "\t\r\n ") {
		return nil, ErrUnauthenticated
	}
	digest := sha256.Sum256([]byte(credential))
	policy, ok := r.byCredential[digest]
	if !ok {
		return nil, ErrUnauthenticated
	}
	return policy, nil
}
