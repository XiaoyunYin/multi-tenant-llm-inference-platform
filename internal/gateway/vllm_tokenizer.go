package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"sort"
	"time"
)

const maxVLLMTokenizeResponseBytes = 16 << 20

// VLLMRoutingKeyTokenizer obtains prompt IDs from the pinned vLLM replica's
// /tokenize endpoint. The request ID spreads the first attempt across replicas;
// retries then visit the remaining candidates in stable backend-ID order.
type VLLMRoutingKeyTokenizer struct {
	client       *http.Client
	attemptLimit time.Duration
	maxTokenIDs  int
}

func NewVLLMRoutingKeyTokenizer(client *http.Client, attemptLimit time.Duration, maxTokenIDs int) (*VLLMRoutingKeyTokenizer, error) {
	if client == nil {
		return nil, errors.New("vLLM routing tokenizer requires an HTTP client")
	}
	if attemptLimit <= 0 {
		return nil, errors.New("vLLM routing tokenizer attempt timeout must be positive")
	}
	if maxTokenIDs <= 0 || maxTokenIDs > 1<<20 {
		return nil, errors.New("vLLM routing tokenizer maximum token IDs must be between 1 and 1048576")
	}
	return &VLLMRoutingKeyTokenizer{client: client, attemptLimit: attemptLimit, maxTokenIDs: maxTokenIDs}, nil
}

func (t *VLLMRoutingKeyTokenizer) TokenizeChat(ctx context.Context, requestID, model string, messages []RoutingMessage, candidates []BackendCandidate) (RoutingTokenizationResult, error) {
	if ctx == nil {
		return RoutingTokenizationResult{}, errors.New("routing tokenization context is required")
	}
	if requestID == "" || model == "" || len(messages) == 0 {
		return RoutingTokenizationResult{}, errors.New("routing tokenization requires a request ID, model, and validated chat messages")
	}
	ordered := make([]BackendCandidate, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate.Backend != nil && candidate.Healthy && candidate.Ready && candidate.Backend.URL != nil {
			ordered = append(ordered, candidate)
		}
	}
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].Backend.ID != ordered[j].Backend.ID {
			return ordered[i].Backend.ID < ordered[j].Backend.ID
		}
		if ordered[i].Backend.Generation != ordered[j].Backend.Generation {
			return ordered[i].Backend.Generation < ordered[j].Backend.Generation
		}
		return ordered[i].Backend.URL.String() < ordered[j].Backend.URL.String()
	})
	if len(ordered) == 0 {
		return RoutingTokenizationResult{}, errors.New("no healthy ready replica is available for routing tokenization")
	}
	first := firstCandidateIndex(requestID, len(ordered))
	ordered = rotateCandidates(ordered, first)
	attempts := make([]string, 0, len(ordered))
	for _, candidate := range ordered {
		attempts = append(attempts, candidate.Backend.ID)
		attemptContext, cancel := context.WithTimeout(ctx, t.attemptLimit)
		tokenIDs, err := t.tokenizeReplica(attemptContext, model, messages, candidate.Backend)
		cancel()
		if err == nil {
			return RoutingTokenizationResult{TokenIDs: tokenIDs, AttemptedBackendIDs: attempts}, nil
		}
		if ctx.Err() != nil {
			break
		}
	}
	return RoutingTokenizationResult{AttemptedBackendIDs: attempts}, fmt.Errorf("routing tokenization failed on all %d healthy ready replicas", len(ordered))
}

func firstCandidateIndex(requestID string, candidateCount int) int {
	digest := sha256.Sum256([]byte(requestID))
	return int(binary.BigEndian.Uint64(digest[:8]) % uint64(candidateCount))
}

func rotateCandidates(candidates []BackendCandidate, first int) []BackendCandidate {
	rotated := make([]BackendCandidate, 0, len(candidates))
	rotated = append(rotated, candidates[first])
	for index, candidate := range candidates {
		if index != first {
			rotated = append(rotated, candidate)
		}
	}
	return rotated
}

func (t *VLLMRoutingKeyTokenizer) tokenizeReplica(ctx context.Context, model string, messages []RoutingMessage, backend *Backend) ([]uint32, error) {
	requestBody, err := json.Marshal(struct {
		Model               string           `json:"model"`
		Messages            []RoutingMessage `json:"messages"`
		AddGenerationPrompt bool             `json:"add_generation_prompt"`
	}{Model: model, Messages: messages, AddGenerationPrompt: true})
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, backend.URL.JoinPath("tokenize").String(), bytes.NewReader(requestBody))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := t.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("vLLM tokenize returned HTTP %d", response.StatusCode)
	}
	responseBytes, err := io.ReadAll(io.LimitReader(response.Body, maxVLLMTokenizeResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if len(responseBytes) > maxVLLMTokenizeResponseBytes {
		return nil, errors.New("vLLM tokenize response exceeded the configured safety limit")
	}
	var payload struct {
		Count  *int    `json:"count"`
		Tokens []int64 `json:"tokens"`
	}
	if err := json.Unmarshal(responseBytes, &payload); err != nil {
		return nil, err
	}
	if payload.Count == nil || *payload.Count < 0 || *payload.Count != len(payload.Tokens) {
		return nil, errors.New("vLLM tokenize response count did not match its tokens")
	}
	count := min(len(payload.Tokens), t.maxTokenIDs)
	tokenIDs := make([]uint32, count)
	for index, token := range payload.Tokens[:count] {
		if token < 0 || token > math.MaxUint32 {
			return nil, errors.New("vLLM tokenize response contained an out-of-range token ID")
		}
		tokenIDs[index] = uint32(token)
	}
	return tokenIDs, nil
}
