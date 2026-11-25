package gateway

import (
	"context"
	"encoding/json"
	"errors"

	"multi-tenant-llm-inference-platform/internal/admission"
)

type usageLedger interface {
	UsageMeteringEnabled() bool
	BeginUsageDispatch(context.Context, admission.UsageAttempt, admission.UsagePins) error
	CheckpointUsage(context.Context, admission.UsageAttempt, admission.UsageCheckpoint) error
	FinalizeUsage(context.Context, admission.UsageAttempt, admission.UsagePins, string, bool) (admission.UsageTerminal, error)
}

type meteredAttempt struct {
	identity admission.UsageAttempt
	pins     admission.UsagePins
}

// WithUsagePins records configured provenance for metered attempts. The model
// name comes from the tenant-validated request.
func WithUsagePins(model, engine, tokenizer string) Option {
	return func(g *Gateway) error {
		pins := admission.UsagePins{Model: "model", ModelPin: model, Engine: engine, Tokenizer: tokenizer}
		if !admission.ValidUsagePins(pins) {
			return errors.New("invalid metering provenance pin")
		}
		g.usagePins = pins
		return nil
	}
}

func (g *Gateway) beginMeteredAttempt(tenant, reservation, request, model string) *meteredAttempt {
	pins := g.usagePins
	pins.Model = model
	return &meteredAttempt{identity: admission.UsageAttempt{
		TenantID: tenant, ReservationID: reservation, RequestID: request, OwnerEpoch: g.usageOwner,
	}, pins: pins}
}

func (g *Gateway) finishUsage(attempt *meteredAttempt, terminal requestTerminal) {
	g.writeUsageTerminal(attempt, terminal.cause.String(), terminal.committed, false)
}

func (g *Gateway) finishUncertainAdmission(tenant, reservation, request, model string) {
	g.bestEffortRelease(tenant, reservation, request)
	if g.usage != nil {
		g.writeUsageTerminal(g.beginMeteredAttempt(tenant, reservation, request, model), "rejected", false, true)
	}
}

func (g *Gateway) writeUsageTerminal(attempt *meteredAttempt, outcome string, committed, allowAbsent bool) {
	ctx, cancel := context.WithTimeout(context.Background(), g.config.ReleaseTimeout)
	defer cancel()
	_, err := g.usage.FinalizeUsage(ctx, attempt.identity, attempt.pins, outcome, committed)
	if err != nil && !(allowAbsent && errors.Is(err, admission.ErrUsageBinding)) {
		g.logger.Error("metering terminal write unavailable", "request_id", attempt.identity.RequestID)
	}
}

func (g *Gateway) recordRuntimeUsage(attempt *meteredAttempt, payload []byte) error {
	tokens := meteredRuntimeUsage(payload)
	if tokens == nil {
		return nil
	}
	writeCtx, cancel := context.WithTimeout(context.Background(), g.config.AdmissionTimeout)
	defer cancel()
	return g.usage.CheckpointUsage(writeCtx, attempt.identity, admission.UsageCheckpoint{Sequence: 1, Runtime: tokens})
}

// Called only for a usage frame accepted by validateEvent. Check field
// presence separately so the historical SSE wire representation stays intact.
func meteredRuntimeUsage(payload []byte) *admission.UsageTokens {
	var event struct {
		Usage struct {
			Prompt     *int64 `json:"prompt_tokens"`
			Completion *int64 `json:"completion_tokens"`
			Total      *int64 `json:"total_tokens"`
		} `json:"usage"`
	}
	if json.Unmarshal(payload, &event) != nil {
		return nil
	}
	counts := event.Usage
	if counts.Prompt == nil || counts.Completion == nil || counts.Total == nil ||
		*counts.Prompt < 0 || *counts.Completion < 0 ||
		*counts.Prompt > 1<<31-1 || *counts.Completion > 1<<31-1 ||
		*counts.Total != *counts.Prompt+*counts.Completion {
		return nil
	}
	return &admission.UsageTokens{Prompt: *counts.Prompt, Completion: *counts.Completion}
}
