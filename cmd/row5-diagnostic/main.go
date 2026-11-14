// Command row5-diagnostic sends one production Redis admit and releases an
// allowed reservation. The controlling composition must bind both supplied
// gateway configurations to captured live sources before invoking it.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	redis "github.com/redis/go-redis/v9"
	"multi-tenant-llm-inference-platform/internal/admission"
)

type config struct {
	Addr           string `json:"redis_addr"`
	Namespace      string `json:"namespace"`
	GlobalCapacity int64  `json:"global_capacity"`
	LeaseMS        int64  `json:"lease_ms"`
	TombstoneMS    int64  `json:"tombstone_ms"`
	Running        int64  `json:"running"`
	Waiting        int64  `json:"waiting"`
	TTLMS          int64  `json:"ttl_ms"`
	HoldMS         int64  `json:"hold_ms"`
	Capture        bool   `json:"capture"`
}
type input struct {
	Config        config `json:"config"`
	Gateway0      config `json:"gateway0"`
	Gateway1      config `json:"gateway1"`
	DialAddr      string `json:"dial_addr"`
	ReservationID string `json:"reservation_id"`
}
type receipt struct {
	ReservationID string `json:"reservation_id"`
	Decision      string `json:"decision"`
	Capacity      int64  `json:"capacity"`
	Released      bool   `json:"released"`
}

func execute(ctx context.Context, in input) (receipt, error) {
	if in.Config != in.Gateway0 || in.Config != in.Gateway1 || in.Config.Addr == "" {
		return receipt{}, errors.New("row5:gateway_config_mismatch")
	}
	if !validDialAddr(in.DialAddr) {
		return receipt{}, errors.New("row5:invalid_dial_addr")
	}
	cfg := in.Config
	if cfg.LeaseMS <= 0 || cfg.LeaseMS > 86400000 || cfg.TombstoneMS <= 0 || cfg.TombstoneMS > 86400000 || cfg.TTLMS != 8000 || cfg.HoldMS != 2000 {
		return receipt{}, errors.New("row5:invalid_duration")
	}
	client := redis.NewClient(&redis.Options{Addr: in.DialAddr, Protocol: 2, MaxRetries: -1, DialTimeout: time.Second, ReadTimeout: time.Second, WriteTimeout: time.Second, ContextTimeoutEnabled: true})
	defer client.Close()
	rc := admission.RedisConfig{MeasurementCapture: cfg.Capture, Namespace: cfg.Namespace, GlobalCapacity: cfg.GlobalCapacity, LeaseDuration: time.Duration(cfg.LeaseMS) * time.Millisecond, TombstoneTTL: time.Duration(cfg.TombstoneMS) * time.Millisecond, DynamicCapacity: &admission.DynamicCapacityConfig{Running: cfg.Running, Waiting: cfg.Waiting, ReportTTL: time.Duration(cfg.TTLMS) * time.Millisecond, HoldDown: time.Duration(cfg.HoldMS) * time.Millisecond}}
	coordinator, err := admission.NewRedisCoordinator(client, rc)
	if err != nil {
		return receipt{}, err
	}
	diagnostic, err := admission.NewRow5Diagnostic(coordinator, rc)
	if err != nil {
		return receipt{}, err
	}
	return executeRequest(ctx, diagnostic, in.ReservationID)
}

func validDialAddr(address string) bool {
	host, port, err := net.SplitHostPort(address)
	if err != nil || host == "" || port == "" {
		return false
	}
	if !validDialHost(host) {
		return false
	}
	for _, digit := range port {
		if digit < '0' || digit > '9' {
			return false
		}
	}
	number, err := strconv.ParseUint(port, 10, 16)
	return err == nil && number > 0
}

func validDialHost(host string) bool {
	if net.ParseIP(host) != nil {
		return true
	}
	hostname := strings.TrimSuffix(host, ".")
	if hostname == "" || len(hostname) > 253 {
		return false
	}
	for _, label := range strings.Split(hostname, ".") {
		if len(label) == 0 || len(label) > 63 || !asciiAlphaNumeric(label[0]) || !asciiAlphaNumeric(label[len(label)-1]) {
			return false
		}
		for i := 0; i < len(label); i++ {
			if !asciiAlphaNumeric(label[i]) && label[i] != '-' {
				return false
			}
		}
	}
	return true
}

func asciiAlphaNumeric(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9'
}

type diagnosticClient interface {
	Admit(context.Context, string) (admission.Result, error)
	Release(context.Context, string) error
}

func executeRequest(ctx context.Context, diagnostic diagnosticClient, reservationID string) (receipt, error) {
	out := receipt{ReservationID: reservationID, Decision: "unknown", Capacity: -1}
	result, err := diagnostic.Admit(ctx, reservationID)
	if err != nil {
		return out, err
	}
	out.Decision, out.Capacity = result.Decision.Code(), result.Capacity
	if result.Decision == admission.Allowed {
		if err = diagnostic.Release(ctx, reservationID); err != nil {
			return out, fmt.Errorf("row5:release_failed: %w", err)
		}
		out.Released = true
	}
	return out, nil
}

func decodeInput(reader io.Reader) (input, error) {
	data, err := io.ReadAll(io.LimitReader(reader, 16385))
	if err != nil || len(data) > 16384 {
		return input{}, errors.New("row5:invalid_input")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var in input
	if err := decoder.Decode(&in); err != nil {
		return input{}, errors.New("row5:invalid_input")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return input{}, errors.New("row5:invalid_input")
	}
	return in, nil
}

func main() {
	in, err := decodeInput(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := execute(ctx, in)
	if err != nil {
		_ = json.NewEncoder(os.Stdout).Encode(out)
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err = json.NewEncoder(os.Stdout).Encode(out); err != nil {
		os.Exit(1)
	}
}
