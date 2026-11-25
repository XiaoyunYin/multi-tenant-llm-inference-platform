package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"multi-tenant-llm-inference-platform/internal/admission"
)

func TestUsageCorrectionEvidenceBinding(t *testing.T) {
	dir := t.TempDir()
	receipt, evidence := filepath.Join(dir, "review.json"), filepath.Join(dir, "evidence")
	proof := []byte("synthetic runtime count evidence")
	want := admission.UsageCorrection{EvidenceSHA256: fmt.Sprintf("%x", sha256.Sum256(proof))}
	data, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(receipt, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(evidence, proof, 0600); err != nil {
		t.Fatal(err)
	}
	got, err := loadUsageCorrection(receipt, evidence)
	if err != nil || got.EvidenceSHA256 != want.EvidenceSHA256 {
		t.Fatalf("exact correction evidence did not bind: %v", err)
	}
	if err := os.WriteFile(evidence, []byte("changed evidence"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadUsageCorrection(receipt, evidence); !errors.Is(err, admission.ErrUsageBinding) {
		t.Fatalf("changed correction evidence did not refuse: %v", err)
	}
}
