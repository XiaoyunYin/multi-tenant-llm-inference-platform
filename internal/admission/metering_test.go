package admission

import (
	"crypto/sha256"
	"fmt"
	"testing"
)

func TestMeteringOffUsesByteIdenticalAdmissionScript(t *testing.T) {
	// SHA-256 of the INF-058 slice's embedded Lua bytes (LF).
	const before = "8a07f5c4148548e773bd769a9611ea3f3fc3b930adb2669bf0cbfc1ab3c0d745"
	got := fmt.Sprintf("%x", sha256.Sum256([]byte(admissionSource(false))))
	if got != before {
		t.Fatalf("mode-off Redis script changed: %s", got)
	}
}
