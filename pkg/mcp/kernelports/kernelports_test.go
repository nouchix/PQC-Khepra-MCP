package kernelports

import (
	"context"
	"testing"
	"time"
)

func TestDefaults(t *testing.T) {
	deps := Defaults()
	ctx := context.Background()

	// Test NoopAttestor
	id, err := deps.Attestor.Append(ctx, "test_tool", []byte("in"), []byte("out"))
	if err != nil {
		t.Fatalf("Append failed: %v", err)
	}
	if id == "" {
		t.Fatalf("Append returned empty id")
	}

	env, err := deps.Attestor.SignEnvelope(ctx, "envelope")
	if err != nil {
		t.Fatalf("SignEnvelope failed: %v", err)
	}
	if env != "envelope" {
		t.Fatalf("SignEnvelope modified envelope")
	}

	// Test License gating: community tool allowed for free, enterprise tool blocked
	if err := deps.License.Check("pqc_stig"); err != nil {
		t.Fatalf("Community tool pqc_stig check failed: %v", err)
	}
	if err := deps.License.Check("cmmc_assess"); err == nil {
		t.Fatalf("Expected cmmc_assess to be gated for free users")
	}

	// Test NoopFlightRecorder
	if err := deps.Flight.Record(ctx, RecordInput{
		AgentID:   "test",
		StartedAt: time.Now(),
	}); err != nil {
		t.Fatalf("Record failed: %v", err)
	}
	if deps.Flight.Path() != "/dev/null" {
		t.Fatalf("Unexpected path: %s", deps.Flight.Path())
	}

	// Test SlogLogger
	deps.Logger.Log("INFO", "test message")
	deps.Logger.Log("ERROR", "test error")

	// Test NoopSigner
	sig, err := deps.Signer.Sign([]byte("key"), []byte("digest"))
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	if sig == nil {
		t.Fatalf("Sign returned nil")
	}

	ok, err := deps.Signer.Verify([]byte("key"), []byte("digest"), sig)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if !ok {
		t.Fatalf("Verify returned false")
	}
}
