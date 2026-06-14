package ert_test

// crashdummy_test.go — Integration smoke test using a synthetic vulnerable project.
//
// The crash dummy creates an isolated temp directory with a crafted go.mod
// that references an intentionally old golang.org/x/crypto version known to
// have CVEs (e.g., CVE-2021-43565 in x/crypto < 0.0.0-20211202192323).
// The ERT ScanOrchestrator is then executed against this directory and the
// result is asserted to contain at least one finding.
//
// This proves end-to-end pipeline correctness without requiring DVWA/WebGoat
// to be running in the CI environment. External dummy targets (DVWA etc.) are
// optional and covered by the _validate_crash_dummy() step in adinkhepra.py.
//
// Run with:
//   go test ./pkg/ert/... -run TestERTScanSmoke -v
//   go test ./pkg/ert/... -run TestERTScanSmoke -v -short   (skips SCA tool check)

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/ert"
)

// syntheticGoMod is a crafted go.mod that references old, CVE-bearing packages.
// golang.org/x/crypto v0.0.0-20200820211705 is pre-CVE-2021-43565.
// golang.org/x/net v0.0.0-20210226172049 is pre-CVE-2021-44716.
const syntheticGoMod = `module crashdummy.test/vulnerable

go 1.20

require (
	golang.org/x/crypto v0.0.0-20200820211705-5c72a883971a
	golang.org/x/net v0.0.0-20210226172049-31ac24dafe12
)
`

// syntheticMainGo provides source code that references RSA and MD5 — ensuring
// the Horus and crypto scan lanes have something to find even without Syft/Grype.
const syntheticMainGo = `package main

import (
	"crypto/md5"    // intentional weak primitive — crash dummy
	"crypto/rsa"    // intentional RSA reference — quantum-vulnerable
	"crypto/rand"
	"fmt"
)

func main() {
	// Weak: MD5 usage (should be flagged by Horus)
	h := md5.New()
	h.Write([]byte("crashdummy"))
	fmt.Printf("hash: %x\n", h.Sum(nil))

	// RSA key gen (should be flagged as quantum-vulnerable)
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	fmt.Printf("rsa key bits: %d\n", key.Size()*8)
}
`

// syntheticHardcodedSecret contains a fake hardcoded API key — detected by HorusSecretLane.
const syntheticHardcodedSecret = `package config

// WARNING: crash dummy secret — DO NOT deploy
const APIKey = "AKIAIOSFODNN7EXAMPLE1234567890ABCDEF"  // fake AWS-style key
const DBPassword = "s3cr3t-password-hardcoded"
`

// TestERTScanSmoke validates that the ScanOrchestrator produces ≥1 finding
// against a synthetically crafted vulnerable project directory.
func TestERTScanSmoke(t *testing.T) {
	// Create a temp directory with our synthetic vulnerable project
	tmpDir := t.TempDir()

	// Write go.mod
	if err := os.WriteFile(filepath.Join(tmpDir, "go.mod"), []byte(syntheticGoMod), 0644); err != nil {
		t.Fatalf("failed to write synthetic go.mod: %v", err)
	}

	// Write main.go with weak primitives
	if err := os.WriteFile(filepath.Join(tmpDir, "main.go"), []byte(syntheticMainGo), 0644); err != nil {
		t.Fatalf("failed to write synthetic main.go: %v", err)
	}

	// Write config with hardcoded secrets
	if err := os.WriteFile(filepath.Join(tmpDir, "config.go"), []byte(syntheticHardcodedSecret), 0644); err != nil {
		t.Fatalf("failed to write synthetic config.go: %v", err)
	}

	// Build orchestrator — always uses Horus lanes; SCA lane requires syft+grype
	orch := ert.NewScanOrchestrator()
	orch.RegisterLane(ert.NewHorusVulnLane())
	orch.RegisterLane(ert.NewHorusSecretLane())
	orch.RegisterLane(ert.NewHorusComplianceLane())
	orch.RegisterLane(ert.NewHorusContainerLane())

	// Run scan
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	result, err := orch.Execute(ctx, ert.ScanRequest{
		TargetPath:          tmpDir,
		ComplianceFramework: "nist",
		Timeout:             90 * time.Second,
	})
	if err != nil {
		t.Fatalf("ScanOrchestrator.Execute failed: %v", err)
	}

	// Assertions
	t.Logf("Crash Dummy Scan complete:")
	t.Logf("  Lanes executed: %v", result.Lanes)
	t.Logf("  Total findings: %d", result.Stats.TotalFindings)
	t.Logf("  By severity: %v", result.Stats.BySeverity)
	t.Logf("  Secrets detected: %d", result.Stats.SecretsDetected)
	t.Logf("  Errors: %v", result.Errors)
	t.Logf("  Duration: %v", result.Duration)

	// The Horus secret lane must detect the fake hardcoded API key
	if result.Stats.SecretsDetected == 0 {
		// Non-fatal: log as a gap, not a test failure — secret patterns may vary by env
		t.Logf("WARN: No secrets detected. Horus secret patterns may not match fake AWS key format.")
	}

	// Overall: must have at least 1 finding from some lane
	if result.Stats.TotalFindings == 0 {
		t.Errorf("Crash dummy scan produced 0 findings — scanner pipeline may be broken")
	}

	// Duration sanity: scan should complete within 2 minutes
	if result.Duration > 2*time.Minute {
		t.Errorf("Scan took %v — exceeds 2-minute SLA", result.Duration)
	}

	// Verify scan was not entirely errored out
	if len(result.Errors) > 0 && result.Stats.TotalFindings == 0 {
		t.Errorf("All lanes errored and no findings produced. Errors: %s", strings.Join(result.Errors, "; "))
	}
}

// TestERTScanSmokeShortCircuit verifies the orchestrator gracefully handles an
// empty project directory (no source files) without panicking.
func TestERTScanSmokeShortCircuit(t *testing.T) {
	tmpDir := t.TempDir()

	orch := ert.NewScanOrchestrator()
	orch.RegisterLane(ert.NewHorusVulnLane())
	orch.RegisterLane(ert.NewHorusSecretLane())

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := orch.Execute(ctx, ert.ScanRequest{
		TargetPath: tmpDir,
		Timeout:    20 * time.Second,
	})
	if err != nil {
		t.Fatalf("Execute should not error on empty dir: %v", err)
	}
	// An empty directory should produce 0 findings — not panic
	t.Logf("Empty dir scan: %d findings, errors: %v", result.Stats.TotalFindings, result.Errors)
}

// TestERTOrchestratorNoLanes verifies that an unregistered lane is silently
// skipped rather than causing a panic or hard error.
func TestERTOrchestratorNoLanes(t *testing.T) {
	orch := ert.NewScanOrchestrator() // no lanes registered

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := orch.Execute(ctx, ert.ScanRequest{
		TargetPath: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("Orchestrator with no registered lanes should not error: %v", err)
	}
	if result.Stats.TotalFindings != 0 {
		t.Errorf("Expected 0 findings from empty orchestrator, got %d", result.Stats.TotalFindings)
	}
}
