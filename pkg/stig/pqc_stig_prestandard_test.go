package stig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// runPQC010010 writes src into a fresh directory, runs control PQC-010010 on
// it and returns the resulting finding.
func runPQC010010(t *testing.T, src string) Finding {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "crypto.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	result := &ValidationResult{}
	NewValidator(dir).checkPQC_010010(result, nil)
	for _, f := range result.Findings {
		if f.ID == "PQC-010010" {
			return f
		}
	}
	t.Fatal("PQC-010010 finding not produced")
	return Finding{}
}

// Pre-standard CRYSTALS-Kyber is not FIPS 203 ML-KEM. The scanner used to list
// "kyber" as approved and passed code that imported it.
func TestPQC010010_FailsPreStandardKyber(t *testing.T) {
	f := runPQC010010(t, `package x
import "github.com/cloudflare/circl/kem/kyber/kyber1024"
var _ = kyber1024.Scheme()
`)
	if f.Status != "Fail" {
		t.Fatalf("pre-standard Kyber must fail PQC-010010, got %q (%s)", f.Status, f.Actual)
	}
	if !strings.Contains(f.Actual, "kyber1024") {
		t.Errorf("finding should name the pre-standard identifier, got %q", f.Actual)
	}
}

func TestPQC010010_FailsPreStandardDilithium(t *testing.T) {
	f := runPQC010010(t, `package x
import "github.com/cloudflare/circl/sign/dilithium/mode3"
var _ = mode3.GenerateKey
`)
	if f.Status != "Fail" {
		t.Fatalf("pre-standard Dilithium must fail PQC-010010, got %q (%s)", f.Status, f.Actual)
	}
}

func TestPQC010010_PassesStandardizedOnly(t *testing.T) {
	f := runPQC010010(t, `package x
import (
	"crypto/mldsa"
	"crypto/mlkem"
)
var _, _ = mlkem.GenerateKey1024, mldsa.MLDSA87
`)
	if f.Status != "Pass" {
		t.Fatalf("ML-KEM/ML-DSA-only code should pass, got %q (%s)", f.Status, f.Actual)
	}
}

// Prose that mentions the old names, and ordinary words such as "guide",
// must not trigger the pre-standard or deprecated findings.
func TestPQC010010_IgnoresProseMentions(t *testing.T) {
	f := runPQC010010(t, `package x
// This guide explains how ML-KEM (formerly CRYSTALS-Kyber) replaces RSA.
import "crypto/mlkem"
var _ = mlkem.GenerateKey1024
`)
	if f.Status != "Pass" {
		t.Fatalf("prose mentions must not fail PQC-010010, got %q (%s)", f.Status, f.Actual)
	}
}
