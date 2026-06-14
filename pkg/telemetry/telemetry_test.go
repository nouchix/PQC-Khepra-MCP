package telemetry

import (
	"encoding/hex"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/types"
)

// ─── GenerateAnonymousID ──────────────────────────────────────────────────────

func TestGenerateAnonymousID_Format(t *testing.T) {
	id := GenerateAnonymousID()
	if id == "" {
		t.Fatal("GenerateAnonymousID returned empty string")
	}
	if len(id) != 64 {
		t.Errorf("expected 64-char hex (SHA-256), got %d chars", len(id))
	}
	if _, err := hex.DecodeString(id); err != nil {
		t.Errorf("GenerateAnonymousID is not valid hex: %v", err)
	}
}

func TestGenerateAnonymousID_Stable(t *testing.T) {
	id1 := GenerateAnonymousID()
	id2 := GenerateAnonymousID()
	if id1 != id2 {
		t.Errorf("GenerateAnonymousID is not stable across calls: %q != %q", id1, id2)
	}
}

func TestGenerateAnonymousID_MeetsServerRequirement(t *testing.T) {
	// The sovereign server requires ≥32 hex chars and valid hex.
	id := GenerateAnonymousID()
	if err := validateAnonymousID(id); err != nil {
		t.Errorf("GenerateAnonymousID does not meet sovereign server requirement: %v", err)
	}
}

// ─── validateAnonymousID ──────────────────────────────────────────────────────

func TestValidateAnonymousID_TooShort(t *testing.T) {
	if err := validateAnonymousID("aabbcc"); err == nil {
		t.Error("expected error for too-short anonymous_id, got nil")
	}
}

func TestValidateAnonymousID_NotHex(t *testing.T) {
	if err := validateAnonymousID(strings.Repeat("g", 32)); err == nil {
		t.Error("expected error for non-hex anonymous_id, got nil")
	}
}

func TestValidateAnonymousID_ValidMinimum(t *testing.T) {
	if err := validateAnonymousID(strings.Repeat("0", 32)); err != nil {
		t.Errorf("32-char hex should be valid: %v", err)
	}
}

func TestValidateAnonymousID_ValidFull(t *testing.T) {
	id := GenerateAnonymousID()
	if err := validateAnonymousID(id); err != nil {
		t.Errorf("GenerateAnonymousID result should be valid: %v", err)
	}
}

// ─── checkTelemetryEnabled ────────────────────────────────────────────────────

func TestCheckTelemetryEnabled_CommunityDefault(t *testing.T) {
	os.Unsetenv("KHEPRA_MODE")
	os.Unsetenv("KHEPRA_TELEMETRY")
	// Community mode default: opt-in required
	if err := checkTelemetryEnabled(); err == nil {
		t.Error("community mode without KHEPRA_TELEMETRY=true should return error")
	}
}

func TestCheckTelemetryEnabled_CommunityOptIn(t *testing.T) {
	os.Setenv("KHEPRA_MODE", "community")
	os.Setenv("KHEPRA_TELEMETRY", "true")
	t.Cleanup(func() {
		os.Unsetenv("KHEPRA_MODE")
		os.Unsetenv("KHEPRA_TELEMETRY")
	})
	if err := checkTelemetryEnabled(); err != nil {
		t.Errorf("community + KHEPRA_TELEMETRY=true should pass: %v", err)
	}
}

func TestCheckTelemetryEnabled_EnterpriseDefault(t *testing.T) {
	os.Setenv("KHEPRA_MODE", "enterprise")
	os.Unsetenv("KHEPRA_TELEMETRY")
	t.Cleanup(func() {
		os.Unsetenv("KHEPRA_MODE")
	})
	if err := checkTelemetryEnabled(); err != nil {
		t.Errorf("enterprise mode without opt-out should pass: %v", err)
	}
}

func TestCheckTelemetryEnabled_EnterpriseOptOut(t *testing.T) {
	os.Setenv("KHEPRA_MODE", "enterprise")
	os.Setenv("KHEPRA_TELEMETRY", "false")
	t.Cleanup(func() {
		os.Unsetenv("KHEPRA_MODE")
		os.Unsetenv("KHEPRA_TELEMETRY")
	})
	if err := checkTelemetryEnabled(); err == nil {
		t.Error("enterprise + KHEPRA_TELEMETRY=false should return error")
	}
}

// ─── SovereignBeaconPayload.canonical ────────────────────────────────────────

func TestSovereignBeaconPayload_Canonical_Deterministic(t *testing.T) {
	p := &SovereignBeaconPayload{
		TelemetryVersion: "2.0",
		AnonymousID:      strings.Repeat("ab", 16),
		LicenseTier:      "pilot",
		ScanCount:        42,
		FindingCount:     7,
		Timestamp:        "2026-05-07T12:00:00Z",
	}
	b1, err := p.canonical()
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	b2, err := p.canonical()
	if err != nil {
		t.Fatalf("canonical (2nd): %v", err)
	}
	if string(b1) != string(b2) {
		t.Error("canonical is not deterministic")
	}
}

func TestSovereignBeaconPayload_Canonical_ContainsFields(t *testing.T) {
	p := &SovereignBeaconPayload{
		TelemetryVersion: "2.0",
		AnonymousID:      strings.Repeat("cd", 16),
		LicenseTier:      "enterprise",
		ScanCount:        99,
		FindingCount:     3,
		Timestamp:        "2026-05-07T00:00:00Z",
	}
	b, err := p.canonical()
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	raw := string(b)
	for _, want := range []string{"2.0", "enterprise", "99", "3", "2026-05-07"} {
		if !strings.Contains(raw, want) {
			t.Errorf("canonical JSON missing %q; got: %s", want, raw)
		}
	}
}

func TestSovereignBeaconPayload_Canonical_ExcludesSignature(t *testing.T) {
	// The signature fields must NOT appear in the canonical payload; otherwise
	// the server's verification would require the client to know the signature
	// before signing — a circular dependency.
	p := &SovereignBeaconPayload{
		TelemetryVersion: "2.0",
		AnonymousID:      strings.Repeat("ef", 16),
		Signature:        []byte("should-not-appear"),
		SignerPublicKey:  []byte("also-should-not"),
	}
	b, err := p.canonical()
	if err != nil {
		t.Fatalf("canonical: %v", err)
	}
	raw := string(b)
	if strings.Contains(raw, "should-not-appear") {
		t.Error("canonical payload must not include Signature field")
	}
	if strings.Contains(raw, "also-should-not") {
		t.Error("canonical payload must not include SignerPublicKey field")
	}
}

// ─── primaryMACAddress ────────────────────────────────────────────────────────

func TestPrimaryMACAddress_NonEmpty(t *testing.T) {
	mac := primaryMACAddress()
	if mac == "" {
		t.Error("primaryMACAddress returned empty string")
	}
}

// ─── DetectContainerRuntime ───────────────────────────────────────────────────

func TestDetectContainerRuntime_ValidString(t *testing.T) {
	rt := DetectContainerRuntime()
	valid := map[string]bool{"docker": true, "podman": true, "kubernetes": true, "native": true}
	if !valid[rt] {
		t.Errorf("DetectContainerRuntime returned unexpected value: %q", rt)
	}
}

// ─── DetectGeographicHint ─────────────────────────────────────────────────────

func TestDetectGeographicHint_NonEmpty(t *testing.T) {
	// In non-cloud environments this should return "on-prem" within 2s×3 attempts.
	hint := DetectGeographicHint()
	if hint == "" {
		t.Error("DetectGeographicHint returned empty string")
	}
}

// ─── ExtractCryptoInventory ───────────────────────────────────────────────────

func TestExtractCryptoInventory_EmptySnapshot(t *testing.T) {
	// Empty snapshot must produce all-zero counts, not panic.
	inv := ExtractCryptoInventory(types.AuditSnapshot{})
	if inv.RSA2048Keys != 0 || inv.Dilithium3Keys != 0 {
		t.Errorf("empty snapshot should yield zero inventory: %+v", inv)
	}
}

func TestExtractCryptoInventory_PQCSignatureCountsDilithium(t *testing.T) {
	snap := types.AuditSnapshot{
		PQCSignature: &types.PQCSignature{
			Algorithm: "ML-DSA-65",
			SignedAt:  time.Now(),
		},
	}
	inv := ExtractCryptoInventory(snap)
	if inv.Dilithium3Keys != 1 {
		t.Errorf("PQCSignature with ML-DSA-65 should count as 1 Dilithium3 key, got %d", inv.Dilithium3Keys)
	}
}

func TestExtractCryptoInventory_Dilithium3AlgorithmName(t *testing.T) {
	snap := types.AuditSnapshot{
		PQCSignature: &types.PQCSignature{Algorithm: "Dilithium3"},
	}
	inv := ExtractCryptoInventory(snap)
	if inv.Dilithium3Keys != 1 {
		t.Errorf("PQCSignature Dilithium3 should count, got %d", inv.Dilithium3Keys)
	}
}

func TestExtractCryptoInventory_RSAFromComplianceFindings(t *testing.T) {
	snap := types.AuditSnapshot{
		Compliance: types.ComplianceReport{
			Findings: []types.ComplianceFinding{
				{Title: "RSA-2048 key in use", Description: "Found RSA-2048 key", Severity: "MEDIUM"},
				{Title: "RSA-4096 key detected", Description: "Found RSA-4096 in TLS cert", Severity: "LOW"},
				{Title: "P-256 ECDSA", Description: "ECC P-256 key found", Severity: "LOW"},
			},
		},
	}
	inv := ExtractCryptoInventory(snap)
	if inv.RSA2048Keys != 1 {
		t.Errorf("RSA2048Keys: want 1, got %d", inv.RSA2048Keys)
	}
	if inv.RSA4096Keys != 1 {
		t.Errorf("RSA4096Keys: want 1, got %d", inv.RSA4096Keys)
	}
	if inv.ECCP256Keys != 1 {
		t.Errorf("ECCP256Keys: want 1, got %d", inv.ECCP256Keys)
	}
}

func TestExtractCryptoInventory_WeakTLSFromHighSeverity(t *testing.T) {
	snap := types.AuditSnapshot{
		Compliance: types.ComplianceReport{
			Findings: []types.ComplianceFinding{
				{Title: "TLS 1.0 Enabled", Severity: "HIGH"},
				{Title: "SSL 3.0 vulnerability", Severity: "CRITICAL"},
				{Title: "TLS 1.2 config", Severity: "LOW"}, // should NOT count
			},
		},
	}
	inv := ExtractCryptoInventory(snap)
	if inv.TLSWeakConfigs != 2 {
		t.Errorf("TLSWeakConfigs: want 2, got %d", inv.TLSWeakConfigs)
	}
}

func TestExtractCryptoInventory_DeprecatedCiphersFromVulnerabilities(t *testing.T) {
	snap := types.AuditSnapshot{
		Vulnerabilities: []types.Vulnerability{
			{Description: "Server uses 3DES cipher suite"},
			{Description: "RC4 stream cipher detected in TLS"},
			{Description: "AES-256 in use"}, // should NOT count
		},
	}
	inv := ExtractCryptoInventory(snap)
	if inv.DeprecatedCiphers != 2 {
		t.Errorf("DeprecatedCiphers: want 2, got %d", inv.DeprecatedCiphers)
	}
}

func TestExtractCryptoInventory_DeprecatedCipherCountedOncePerVuln(t *testing.T) {
	// A single vulnerability description that matches multiple keywords
	// should only be counted once.
	snap := types.AuditSnapshot{
		Vulnerabilities: []types.Vulnerability{
			{Description: "3DES and RC4 both used by service"}, // matches 3DES first → count once
		},
	}
	inv := ExtractCryptoInventory(snap)
	if inv.DeprecatedCiphers != 1 {
		t.Errorf("DeprecatedCiphers: want 1 (one vuln), got %d", inv.DeprecatedCiphers)
	}
}

func TestExtractCryptoInventory_CaseInsensitiveMatching(t *testing.T) {
	snap := types.AuditSnapshot{
		Vulnerabilities: []types.Vulnerability{
			{Description: "server uses rc4 stream cipher"},
		},
		Compliance: types.ComplianceReport{
			Findings: []types.ComplianceFinding{
				{Title: "rsa-2048 key detected", Description: "found rsa-2048 usage", Severity: "LOW"},
			},
		},
	}
	inv := ExtractCryptoInventory(snap)
	if inv.DeprecatedCiphers != 1 {
		t.Errorf("case-insensitive deprecated cipher: want 1, got %d", inv.DeprecatedCiphers)
	}
	if inv.RSA2048Keys != 1 {
		t.Errorf("case-insensitive RSA-2048: want 1, got %d", inv.RSA2048Keys)
	}
}

// ─── signLegacy ───────────────────────────────────────────────────────────────

func TestSignLegacy_EmptyKeyErrors(t *testing.T) {
	_, err := signLegacy([]byte("payload"), "")
	if err == nil {
		t.Error("expected error for empty private key, got nil")
	}
}

func TestSignLegacy_InvalidHexErrors(t *testing.T) {
	_, err := signLegacy([]byte("payload"), "not-hex!!")
	if err == nil {
		t.Error("expected error for invalid hex key, got nil")
	}
}

func TestSignLegacy_WrongKeySizeErrors(t *testing.T) {
	// 32 bytes is not the right size for ML-DSA-65
	_, err := signLegacy([]byte("payload"), strings.Repeat("aa", 32))
	if err == nil {
		t.Error("expected error for wrong key size, got nil")
	}
}

// ─── hashID ───────────────────────────────────────────────────────────────────

func TestHashID_Deterministic(t *testing.T) {
	h1 := hashID("machine-abc-123")
	h2 := hashID("machine-abc-123")
	if h1 != h2 {
		t.Error("hashID is not deterministic")
	}
}

func TestHashID_Length(t *testing.T) {
	h := hashID("test")
	if len(h) != 64 {
		t.Errorf("hashID length: want 64, got %d", len(h))
	}
}

func TestHashID_DifferentInputsDifferentOutputs(t *testing.T) {
	if hashID("a") == hashID("b") {
		t.Error("hashID collision between distinct inputs")
	}
}
