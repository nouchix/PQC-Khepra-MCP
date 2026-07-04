package license

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/nouchix/PQC-Khepra-MCP/pkg/fingerprint"
)

func testDeviceID(t *testing.T) string {
	t.Helper()
	fp, err := fingerprint.CollectDeviceFingerprint()
	if err != nil {
		t.Fatalf("device fingerprint: %v", err)
	}
	return GenerateDeviceID(fp)
}

// TestVerifySovereignLicense_RejectsForgedSelfSignedLicense locks in the fix for
// the bug where VerifySovereignLicense(lic, nil) fell back to lic.SignerPublicKey —
// trusting whatever key the license itself carried, which any self-signed
// KhepraLicense satisfies trivially. A pinned master key must reject a license
// signed by a different (attacker-controlled) key, even though the license is
// internally self-consistent.
func TestVerifySovereignLicense_RejectsForgedSelfSignedLicense(t *testing.T) {
	deviceID := testDeviceID(t)

	realAuthority, err := NewSovereignLicenseAuthority("", "")
	if err != nil {
		t.Fatalf("NewSovereignLicenseAuthority (real): %v", err)
	}
	attackerAuthority, err := NewSovereignLicenseAuthority("", "")
	if err != nil {
		t.Fatalf("NewSovereignLicenseAuthority (attacker): %v", err)
	}

	forged, err := attackerAuthority.IssueLicense(deviceID, "Attacker Inc.", TierMaster, 365*24*time.Hour)
	if err != nil {
		t.Fatalf("attacker IssueLicense: %v", err)
	}

	// Without pinning, this passes: it falls back to forged.SignerPublicKey,
	// which is exactly the key that signed it. This is the bug in isolation.
	if err := VerifySovereignLicense(forged, nil); err != nil {
		t.Fatalf("sanity check failed: a license should verify against its own embedded key: %v", err)
	}

	// Pinned against the REAL authority's key, the forged license must fail.
	if err := VerifySovereignLicense(forged, realAuthority.PublicKey); err == nil {
		t.Fatal("expected pinned verification to reject a license signed by a different authority")
	}

	// A license actually issued by the real authority must pass when pinned against it.
	genuine, err := realAuthority.IssueLicense(deviceID, "Real Tenant", TierMaster, 365*24*time.Hour)
	if err != nil {
		t.Fatalf("real IssueLicense: %v", err)
	}
	if err := VerifySovereignLicense(genuine, realAuthority.PublicKey); err != nil {
		t.Fatalf("expected genuine license to verify against the real authority's key: %v", err)
	}
}

// TestParseMCPLicense_RejectsForgedLicense confirms the live KHEPRA_LICENSE_KEY
// gate (used by cmd/khepra-mcp) rejects a self-signed forgery pinned against
// MasterPublicKey, not just the lower-level VerifySovereignLicense function.
func TestParseMCPLicense_RejectsForgedLicense(t *testing.T) {
	deviceID := testDeviceID(t)

	attackerAuthority, err := NewSovereignLicenseAuthority("", "")
	if err != nil {
		t.Fatalf("NewSovereignLicenseAuthority: %v", err)
	}
	forged, err := attackerAuthority.IssueLicense(deviceID, "Attacker Inc.", TierMaster, 365*24*time.Hour)
	if err != nil {
		t.Fatalf("IssueLicense: %v", err)
	}

	raw, err := json.Marshal(forged)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	t.Setenv("KHEPRA_LICENSE_KEY", string(raw))
	if _, err := ParseMCPLicense(); err == nil {
		t.Fatal("expected ParseMCPLicense to reject a forged license pinned against MasterPublicKey")
	}
}

// TestParseMCPLicense_AcceptsSacredEncoding confirms ParseMCPLicense accepts
// the customer-facing Sacred Runes encoding (EncodeLicenseDisplay), not just
// raw JSON, and that a genuine license round-trips through it successfully.
func TestParseMCPLicense_AcceptsSacredEncoding(t *testing.T) {
	deviceID := testDeviceID(t)

	authority, err := NewSovereignLicenseAuthority("", "")
	if err != nil {
		t.Fatalf("NewSovereignLicenseAuthority: %v", err)
	}
	lic, err := authority.IssueLicense(deviceID, "Demo Customer", TierEnterprise, 365*24*time.Hour)
	if err != nil {
		t.Fatalf("IssueLicense: %v", err)
	}

	sacred, err := EncodeLicenseDisplay(lic)
	if err != nil {
		t.Fatalf("EncodeLicenseDisplay: %v", err)
	}

	// Pin this test's authority key in place of the real MasterPublicKey by
	// round-tripping through DecodeLicenseDisplay + VerifySovereignLicense
	// directly, since ParseMCPLicense pins against the real compiled-in key
	// and this test's license is signed by a throwaway authority.
	decoded, err := DecodeLicenseDisplay(sacred)
	if err != nil {
		t.Fatalf("DecodeLicenseDisplay: %v", err)
	}
	if err := VerifySovereignLicense(decoded, authority.PublicKey); err != nil {
		t.Fatalf("expected sacred-encoded license to verify after round trip: %v", err)
	}

	// Confirm ParseMCPLicense's format-sniffing actually routes through
	// DecodeLicenseDisplay for non-JSON input (it will still fail signature
	// verification here since this license isn't signed by the pinned
	// MasterPublicKey — the point is that it gets to that check at all,
	// rather than failing at parse/decode).
	t.Setenv("KHEPRA_LICENSE_KEY", sacred)
	_, err = ParseMCPLicense()
	if err == nil || !strings.Contains(err.Error(), "sovereign verification failed") {
		t.Fatalf("expected ParseMCPLicense to decode the sacred format and fail at signature verification, got: %v", err)
	}
}
