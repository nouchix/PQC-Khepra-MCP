package license

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// ---------------------------------------------------------------------------
// API-key format tests (kphr_{tier}_{base64url-payload})
// ---------------------------------------------------------------------------

// useTestAPIKeyRoot replaces the pinned API-key root with a throwaway ML-DSA-65
// key for the duration of the test and returns its packed private key.
func useTestAPIKeyRoot(t *testing.T) []byte {
	t.Helper()
	pk, sk, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("mldsa65.GenerateKey: %v", err)
	}
	pub, _ := pk.MarshalBinary()
	priv, _ := sk.MarshalBinary()
	prev := apiKeyTrustedRoot
	apiKeyTrustedRoot = func() []byte { return pub }
	t.Cleanup(func() { apiKeyTrustedRoot = prev })
	return priv
}

// signLicenseFile signs lf's canonical payload with the given ML-DSA-65 key.
func signLicenseFile(t *testing.T, lf *licenseFile, priv []byte) {
	t.Helper()
	var sk mldsa65.PrivateKey
	if err := sk.UnmarshalBinary(priv); err != nil {
		t.Fatalf("unmarshal test key: %v", err)
	}
	sig := make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(&sk, canonicalPayload(t, *lf), nil, true, sig); err != nil {
		t.Fatalf("SignTo: %v", err)
	}
	lf.Signature = base64.StdEncoding.EncodeToString(sig)
}

// canonicalPayload reproduces the exact payload that verifySignature() builds.
func canonicalPayload(t *testing.T, lf licenseFile) []byte {
	t.Helper()
	payload := map[string]string{
		"license_key": lf.LicenseKey,
		"tier":        lf.Tier,
		"customer_id": lf.CustomerID,
		"issued_at":   lf.IssuedAt,
		"expires_at":  lf.ExpiresAt,
		"version":     lf.Version,
		"algorithm":   lf.Algorithm,
	}
	if lf.MachineID != "" {
		payload["machine_id"] = lf.MachineID
	}
	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	return b
}

// buildSignedLicenseFile constructs a licenseFile signed with ML-DSA-65 under a
// throwaway root installed for the duration of the test.
func buildSignedLicenseFile(t *testing.T, tier string, expiresIn time.Duration) licenseFile {
	t.Helper()
	priv := useTestAPIKeyRoot(t)

	lf := licenseFile{
		LicenseKey: "KHRPA-TEST-0000-0000-0001",
		Tier:       tier,
		CustomerID: "test-customer",
		IssuedAt:   time.Now().UTC().Format(time.RFC3339),
		ExpiresAt:  time.Now().Add(expiresIn).UTC().Format(time.RFC3339),
		Version:    "1",
		Algorithm:  "ML-DSA-65",
		MachineID:  "",
	}

	signLicenseFile(t, &lf, priv)
	return lf
}

// TestEncodeDecodeAPIKey verifies that EncodeAPIKey → ParseAPIKey round-trips.
func TestEncodeDecodeAPIKey(t *testing.T) {
	lf := buildSignedLicenseFile(t, "sovereign", 30*24*time.Hour)

	key, err := EncodeAPIKey(lf)
	if err != nil {
		t.Fatalf("EncodeAPIKey: %v", err)
	}

	if len(key) < 9 || key[:9] != "kphr_sov_" {
		t.Errorf("expected prefix kphr_sov_, got %q", key[:minInt(len(key), 12)])
	}

	decoded, err := ParseAPIKey(key)
	if err != nil {
		t.Fatalf("ParseAPIKey: %v", err)
	}
	if decoded.Tier != lf.Tier {
		t.Errorf("tier: want %q, got %q", lf.Tier, decoded.Tier)
	}
	if decoded.CustomerID != lf.CustomerID {
		t.Errorf("customer_id: want %q, got %q", lf.CustomerID, decoded.CustomerID)
	}
}

// TestValidateAPIKey_HappyPath validates a well-formed, unexpired, signed key.
func TestValidateAPIKey_HappyPath(t *testing.T) {
	lf := buildSignedLicenseFile(t, "sovereign", 30*24*time.Hour)
	key, _ := EncodeAPIKey(lf)

	parsed, err := ValidateAPIKey(key)
	if err != nil {
		t.Fatalf("ValidateAPIKey: %v", err)
	}
	if parsed.Tier != "sovereign" {
		t.Errorf("tier: want sovereign, got %q", parsed.Tier)
	}
}

// TestValidateAPIKey_AllTierSlugs ensures tier slug round-trip is correct.
func TestValidateAPIKey_AllTierSlugs(t *testing.T) {
	cases := []struct {
		tier string
		slug string
	}{
		{"community", "com"},
		{"pro", "pro"},
		{"enterprise", "ent"},
		{"sovereign", "sov"},
		{"master", "mas"},
		{"pharaoh", "pha"},
	}
	for _, tc := range cases {
		lf := buildSignedLicenseFile(t, tc.tier, 24*time.Hour)
		key, err := EncodeAPIKey(lf)
		if err != nil {
			t.Errorf("tier %s: EncodeAPIKey: %v", tc.tier, err)
			continue
		}
		wantPrefix := "kphr_" + tc.slug + "_"
		if len(key) < len(wantPrefix) || key[:len(wantPrefix)] != wantPrefix {
			t.Errorf("tier %s: want prefix %q, key starts with %q", tc.tier, wantPrefix, key[:minInt(len(key), 12)])
		}

		parsed, err := ValidateAPIKey(key)
		if err != nil {
			t.Errorf("tier %s: ValidateAPIKey: %v", tc.tier, err)
			continue
		}
		if parsed.Tier != tc.tier {
			t.Errorf("tier %s: want %q, got %q", tc.tier, tc.tier, parsed.Tier)
		}
	}
}

// TestValidateAPIKey_BadPrefix rejects non-kphr_ strings.
func TestValidateAPIKey_BadPrefix(t *testing.T) {
	_, err := ValidateAPIKey("sk-ant-api03-fakefakefake")
	if err == nil {
		t.Error("expected error for wrong prefix, got nil")
	}
}

// TestValidateAPIKey_UnknownSlug rejects unknown tier slugs.
func TestValidateAPIKey_UnknownSlug(t *testing.T) {
	_, err := ParseAPIKey("kphr_xyz_abc123")
	if err == nil {
		t.Error("expected error for unknown tier slug, got nil")
	}
}

// TestValidateAPIKey_MissingSegments rejects malformed keys.
func TestValidateAPIKey_MissingSegments(t *testing.T) {
	cases := []string{
		"kphr_",
		"kphr_sov",
		"kphr__payload",
	}
	for _, c := range cases {
		if _, err := ParseAPIKey(c); err == nil {
			t.Errorf("expected error for %q, got nil", c)
		}
	}
}

// TestValidateAPIKey_Expired rejects expired keys.
func TestValidateAPIKey_Expired(t *testing.T) {
	lf := buildSignedLicenseFile(t, "sovereign", -1*time.Hour)
	key, _ := EncodeAPIKey(lf)

	_, err := ValidateAPIKey(key)
	if err == nil {
		t.Error("expected expiry error, got nil")
	}
}

// TestValidateAPIKey_TierMismatch rejects keys where slug disagrees with payload tier.
func TestValidateAPIKey_TierMismatch(t *testing.T) {
	lf := buildSignedLicenseFile(t, "sovereign", 24*time.Hour)
	key, _ := EncodeAPIKey(lf)

	// Swap sov → pha in the prefix
	tampered := "kphr_pha_" + key[9:]
	_, err := ParseAPIKey(tampered)
	if err == nil {
		t.Error("expected tier mismatch error, got nil")
	}
}

// TestValidateEnv_KeyTakesPriority verifies KHEPRA_LICENSE_KEY takes priority
// over KHEPRA_LICENSE_PATH when both are set.
func TestValidateEnv_KeyTakesPriority(t *testing.T) {
	lf := buildSignedLicenseFile(t, "sovereign", 24*time.Hour)
	key, _ := EncodeAPIKey(lf)

	t.Setenv("KHEPRA_LICENSE_KEY", key)
	t.Setenv("KHEPRA_LICENSE_PATH", "/nonexistent/license.adinkhepra")

	parsed, err := ValidateEnv()
	if err != nil {
		t.Fatalf("ValidateEnv: %v", err)
	}
	if parsed.Tier != "sovereign" {
		t.Errorf("expected sovereign from KHEPRA_LICENSE_KEY, got %q", parsed.Tier)
	}
}

// TestValidateEnv_CommunityFallback verifies community fallback when both vars unset.
func TestValidateEnv_CommunityFallback(t *testing.T) {
	t.Setenv("KHEPRA_LICENSE_KEY", "")
	t.Setenv("KHEPRA_LICENSE_PATH", "")

	parsed, err := ValidateEnv()
	if err != ErrNoLicense {
		t.Errorf("expected ErrNoLicense, got %v", err)
	}
	if parsed == nil || parsed.Tier != TierCommunity {
		t.Errorf("expected community tier fallback, got %v", parsed)
	}
}

// TestSlugForTier verifies the tier → slug mapping.
func TestSlugForTier(t *testing.T) {
	cases := map[string]string{
		"community":  "com",
		"pro":        "pro",
		"enterprise": "ent",
		"sovereign":  "sov",
		"master":     "mas",
		"pharaoh":    "pha",
		"unknown":    "unk",
	}
	for tier, want := range cases {
		got := slugForTier(tier)
		if got != want {
			t.Errorf("slugForTier(%q): want %q, got %q", tier, want, got)
		}
	}
}

// TestGenerateSignedAPIKey tests the programmatic generation of API keys.
func TestGenerateSignedAPIKey(t *testing.T) {
	priv := useTestAPIKeyRoot(t)
	key, err := GenerateSignedAPIKey(priv, TierPro, "cus_test_123", time.Now().Add(30*24*time.Hour), "")
	if err != nil {
		t.Fatalf("GenerateSignedAPIKey: %v", err)
	}

	parsed, err := ValidateAPIKey(key)
	if err != nil {
		t.Fatalf("ValidateAPIKey on generated key: %v", err)
	}
	if parsed.Tier != TierPro {
		t.Errorf("tier: want %q, got %q", TierPro, parsed.Tier)
	}
	if parsed.CustomerID != "cus_test_123" {
		t.Errorf("customer_id: want %q, got %q", "cus_test_123", parsed.CustomerID)
	}
}

// TestValidateAPIKey_RevocationDenylist ensures that a key whose LicenseKey matches
// a revoked ID (Incident 2026-09-06) is rejected even if mathematically valid.
func TestValidateAPIKey_RevocationDenylist(t *testing.T) {
	priv := useTestAPIKeyRoot(t)
	lf := licenseFile{
		LicenseKey: "ce74939c-6af8-4a77-98b6-c9e179255771", // explicitly revoked in revoked.go
		Tier:       TierMaster,
		CustomerID: "test-customer",
		IssuedAt:   time.Now().UTC().Format(time.RFC3339),
		ExpiresAt:  time.Now().Add(30 * 24 * time.Hour).UTC().Format(time.RFC3339),
		Version:    "1",
		Algorithm:  "ML-DSA-65",
	}
	// Sign under the trusted test root so the signature is genuine and only the
	// denylist can reject it.
	signLicenseFile(t, &lf, priv)

	key, err := EncodeAPIKey(lf)
	if err != nil {
		t.Fatalf("EncodeAPIKey: %v", err)
	}

	_, err = ValidateAPIKey(key)
	if err == nil {
		t.Fatal("expected revoked license key to be rejected by ValidateAPIKey, but got nil error")
	}
}

// minInt is a local helper for integer minimum (avoids shadowing Go 1.21+ builtin).
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// The HMAC issuer is gone: a missing or non-ML-DSA key must be refused rather
// than silently falling back to a MAC keyed by a file in the repository.
func TestGenerateSignedAPIKey_RequiresMLDSAKey(t *testing.T) {
	for _, key := range [][]byte{nil, []byte("not-an-ml-dsa-key"), make([]byte, 32)} {
		if _, err := GenerateSignedAPIKey(key, TierPro, "cus_x", time.Now().Add(time.Hour), ""); err == nil {
			t.Errorf("expected an error for a %d-byte signer key", len(key))
		}
	}
}

// A key MAC'd with HMAC-SHA256, as the old webhook issued them, must never
// validate, whatever MAC key was used.
func TestValidateAPIKey_RejectsLegacyHMACKey(t *testing.T) {
	useTestAPIKeyRoot(t)
	lf := licenseFile{
		LicenseKey: "KHRPA-FORGED-0001",
		Tier:       TierPharaoh,
		CustomerID: "attacker",
		IssuedAt:   time.Now().UTC().Format(time.RFC3339),
		ExpiresAt:  time.Now().Add(365 * 24 * time.Hour).UTC().Format(time.RFC3339),
		Version:    "1",
		Algorithm:  "ML-DSA-65",
	}
	mac := hmac.New(sha256.New, []byte("any key at all"))
	mac.Write(canonicalPayload(t, lf))
	lf.Signature = base64.StdEncoding.EncodeToString(mac.Sum(nil))

	key, err := EncodeAPIKey(lf)
	if err != nil {
		t.Fatalf("EncodeAPIKey: %v", err)
	}
	_, err = ValidateAPIKey(key)
	if err == nil {
		t.Fatal("SECURITY REGRESSION: an HMAC-signed API key validated")
	}
	if !strings.Contains(err.Error(), "retired signing method") {
		t.Errorf("expected a retired-signing-method error, got: %v", err)
	}
}

// A well-formed ML-DSA-65 signature from a key other than the pinned root must
// be rejected.
func TestValidateAPIKey_RejectsUntrustedSigner(t *testing.T) {
	useTestAPIKeyRoot(t)
	_, attackerSK, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	attackerPriv, _ := attackerSK.MarshalBinary()
	lf := licenseFile{
		LicenseKey: "KHRPA-FORGED-0002",
		Tier:       TierPharaoh,
		CustomerID: "attacker",
		IssuedAt:   time.Now().UTC().Format(time.RFC3339),
		ExpiresAt:  time.Now().Add(365 * 24 * time.Hour).UTC().Format(time.RFC3339),
		Version:    "1",
		Algorithm:  "ML-DSA-65",
	}
	signLicenseFile(t, &lf, attackerPriv)
	key, err := EncodeAPIKey(lf)
	if err != nil {
		t.Fatalf("EncodeAPIKey: %v", err)
	}
	if _, err := ValidateAPIKey(key); err == nil {
		t.Fatal("SECURITY REGRESSION: an API key signed by an untrusted ML-DSA key validated")
	}
}
