package license

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// API-key format tests (kphr_{tier}_{base64url-payload})
// ---------------------------------------------------------------------------

// buildSignedLicenseFile constructs a licenseFile with a valid HMAC-SHA256
// signature using the same logic as verifySignature — sufficient for unit tests
// since the placeholder implementation uses HMAC, not ML-DSA-65 yet.
func buildSignedLicenseFile(t *testing.T, tier string, expiresIn time.Duration) licenseFile {
	t.Helper()

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

	// Reproduce the exact payload that verifySignature() builds.
	payload := map[string]string{
		"license_key": lf.LicenseKey,
		"tier":        lf.Tier,
		"customer_id": lf.CustomerID,
		"issued_at":   lf.IssuedAt,
		"expires_at":  lf.ExpiresAt,
		"version":     lf.Version,
		"algorithm":   lf.Algorithm,
	}
	payloadJSON, _ := json.Marshal(payload)

	mac := hmac.New(sha256.New, embeddedPublicKey)
	mac.Write(payloadJSON)
	lf.Signature = base64.StdEncoding.EncodeToString(mac.Sum(nil))

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
		{"sovereign", "sov"},
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
		"community": "com",
		"sovereign": "sov",
		"pharaoh":   "pha",
		"unknown":   "unk",
	}
	for tier, want := range cases {
		got := slugForTier(tier)
		if got != want {
			t.Errorf("slugForTier(%q): want %q, got %q", tier, want, got)
		}
	}
}

// minInt is a local helper for integer minimum (avoids shadowing Go 1.21+ builtin).
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
