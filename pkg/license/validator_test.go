package license_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nouchix/PQC-Khepra-MCP/pkg/license"
)

// TestCommunityFallback — no license file → community tier
func TestCommunityFallback(t *testing.T) {
	os.Unsetenv("KHEPRA_LICENSE_PATH")
	lic, err := license.ValidateFromEnv()
	if err != license.ErrNoLicense {
		t.Fatalf("expected ErrNoLicense, got %v", err)
	}
	if lic.Tier != license.TierCommunity {
		t.Fatalf("expected community tier, got %q", lic.Tier)
	}
}

// TestExpiredLicense — expired license is rejected
func TestExpiredLicense(t *testing.T) {
	path := writeLicenseFile(t, "sovereign", time.Now().Add(-48*time.Hour))
	_, err := license.Validate(path)
	if err == nil {
		t.Fatal("expected error for expired license")
	}
}

// TestHasFeature — tier gating
func TestHasFeature(t *testing.T) {
	community := &license.ParsedLicense{Tier: license.TierCommunity}
	sovereign := &license.ParsedLicense{Tier: license.TierSovereign}
	pharaoh := &license.ParsedLicense{Tier: license.TierPharaoh}

	if community.HasFeature("ert_scan") {
		t.Error("community should NOT have ert_scan")
	}
	if !sovereign.HasFeature("ert_scan") {
		t.Error("sovereign SHOULD have ert_scan")
	}
	if sovereign.HasFeature("priority_support") {
		t.Error("sovereign should NOT have priority_support")
	}
	if !pharaoh.HasFeature("priority_support") {
		t.Error("pharaoh SHOULD have priority_support")
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func writeLicenseFile(t *testing.T, tier string, expiresAt time.Time) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.adinkhepra")

	payload := map[string]string{
		"license_key": "KHRPA-TEST-0000-0000-0000",
		"tier":        tier,
		"customer_id": "cus_test",
		"issued_at":   time.Now().Add(-24 * time.Hour).Format(time.RFC3339),
		"expires_at":  expiresAt.Format(time.RFC3339),
		"version":     "1.0",
		"algorithm":   "ML-DSA-65",
		"signature":   "AAAA", // placeholder — real tests need valid sig
	}

	data, _ := json.MarshalIndent(payload, "", "  ")
	os.WriteFile(path, data, 0600)
	return path
}
