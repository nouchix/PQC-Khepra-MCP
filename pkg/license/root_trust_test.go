//go:build !devroot

package license

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A release build must trust only the compiled-in root. The environment and
// ~/.khepra/master.pub used to override it, so anyone who controlled either
// could make their own signing key the root.
func TestLoadMasterPublicKey_IgnoresEnvAndFileOverrides(t *testing.T) {
	attacker, err := NewSovereignLicenseAuthority("", "")
	if err != nil {
		t.Fatalf("NewSovereignLicenseAuthority: %v", err)
	}
	attackerHex := hex.EncodeToString(attacker.PublicKey)

	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".khepra"), 0o700); err != nil {
		t.Fatal(err)
	}
	pubPath := filepath.Join(home, ".khepra", "master.pub")
	if err := os.WriteFile(pubPath, []byte(attackerHex), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("KHEPRA_MASTER_PUBLIC_KEY", attackerHex)
	t.Setenv("KHEPRA_MASTER_PUBLIC_KEY_PATH", pubPath)

	got, err := loadMasterPublicKey()
	if err != nil {
		t.Fatalf("loadMasterPublicKey: %v", err)
	}
	if !bytes.Equal(got, MasterPublicKey) {
		t.Fatal("release build returned an overridden master public key instead of the pinned MasterPublicKey")
	}
}

// The denylist must run inside VerifySovereignLicense itself, so every
// caller (offline file, MCP gate, QKD install) refuses a revoked license.
func TestVerifySovereignLicense_RejectsRevokedLicense(t *testing.T) {
	authority, err := NewSovereignLicenseAuthority("", "")
	if err != nil {
		t.Fatalf("NewSovereignLicenseAuthority: %v", err)
	}
	lic, err := authority.IssueLicense(testDeviceID(t), "Tenant", TierMaster, time.Hour)
	if err != nil {
		t.Fatalf("IssueLicense: %v", err)
	}
	lic.LicenseID = disclosedMasterLicenseID

	err = VerifySovereignLicense(lic, authority.PublicKey)
	if err == nil || !strings.Contains(err.Error(), "REVOKED") {
		t.Fatalf("expected the disclosed license to be rejected as revoked, got %v", err)
	}
}

func TestVerifyCapsuleSignature_RejectsMissingRoot(t *testing.T) {
	authority, err := NewSovereignLicenseAuthority("", "")
	if err != nil {
		t.Fatalf("NewSovereignLicenseAuthority: %v", err)
	}
	capsule := &LicenseCapsule{SignerPublicKey: authority.PublicKey}
	if err := verifyCapsuleSignature(capsule, nil); err == nil {
		t.Fatal("expected a capsule to be rejected when no pinned master public key is supplied")
	}
}

func TestVerifyLicense_RequiresTrustedRoot(t *testing.T) {
	authority, err := GenerateRootCA()
	if err != nil {
		t.Fatalf("GenerateRootCA: %v", err)
	}
	lic := &License{
		ID:        "self-signed-001",
		Tier:      TierSovereign,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	shuBreath, err := SignLicense(lic, authority, nil)
	if err != nil {
		t.Fatalf("SignLicense: %v", err)
	}
	if valid, err := VerifyLicense(shuBreath, nil); err == nil || valid {
		t.Fatalf("expected verification without a trusted root to fail, got valid=%v err=%v", valid, err)
	}
}
