package license

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nouchix/khepra-pqc/sign"
)

func newKey(t *testing.T) *sign.PrivateKey {
	t.Helper()
	k, err := sign.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// writeIssuerCert writes a delegation to a temp directory named by IssuerCertsEnv.
func writeIssuerCert(t *testing.T, cert []byte) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "issuer.json"), cert, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(IssuerCertsEnv, dir)
}

func TestIssuerSignedAPIKeyValidates(t *testing.T) {
	root, issuer := newKey(t), newKey(t)
	prev := apiKeyTrustedRoot
	apiKeyTrustedRoot = func() []byte { return root.PublicKey().Bytes() }
	t.Cleanup(func() { apiKeyTrustedRoot = prev })

	cert, err := IssueIssuerCertificate(root.Bytes(), issuer.PublicKey().Bytes(), []string{PurposeAPIKey},
		time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}

	key, err := GenerateSignedAPIKey(issuer.Bytes(), TierPlatform, "cus_1", time.Now().Add(30*24*time.Hour), "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateAPIKey(key); err == nil {
		t.Fatal("issuer-signed key accepted without a delegation certificate")
	}
	writeIssuerCert(t, cert)
	if _, err := ValidateAPIKey(key); err != nil {
		t.Fatalf("issuer-signed key rejected with a valid delegation: %v", err)
	}
}

func TestIssuerCertificateRejections(t *testing.T) {
	root, other, issuer := newKey(t), newKey(t), newKey(t)
	rootPub := root.PublicKey().Bytes()
	now := time.Now()

	expired, _ := IssueIssuerCertificate(root.Bytes(), issuer.PublicKey().Bytes(), []string{PurposeAPIKey}, now.Add(-48*time.Hour), now.Add(-time.Hour))
	if _, err := ParseIssuerCertificate(expired, rootPub, now); err == nil {
		t.Error("expired certificate accepted")
	}
	foreign, _ := IssueIssuerCertificate(other.Bytes(), issuer.PublicKey().Bytes(), []string{PurposeAPIKey}, now.Add(-time.Hour), now.Add(time.Hour))
	if _, err := ParseIssuerCertificate(foreign, rootPub, now); err == nil {
		t.Error("certificate signed by another key accepted")
	}
	licenseOnly, _ := IssueIssuerCertificate(root.Bytes(), issuer.PublicKey().Bytes(), []string{PurposeLicense}, now.Add(-time.Hour), now.Add(time.Hour))
	c, err := ParseIssuerCertificate(licenseOnly, rootPub, now)
	if err != nil {
		t.Fatal(err)
	}
	if c.allows(PurposeAPIKey) {
		t.Error("license-only certificate allows API keys")
	}
	if _, err := ParseIssuerCertificate(licenseOnly, make([]byte, legacyMLDSA65PublicKeySize), now); err == nil {
		t.Error("the legacy ML-DSA-65 root must not delegate")
	}
	if _, err := IssueIssuerCertificate(root.Bytes(), issuer.PublicKey().Bytes(), []string{"admin"}, now, now.Add(time.Hour)); err == nil {
		t.Error("unknown purpose accepted")
	}
}
