package license

import (
	"testing"
	"time"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/adinkra"
)

// TestGenerateSigningAuthority verifies root CA generation
func TestGenerateSigningAuthority(t *testing.T) {
	authority, err := GenerateRootCA()
	if err != nil {
		t.Fatalf("Failed to generate root CA: %v", err)
	}

	if len(authority.PublicKey) == 0 {
		t.Error("Public key is empty")
	}

	if len(authority.PrivateKey) == 0 {
		t.Error("Private key is empty")
	}

	if authority.Symbol != "Eban" {
		t.Errorf("Expected symbol 'Eban', got '%s'", authority.Symbol)
	}
}

// TestSignAndVerifyLicense verifies the multi-layer signing process
func TestSignAndVerifyLicense(t *testing.T) {
	// 1. Create signing authority (root CA)
	authority, err := GenerateRootCA()
	if err != nil {
		t.Fatalf("Failed to generate root CA: %v", err)
	}

	// 2. Create test license
	license := &License{
		ID:        "test-pharaoh-001",
		Tier:      TierOsiris,
		NodeQuota: -1, // Unlimited
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().AddDate(1, 0, 0), // Valid for 1 year
		Features: []string{
			"all-features",
			"air-gap-licensing",
			"eternal-license",
		},
		DeityAuthorities: TierConfigurations[TierOsiris].DeityAuthorities,
		SephirotAccess:   TierConfigurations[TierOsiris].SephirotAccess,
	}

	// 3. Sign license (no encryption)
	shuBreath, err := SignLicense(license, authority, nil)
	if err != nil {
		t.Fatalf("Failed to sign license: %v", err)
	}

	// 4. Verify signature
	valid, err := VerifyLicense(shuBreath, authority.PublicKey)
	if err != nil {
		t.Fatalf("Signature verification failed: %v", err)
	}

	if !valid {
		t.Error("Signature should be valid but verification returned false")
	}

	// 5. Verify signature components
	if shuBreath.SignatureScheme != "ADINKHEPRA_MLDSA65_KYBER1024" {
		t.Errorf("Unexpected signature scheme: %s", shuBreath.SignatureScheme)
	}

	if len(shuBreath.DilithiumSignature) == 0 {
		t.Error("Dilithium signature is empty")
	}

	if len(shuBreath.LatticeHash) == 0 {
		t.Error("Lattice hash is empty")
	}

	if shuBreath.IsEncrypted {
		t.Error("Signature should not be encrypted (no recipient key provided)")
	}
}

// TestExpiredLicenseVerification verifies that expired licenses are rejected
func TestExpiredLicenseVerification(t *testing.T) {
	authority, err := GenerateRootCA()
	if err != nil {
		t.Fatalf("Failed to generate root CA: %v", err)
	}

	// Create expired license
	license := &License{
		ID:        "test-expired-001",
		Tier:      TierOsiris,
		NodeQuota: -1,
		CreatedAt: time.Now().AddDate(-1, 0, -1), // Created over a year ago
		ExpiresAt: time.Now().AddDate(0, 0, -1),  // Expired yesterday
		Features:  []string{"all-features"},
		DeityAuthorities: TierConfigurations[TierOsiris].DeityAuthorities,
		SephirotAccess:   TierConfigurations[TierOsiris].SephirotAccess,
	}

	// Sign license
	shuBreath, err := SignLicense(license, authority, nil)
	if err != nil {
		t.Fatalf("Failed to sign license: %v", err)
	}

	// Verification should fail due to expiration
	valid, err := VerifyLicense(shuBreath, authority.PublicKey)
	if err == nil {
		t.Error("Expected expiration error, got nil")
	}

	if valid {
		t.Error("Expired license should not verify as valid")
	}
}

// TestForgeryDetection verifies that forged signatures are rejected
func TestForgeryDetection(t *testing.T) {
	// Create two different authorities
	authority1, _ := GenerateSigningAuthority("Eban")
	authority2, _ := GenerateSigningAuthority("Fawohodie")

	license := &License{
		ID:        "test-forgery-001",
		Tier:      TierOsiris,
		NodeQuota: -1,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().AddDate(1, 0, 0),
		Features:  []string{"all-features"},
		DeityAuthorities: TierConfigurations[TierOsiris].DeityAuthorities,
		SephirotAccess:   TierConfigurations[TierOsiris].SephirotAccess,
	}

	// Sign with authority1
	shuBreath, err := SignLicense(license, authority1, nil)
	if err != nil {
		t.Fatalf("Failed to sign license: %v", err)
	}

	// Try to verify with authority2's public key (should fail)
	valid, err := VerifyLicense(shuBreath, authority2.PublicKey)
	if err == nil {
		t.Error("Expected forgery detection error, got nil")
	}

	if valid {
		t.Error("Forged signature should not verify as valid")
	}
}

// TestEncryptDecryptShuBreath verifies Layer 3 encryption
func TestEncryptDecryptShuBreath(t *testing.T) {
	// 1. Create signing authority
	authority, err := GenerateRootCA()
	if err != nil {
		t.Fatalf("Failed to generate root CA: %v", err)
	}

	// 2. Generate Kyber key pair for recipient
	recipientPubKey, recipientPrivKey, err := adinkra.GenerateKyberKey()
	if err != nil {
		t.Fatalf("Failed to generate Kyber key pair: %v", err)
	}

	// 3. Create and sign license
	license := &License{
		ID:        "test-encrypted-001",
		Tier:      TierOsiris,
		NodeQuota: -1,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().AddDate(1, 0, 0),
		Features:  []string{"all-features"},
		DeityAuthorities: TierConfigurations[TierOsiris].DeityAuthorities,
		SephirotAccess:   TierConfigurations[TierOsiris].SephirotAccess,
	}

	shuBreath, err := SignLicense(license, authority, recipientPubKey)
	if err != nil {
		t.Fatalf("Failed to sign license: %v", err)
	}

	// 4. Encrypt the Shu Breath
	encryptedArtifact, err := EncryptShuBreath(shuBreath, recipientPubKey)
	if err != nil {
		t.Fatalf("Failed to encrypt Shu Breath: %v", err)
	}

	if len(encryptedArtifact) == 0 {
		t.Error("Encrypted artifact is empty")
	}

	// 5. Decrypt the Shu Breath
	decryptedShuBreath, err := DecryptShuBreath(encryptedArtifact, recipientPrivKey)
	if err != nil {
		t.Fatalf("Failed to decrypt Shu Breath: %v", err)
	}

	// 6. Verify decrypted signature matches original
	if decryptedShuBreath.LicenseID != shuBreath.LicenseID {
		t.Errorf("License ID mismatch: expected %s, got %s", shuBreath.LicenseID, decryptedShuBreath.LicenseID)
	}

	if decryptedShuBreath.LatticeHash != shuBreath.LatticeHash {
		t.Error("Lattice hash mismatch after decryption")
	}

	// 7. Verify the decrypted signature
	valid, err := VerifyLicense(decryptedShuBreath, authority.PublicKey)
	if err != nil {
		t.Fatalf("Verification after decryption failed: %v", err)
	}

	if !valid {
		t.Error("Decrypted signature should verify as valid")
	}
}

// TestLicenseManagerPQCIntegration verifies LicenseManager PQC signing integration
func TestLicenseManagerPQCIntegration(t *testing.T) {
	// 1. Create license manager
	lm := NewLicenseManager("")

	// 2. Create Pharaoh license
	license, err := lm.CreateLicense("pharaoh-test-001", TierOsiris, 365)
	if err != nil {
		t.Fatalf("Failed to create license: %v", err)
	}

	// 3. Generate signing authority
	authority, err := GenerateRootCA()
	if err != nil {
		t.Fatalf("Failed to generate root CA: %v", err)
	}

	// 4. Generate recipient Kyber keys
	recipientPubKey, recipientPrivKey, err := adinkra.GenerateKyberKey()
	if err != nil {
		t.Fatalf("Failed to generate Kyber key pair: %v", err)
	}

	// 5. Generate signed offline license
	artifact, err := lm.GenerateSignedOfflineLicense(license.ID, authority, recipientPubKey)
	if err != nil {
		t.Fatalf("Failed to generate signed offline license: %v", err)
	}

	if len(artifact) == 0 {
		t.Error("Artifact is empty")
	}

	// 6. Validate the artifact
	valid, err := lm.ValidateSignedOfflineLicense(artifact, authority.PublicKey, recipientPrivKey)
	if err != nil {
		t.Fatalf("Offline license validation failed: %v", err)
	}

	if !valid {
		t.Error("Offline license should be valid")
	}

	// 7. Verify license was marked as air-gapped
	updatedLicense, _ := lm.GetLicense(license.ID)
	if !updatedLicense.IsAirGapped {
		t.Error("License should be marked as air-gapped")
	}

	if len(updatedLicense.OfflineLicenseSig) == 0 {
		t.Error("OfflineLicenseSig should be populated")
	}
}

// TestSignatureStats verifies signature statistics reporting
func TestSignatureStats(t *testing.T) {
	authority, err := GenerateRootCA()
	if err != nil {
		t.Fatalf("Failed to generate root CA: %v", err)
	}

	license := &License{
		ID:        "test-stats-001",
		Tier:      TierOsiris,
		NodeQuota: -1,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().AddDate(1, 0, 0),
		Features:  []string{"all-features", "air-gap-licensing"},
		DeityAuthorities: TierConfigurations[TierOsiris].DeityAuthorities,
		SephirotAccess:   TierConfigurations[TierOsiris].SephirotAccess,
	}

	shuBreath, err := SignLicense(license, authority, nil)
	if err != nil {
		t.Fatalf("Failed to sign license: %v", err)
	}

	stats := GetSignatureStats(shuBreath)

	// Verify stats structure
	if stats["signature_scheme"] != "ADINKHEPRA_MLDSA65_KYBER1024" {
		t.Error("Incorrect signature scheme in stats")
	}

	if stats["tier"] != TierOsiris {
		t.Error("Incorrect tier in stats")
	}

	if stats["is_encrypted"] != false {
		t.Error("Incorrect encryption status in stats")
	}

	if stats["features_count"] != 2 {
		t.Errorf("Expected 2 features, got %v", stats["features_count"])
	}
}

// TestPublicKeyExportImport verifies key serialization
func TestPublicKeyExportImport(t *testing.T) {
	authority, err := GenerateRootCA()
	if err != nil {
		t.Fatalf("Failed to generate root CA: %v", err)
	}

	// Export public key
	exported := authority.ExportPublicKey()
	if len(exported) == 0 {
		t.Error("Exported public key is empty")
	}

	// Import public key
	imported, err := ImportPublicKey(exported)
	if err != nil {
		t.Fatalf("Failed to import public key: %v", err)
	}

	// Verify imported key matches original
	if !bytesEqual(imported, authority.PublicKey) {
		t.Error("Imported public key does not match original")
	}
}

// BenchmarkSignLicense measures signing performance
func BenchmarkSignLicense(b *testing.B) {
	authority, _ := GenerateRootCA()

	license := &License{
		ID:        "bench-license-001",
		Tier:      TierOsiris,
		NodeQuota: -1,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().AddDate(1, 0, 0),
		Features:  []string{"all-features"},
		DeityAuthorities: TierConfigurations[TierOsiris].DeityAuthorities,
		SephirotAccess:   TierConfigurations[TierOsiris].SephirotAccess,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := SignLicense(license, authority, nil)
		if err != nil {
			b.Fatalf("Sign failed: %v", err)
		}
	}
}

// BenchmarkVerifyLicense measures verification performance
func BenchmarkVerifyLicense(b *testing.B) {
	authority, _ := GenerateRootCA()

	license := &License{
		ID:        "bench-license-002",
		Tier:      TierOsiris,
		NodeQuota: -1,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().AddDate(1, 0, 0),
		Features:  []string{"all-features"},
		DeityAuthorities: TierConfigurations[TierOsiris].DeityAuthorities,
		SephirotAccess:   TierConfigurations[TierOsiris].SephirotAccess,
	}

	shuBreath, _ := SignLicense(license, authority, nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := VerifyLicense(shuBreath, authority.PublicKey)
		if err != nil {
			b.Fatalf("Verify failed: %v", err)
		}
	}
}
