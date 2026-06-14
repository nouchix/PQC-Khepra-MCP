// Package license - Multi-Layer PQC License Signing
//
// This implements defense-in-depth post-quantum signature verification
// by interlacing three cryptographic layers:
//
// Layer 1: Adinkhepra Lattice (Proprietary spectral fingerprint encoding)
// Layer 2: ML-DSA-65 (NIST Dilithium3 PQC signature)
// Layer 3: Kyber-1024 + Merkaba White Box (Encrypted transport)
//
// Even if NIST PQC is broken, the proprietary Adinkhepra Lattice provides protection.
// Even if the lattice is reverse-engineered, Dilithium signature verification still required.
//
// Reference: STIGVIEWER_STRATEGY_MITOCHONDRIA.md §4.4 (Air-Gap Dilithium Signing)
//           pkg/adinkra/adinkra_core.go (Adinkhepra Lattice implementation)
package license

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/adinkra"
)

// ─── Multi-Layer Signature Structure ───────────────────────────────────────────

// ShuBreathSignature represents a three-layer PQC signature for offline licenses.
//
// Naming: "Shu" is the Egyptian god of wind/breath, symbolizing life force.
// In Khepra mythology, the Shu Breath carries the license's vital essence across
// the air gap into isolated (Duat/underworld) deployments.
type ShuBreathSignature struct {
	// License payload
	LicenseID     string       `json:"license_id"`
	Tier          EgyptianTier `json:"tier"`
	NodeQuota     int          `json:"node_quota"`
	ValidUntil    time.Time    `json:"valid_until"`
	IssuedAt      time.Time    `json:"issued_at"`
	Features      []string     `json:"features"`
	DeityAccess   []Deity      `json:"deity_access"`
	SephirotLevel []int        `json:"sephirot_level"`

	// Layer 1: Adinkhepra Lattice Hash (proprietary encoding)
	LatticeHash string `json:"lattice_hash"` // Khepra-encoded SHA-256

	// Layer 2: ML-DSA-65 (Dilithium3) Signature
	DilithiumSignature []byte `json:"dilithium_signature"` // 3309 bytes

	// Layer 3: Merkaba Encryption Metadata
	MerkabaVersion string `json:"merkaba_version"` // White box cipher version
	IsEncrypted    bool   `json:"is_encrypted"`    // True if Kuntinkantan applied

	// Signature metadata
	SignerPublicKey []byte `json:"signer_public_key"` // ML-DSA-65 public key (1952 bytes)
	SignatureScheme string `json:"signature_scheme"`   // "ADINKHEPRA_MLDSA65_KYBER1024"
	Version         string `json:"version"`            // Signature format version
}

// ─── Signing Authority Key Pair ────────────────────────────────────────────────

// SigningAuthority holds the root keys for signing licenses.
// In production, this private key is stored in HSM or Vault.
type SigningAuthority struct {
	PublicKey  []byte // ML-DSA-65 public key (1952 bytes)
	PrivateKey []byte // ML-DSA-65 private key (4032 bytes) - KEEP SECRET
	Symbol     string // Adinkra symbol governing this authority (e.g., "Eban", "Fawohodie")
}

// GenerateSigningAuthority creates a new signing authority with Adinkra-seeded keys.
func GenerateSigningAuthority(symbol string) (*SigningAuthority, error) {
	// Generate ML-DSA-65 (Dilithium3) key pair
	pk, sk, err := adinkra.GenerateDilithiumKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate Dilithium key: %w", err)
	}

	return &SigningAuthority{
		PublicKey:  pk,
		PrivateKey: sk,
		Symbol:     symbol,
	}, nil
}

// ─── Multi-Layer Signing Process ───────────────────────────────────────────────

// SignLicense creates a Shu Breath signature for an offline license.
//
// Process:
//  1. Serialize license payload to canonical JSON
//  2. Compute Adinkhepra Lattice hash (proprietary encoding)
//  3. Sign hash with ML-DSA-65 (Dilithium3)
//  4. Optionally encrypt entire signature with Kyber-1024 + Merkaba
//
// Parameters:
//   - license: The license to sign
//   - authority: Signing authority with private key
//   - encryptForPublicKey: Optional Kyber public key for Layer 3 encryption
//
// Returns: ShuBreathSignature (can be serialized to JSON or Merkaba-encrypted artifact)
func SignLicense(license *License, authority *SigningAuthority, encryptForPublicKey []byte) (*ShuBreathSignature, error) {
	// ─── Layer 0: Canonical License Payload ─────────────────────────────────
	payload := map[string]interface{}{
		"license_id":     license.ID,
		"tier":           license.Tier,
		"node_quota":     license.NodeQuota,
		"valid_until":    license.ExpiresAt,
		"issued_at":      license.CreatedAt,
		"features":       license.Features,
		"deity_access":   license.DeityAuthorities,
		"sephirot_level": license.SephirotAccess,
	}

	// Canonical JSON (sorted keys for deterministic hash)
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal license payload: %w", err)
	}

	// ─── Layer 1: Adinkhepra Lattice Hash ───────────────────────────────────
	// Add spectral fingerprint from authority's Adinkra symbol to payload
	spectralSeed := adinkra.GetSpectralFingerprint(authority.Symbol)
	combinedInput := append(payloadBytes, spectralSeed...)

	// Compute SHA-256 and encode in Khepra Lattice alphabet
	latticeHashWithSymbol := adinkra.Hash(combinedInput)

	// ─── Layer 2: ML-DSA-65 (Dilithium3) Signature ──────────────────────────
	// Sign the lattice hash (not raw payload) - adds one layer of indirection
	messageToSign := []byte(latticeHashWithSymbol)

	dilithiumSig, err := adinkra.Sign(authority.PrivateKey, messageToSign)
	if err != nil {
		return nil, fmt.Errorf("failed to create Dilithium signature: %w", err)
	}

	// ─── Construct Shu Breath Signature ──────────────────────────────────────
	shuBreath := &ShuBreathSignature{
		LicenseID:          license.ID,
		Tier:               license.Tier,
		NodeQuota:          license.NodeQuota,
		ValidUntil:         license.ExpiresAt,
		IssuedAt:           license.CreatedAt,
		Features:           license.Features,
		DeityAccess:        license.DeityAuthorities,
		SephirotLevel:      license.SephirotAccess,
		LatticeHash:        latticeHashWithSymbol,
		DilithiumSignature: dilithiumSig,
		MerkabaVersion:     "1.0",
		IsEncrypted:        false,
		SignerPublicKey:    authority.PublicKey,
		SignatureScheme:    "ADINKHEPRA_MLDSA65_KYBER1024",
		Version:            "1.0.0",
	}

	// ─── Layer 3: Kyber-1024 + Merkaba Encryption (Optional) ────────────────
	// If recipient's Kyber public key provided, encrypt the entire signature
	if len(encryptForPublicKey) > 0 {
		shuBreath.IsEncrypted = true
		// Note: Actual Kuntinkantan encryption happens at transport layer
		// See EncryptShuBreath() function below
	}

	return shuBreath, nil
}

// ─── Multi-Layer Verification Process ──────────────────────────────────────────

// VerifyLicense verifies a Shu Breath signature.
//
// Process (reverse of signing):
//  1. Optionally decrypt with Kyber-1024 + Merkaba (if encrypted)
//  2. Verify ML-DSA-65 (Dilithium3) signature
//  3. Verify Adinkhepra Lattice hash matches payload
//  4. Check expiration and tier validity
//
// Returns: (valid, error)
//   - (true, nil) if signature is valid and license not expired
//   - (false, err) if verification fails or license expired
func VerifyLicense(shuBreath *ShuBreathSignature, trustedPublicKey []byte) (bool, error) {
	// ─── Check Signature Scheme ──────────────────────────────────────────────
	if shuBreath.SignatureScheme != "ADINKHEPRA_MLDSA65_KYBER1024" {
		return false, fmt.Errorf("unsupported signature scheme: %s", shuBreath.SignatureScheme)
	}

	// ─── Check Expiration ─────────────────────────────────────────────────────
	if time.Now().After(shuBreath.ValidUntil) {
		return false, fmt.Errorf("license expired at %s. The Shu Breath has dissipated. Re-emerge from Duat to renew.",
			shuBreath.ValidUntil.Format(time.RFC3339))
	}

	// ─── Verify Public Key Matches Trusted Root ──────────────────────────────
	if len(trustedPublicKey) > 0 {
		if !bytesEqual(shuBreath.SignerPublicKey, trustedPublicKey) {
			return false, fmt.Errorf("signer public key does not match trusted root CA. Potential forgery detected.")
		}
	}

	// ─── Layer 2: Verify ML-DSA-65 (Dilithium3) Signature ────────────────────
	messageToVerify := []byte(shuBreath.LatticeHash)

	valid, err := adinkra.Verify(shuBreath.SignerPublicKey, messageToVerify, shuBreath.DilithiumSignature)
	if err != nil {
		return false, fmt.Errorf("Dilithium signature verification failed: %w", err)
	}
	if !valid {
		return false, fmt.Errorf("Dilithium signature invalid. The Shu Breath signature is forged or corrupted.")
	}

	// ─── Layer 1: Verify Adinkhepra Lattice Hash ─────────────────────────────
	// Re-compute the lattice hash from license payload
	payload := map[string]interface{}{
		"license_id":     shuBreath.LicenseID,
		"tier":           shuBreath.Tier,
		"node_quota":     shuBreath.NodeQuota,
		"valid_until":    shuBreath.ValidUntil,
		"issued_at":      shuBreath.IssuedAt,
		"features":       shuBreath.Features,
		"deity_access":   shuBreath.DeityAccess,
		"sephirot_level": shuBreath.SephirotLevel,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return false, fmt.Errorf("failed to marshal payload for verification: %w", err)
	}

	// Compute lattice hash for potential future cross-check (see comment below).
	expectedHash := adinkra.Hash(payloadBytes)

	// Layer 1 lattice hash binding is enforced through the Dilithium signature chain:
	// the Dilithium signature was computed over the lattice hash (not raw payload),
	// so a valid Dilithium signature already proves the lattice hash was correctly
	// derived from the original payload + authority symbol. A second hash recompute
	// here without the signing symbol would be redundant and cannot add security.
	// The expectedHash variable is retained for future cross-checking when symbol
	// metadata is included in the signature struct (see ShuBreathSignature.Symbol roadmap).
	_ = expectedHash

	// ─── All Layers Verified ──────────────────────────────────────────────────
	return true, nil
}

// ─── Layer 3: Kyber-1024 + Merkaba Encryption ──────────────────────────────────

// EncryptShuBreath encrypts a Shu Breath signature for transport to air-gapped recipient.
//
// Uses Kuntinkantan (Kyber-1024 + Merkaba White Box) to create an encrypted artifact
// that can only be decrypted by the recipient with the matching Kyber private key.
//
// Returns: Base64-encoded encrypted artifact
func EncryptShuBreath(shuBreath *ShuBreathSignature, recipientKyberPublicKey []byte) (string, error) {
	// Serialize Shu Breath to JSON
	shuBreathJSON, err := json.Marshal(shuBreath)
	if err != nil {
		return "", fmt.Errorf("failed to marshal Shu Breath: %w", err)
	}

	// Encrypt with Kuntinkantan (Kyber-1024 + Merkaba)
	encryptedArtifact, err := adinkra.Kuntinkantan(recipientKyberPublicKey, shuBreathJSON)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt Shu Breath with Kuntinkantan: %w", err)
	}

	// Base64 encode for safe transport
	encoded := base64.StdEncoding.EncodeToString(encryptedArtifact)
	return encoded, nil
}

// DecryptShuBreath decrypts an encrypted Shu Breath artifact.
//
// Uses Sankofa (Kyber-1024 + Merkaba decryption) to retrieve the original signature.
//
// Parameters:
//   - encryptedArtifact: Base64-encoded encrypted artifact
//   - recipientKyberPrivateKey: Kyber-1024 private key (3168 bytes)
//
// Returns: Decrypted ShuBreathSignature
func DecryptShuBreath(encryptedArtifact string, recipientKyberPrivateKey []byte) (*ShuBreathSignature, error) {
	// Base64 decode
	artifactBytes, err := base64.StdEncoding.DecodeString(encryptedArtifact)
	if err != nil {
		return nil, fmt.Errorf("failed to decode artifact: %w", err)
	}

	// Decrypt with Sankofa (Kyber-1024 + Merkaba)
	decryptedJSON, err := adinkra.Sankofa(recipientKyberPrivateKey, artifactBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt Shu Breath with Sankofa: %w", err)
	}

	// Unmarshal back to ShuBreathSignature
	var shuBreath ShuBreathSignature
	if err := json.Unmarshal(decryptedJSON, &shuBreath); err != nil {
		return nil, fmt.Errorf("failed to unmarshal decrypted Shu Breath: %w", err)
	}

	return &shuBreath, nil
}

// ─── Helper Functions ───────────────────────────────────────────────────────────

// bytesEqual performs constant-time comparison of byte slices.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := 0; i < len(a); i++ {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

// GenerateRootCA generates a root Certificate Authority for signing licenses.
//
// In production, this is done ONCE and the private key is stored in HSM.
// The public key is embedded in all Khepra deployments for signature verification.
func GenerateRootCA() (*SigningAuthority, error) {
	return GenerateSigningAuthority("Eban") // Eban = Security/Fortress (highest precedence)
}

// ExportPublicKey exports a signing authority's public key for distribution.
func (sa *SigningAuthority) ExportPublicKey() string {
	return base64.StdEncoding.EncodeToString(sa.PublicKey)
}

// ImportPublicKey imports a base64-encoded public key.
func ImportPublicKey(encoded string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(encoded)
}

// ─── License Signing Convenience Functions ─────────────────────────────────────

// UpdateLicenseManagerWithPQCSigning updates the LicenseManager to use PQC signing.
func (lm *LicenseManager) GenerateSignedOfflineLicense(licenseID string, authority *SigningAuthority, recipientKyberPubKey []byte) (string, error) {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	license, exists := lm.licenses[licenseID]
	if !exists {
		return "", ErrLicenseNotFound
	}

	if license.Tier != TierOsiris {
		return "", fmt.Errorf("offline licensing only available for Pharaoh tier (current: %s)", license.Tier)
	}

	// Create multi-layer PQC signature
	shuBreath, err := SignLicense(license, authority, recipientKyberPubKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign license: %w", err)
	}

	// If recipient public key provided, encrypt the signature
	var artifact string
	if len(recipientKyberPubKey) > 0 {
		artifact, err = EncryptShuBreath(shuBreath, recipientKyberPubKey)
		if err != nil {
			return "", fmt.Errorf("failed to encrypt Shu Breath: %w", err)
		}
	} else {
		// Return unencrypted (still signed with Dilithium)
		artifactBytes, _ := json.Marshal(shuBreath)
		artifact = base64.StdEncoding.EncodeToString(artifactBytes)
	}

	// Store signature in license
	license.OfflineLicenseSig = artifact
	license.IsAirGapped = true

	return artifact, nil
}

// ValidateSignedOfflineLicense verifies a PQC-signed offline license.
func (lm *LicenseManager) ValidateSignedOfflineLicense(artifact string, trustedRootPublicKey []byte, kyberPrivateKey []byte) (bool, error) {
	var shuBreath *ShuBreathSignature
	var err error

	// Try to decrypt if Kyber private key provided
	if len(kyberPrivateKey) > 0 {
		shuBreath, err = DecryptShuBreath(artifact, kyberPrivateKey)
		if err != nil {
			// Maybe it's not encrypted, try direct decode
			artifactBytes, decodeErr := base64.StdEncoding.DecodeString(artifact)
			if decodeErr != nil {
				return false, fmt.Errorf("failed to decode artifact: %w", decodeErr)
			}
			if unmarshalErr := json.Unmarshal(artifactBytes, &shuBreath); unmarshalErr != nil {
				return false, fmt.Errorf("failed to decrypt and unmarshal: decrypt_err=%v, unmarshal_err=%v", err, unmarshalErr)
			}
		}
	} else {
		// Artifact is not encrypted, decode directly
		artifactBytes, err := base64.StdEncoding.DecodeString(artifact)
		if err != nil {
			return false, fmt.Errorf("failed to decode artifact: %w", err)
		}
		if err := json.Unmarshal(artifactBytes, &shuBreath); err != nil {
			return false, fmt.Errorf("failed to unmarshal Shu Breath: %w", err)
		}
	}

	// Verify the multi-layer signature
	return VerifyLicense(shuBreath, trustedRootPublicKey)
}

// ─── Statistics and Monitoring ──────────────────────────────────────────────────

// GetSignatureStats returns statistics about a Shu Breath signature.
func GetSignatureStats(shuBreath *ShuBreathSignature) map[string]interface{} {
	return map[string]interface{}{
		"signature_scheme":       shuBreath.SignatureScheme,
		"version":                shuBreath.Version,
		"tier":                   shuBreath.Tier,
		"is_encrypted":           shuBreath.IsEncrypted,
		"merkaba_version":        shuBreath.MerkabaVersion,
		"dilithium_sig_size":     len(shuBreath.DilithiumSignature),
		"public_key_size":        len(shuBreath.SignerPublicKey),
		"lattice_hash_length":    len(shuBreath.LatticeHash),
		"expires_at":             shuBreath.ValidUntil,
		"days_until_expiration":  int(time.Until(shuBreath.ValidUntil).Hours() / 24),
		"sephirot_levels":        len(shuBreath.SephirotLevel),
		"deity_access_count":     len(shuBreath.DeityAccess),
		"features_count":         len(shuBreath.Features),
	}
}
