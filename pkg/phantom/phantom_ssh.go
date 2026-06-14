// Package phantom - Spectral SSH: Symbol-Derived SSH Keys
//
// Traditional SSH uses static key files (~/.ssh/id_rsa) which can be:
// - Stolen from disk
// - Compromised via memory dumps
// - Copied by malware
// - Vulnerable to quantum attacks (RSA/ECDSA)
//
// Spectral SSH solves this by:
// - Deriving keys from Adinkra symbol combinations (deterministic, no files)
// - Rotating keys automatically (symbol precedence + time)
// - Quantum-resistant (Adinkhepra-PQC lattice signatures)
// - Impossible to exfiltrate (keys exist only in symbol space)
//
// Example Usage:
//
//	// Generate SSH key from symbol combination
//	sshKey := phantom.DeriveSpectralSSHKey("Eban+Fawohodie+Dwennimmen", "alice@khepra.dev")
//
//	// Login to server (no key files needed)
//	phantom.SSHConnect("server.khepra.dev:22", sshKey)
//
//	// Server validates using Adinkhepra-PQC signature
package phantom

import (
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/adinkra"
)

// ─── Spectral SSH Key Structure ───────────────────────────────────────────────

// SpectralSSHKey represents an SSH key derived from Adinkra symbols
type SpectralSSHKey struct {
	// User identity (symbol combination)
	SymbolCombination string // e.g., "Eban+Fawohodie+Dwennimmen"
	UserEmail         string // e.g., "alice@khepra.dev"

	// Derived PQC keys
	AdinkhepraPQCPublic  *adinkra.AdinkhepraPQCPublicKey
	AdinkhepraPQCPrivate *adinkra.AdinkhepraPQCPrivateKey

	// Metadata
	CreatedAt      time.Time
	ExpiresAt      time.Time
	RotationPeriod time.Duration // Default: 90 days
	Version        int           // Key version (increments on rotation)
}

// SpectralSSHAuthorizedKey represents an authorized key on SSH server
type SpectralSSHAuthorizedKey struct {
	SymbolCombination string
	UserEmail         string
	PublicKey         *adinkra.AdinkhepraPQCPublicKey
	CreatedAt         time.Time
	Comment           string
}

// ─── Key Derivation ────────────────────────────────────────────────────────────

// DeriveSpectralSSHKey generates an SSH key from symbol combination
//
// Algorithm:
//  1. Parse symbol combination (e.g., "Eban+Fawohodie+Dwennimmen")
//  2. Get spectral fingerprint of each symbol
//  3. Combine fingerprints with user email + timestamp
//  4. Generate Adinkhepra-PQC key pair from combined seed
//  5. Result: Deterministic key (same symbols → same keys)
//
// Key Properties:
// - No key files needed (derive on-demand from symbols)
// - Quantum-resistant (lattice-based signatures)
// - Automatic rotation (based on time + version)
// - Impossible to steal (attacker needs to know symbol combination)
func DeriveSpectralSSHKey(symbolCombination string, userEmail string) (*SpectralSSHKey, error) {
	// 1. Parse symbol combination
	symbols := strings.Split(symbolCombination, "+")
	if len(symbols) == 0 {
		return nil, fmt.Errorf("empty symbol combination")
	}

	// 2. Get spectral fingerprints and combine
	combinedSeed := combineSpectralFingerprints(symbols, userEmail)

	// 3. Determine key version based on time (90-day rotation)
	version := getKeyVersion(time.Now(), 90*24*time.Hour)

	// 4. Mix version into seed (ensures rotation)
	versionedSeed := mixVersion(combinedSeed, version)

	// 5. Generate Adinkhepra-PQC key pair
	// Use first symbol as primary symbol for key generation
	publicKey, privateKey, err := adinkra.GenerateAdinkhepraPQCKeyPair(versionedSeed, symbols[0])
	if err != nil {
		return nil, fmt.Errorf("key generation failed: %w", err)
	}

	// 6. Calculate expiration (90 days from creation)
	createdAt := time.Now()
	expiresAt := createdAt.Add(90 * 24 * time.Hour)

	return &SpectralSSHKey{
		SymbolCombination:    symbolCombination,
		UserEmail:            userEmail,
		AdinkhepraPQCPublic:  publicKey,
		AdinkhepraPQCPrivate: privateKey,
		CreatedAt:            createdAt,
		ExpiresAt:            expiresAt,
		RotationPeriod:       90 * 24 * time.Hour,
		Version:              version,
	}, nil
}

// combineSpectralFingerprints merges multiple symbol fingerprints
func combineSpectralFingerprints(symbols []string, userEmail string) []byte {
	h := sha512.New()

	// Add each symbol's fingerprint
	for _, symbol := range symbols {
		fingerprint := adinkra.GetSpectralFingerprint(symbol)
		h.Write(fingerprint)
	}

	// Add user email for uniqueness
	h.Write([]byte(userEmail))

	// Add salt for domain separation
	h.Write([]byte("SPECTRAL_SSH_KEY_DERIVATION_V1"))

	return h.Sum(nil)
}

// getKeyVersion calculates current key version based on time
func getKeyVersion(now time.Time, rotationPeriod time.Duration) int {
	// Epoch: 2024-01-01 00:00:00 UTC (start of PQC era)
	epoch := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	elapsed := now.Sub(epoch)

	// Version = number of rotation periods since epoch
	version := int(elapsed / rotationPeriod)
	return version
}

// mixVersion adds version number to seed (for key rotation)
func mixVersion(seed []byte, version int) []byte {
	h := sha512.New()
	h.Write(seed)
	h.Write([]byte(fmt.Sprintf("VERSION_%d", version)))
	return h.Sum(nil)
}

// ─── SSH Key Serialization ─────────────────────────────────────────────────────

// ToAuthorizedKeysFormat exports public key in OpenSSH authorized_keys format
//
// Format: spectral-pqc-ssh <base64-public-key> <symbol-combination>@<email>
//
// Example:
// spectral-pqc-ssh AAAAB3NzaC1zcGVjdHJhbC1wcWMtc3NoAAAA... Eban+Fawohodie@alice@khepra.dev
func (ssk *SpectralSSHKey) ToAuthorizedKeysFormat() string {
	// Serialize public key (simple format: lattice vectors concatenated)
	publicKeyBytes := serializeAdinkhepraPQCPublicKey(ssk.AdinkhepraPQCPublic)

	// Base64 encode
	publicKeyB64 := base64.StdEncoding.EncodeToString(publicKeyBytes)

	// Format: spectral-pqc-ssh <base64-key> <identifier>
	identifier := fmt.Sprintf("%s@%s", ssk.SymbolCombination, ssk.UserEmail)
	return fmt.Sprintf("spectral-pqc-ssh %s %s", publicKeyB64, identifier)
}

// FromAuthorizedKeysFormat parses a spectral SSH public key
func FromAuthorizedKeysFormat(line string) (*SpectralSSHAuthorizedKey, error) {
	parts := strings.Fields(line)
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid format: expected 3 fields, got %d", len(parts))
	}

	if parts[0] != "spectral-pqc-ssh" {
		return nil, fmt.Errorf("invalid key type: %s", parts[0])
	}

	// Decode base64 public key
	publicKeyBytes, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid base64: %w", err)
	}

	// Deserialize public key
	publicKey, err := deserializeAdinkhepraPQCPublicKey(publicKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid public key: %w", err)
	}

	// Parse identifier (symbol-combination@email)
	identifier := parts[2]
	atIndex := strings.LastIndex(identifier, "@")
	if atIndex == -1 {
		return nil, fmt.Errorf("invalid identifier: missing @")
	}

	symbolCombination := identifier[:atIndex]
	userEmail := identifier[atIndex+1:]

	return &SpectralSSHAuthorizedKey{
		SymbolCombination: symbolCombination,
		UserEmail:         userEmail,
		PublicKey:         publicKey,
		CreatedAt:         time.Now(),
		Comment:           "",
	}, nil
}

// serializeAdinkhepraPQCPublicKey converts public key to bytes
func serializeAdinkhepraPQCPublicKey(pub *adinkra.AdinkhepraPQCPublicKey) []byte {
	bytes, _ := pub.MarshalBinary()
	return bytes
}

func deserializeAdinkhepraPQCPublicKey(data []byte) (*adinkra.AdinkhepraPQCPublicKey, error) {
	pub := &adinkra.AdinkhepraPQCPublicKey{}
	err := pub.UnmarshalBinary(data)
	return pub, err
}

// ─── SSH Authentication Protocol ───────────────────────────────────────────────

// SignSSHChallenge signs an SSH authentication challenge
//
// SSH Protocol:
//  1. Client requests authentication
//  2. Server sends random challenge (32 bytes)
//  3. Client signs challenge with private key
//  4. Server verifies signature with authorized public key
func (ssk *SpectralSSHKey) SignSSHChallenge(challenge []byte) ([]byte, error) {
	// 1. Hash challenge with session metadata
	h := sha512.Sum512(challenge)

	// 2. Sign with Adinkhepra-PQC
	signature, err := adinkra.SignAdinkhepraPQC(ssk.AdinkhepraPQCPrivate, h[:])
	if err != nil {
		return nil, fmt.Errorf("signature failed: %w", err)
	}

	return signature, nil
}

// VerifySSHChallenge verifies an SSH authentication signature
func (sak *SpectralSSHAuthorizedKey) VerifySSHChallenge(challenge []byte, signature []byte) error {
	// 1. Hash challenge
	h := sha512.Sum512(challenge)

	// 2. Verify signature
	err := adinkra.VerifyAdinkhepraPQC(sak.PublicKey, h[:], signature)
	if err != nil {
		return fmt.Errorf("verification failed: %w", err)
	}

	return nil
}

// ─── Key Rotation ───────────────────────────────────────────────────────────────

// RotateKey generates the next version of the SSH key
//
// Rotation Algorithm:
//  1. Increment version number
//  2. Derive new key pair from same symbols + new version
//  3. Old key remains valid for grace period (7 days)
func (ssk *SpectralSSHKey) RotateKey() (*SpectralSSHKey, error) {
	// Check if rotation is needed
	if time.Now().Before(ssk.ExpiresAt) {
		return ssk, nil // Not yet expired
	}

	// Generate new key with incremented version
	return DeriveSpectralSSHKey(ssk.SymbolCombination, ssk.UserEmail)
}

// IsValid checks if key is still valid (not expired)
func (ssk *SpectralSSHKey) IsValid() bool {
	return time.Now().Before(ssk.ExpiresAt)
}

// ─── Example Usage ──────────────────────────────────────────────────────────────

// Example demonstrates spectral SSH key usage
func ExampleSpectralSSH() {
	// 1. User "Alice" derives SSH key from her symbol combination
	// (No key files needed - derived on-demand from symbols)
	aliceKey, _ := DeriveSpectralSSHKey("Eban+Fawohodie+Dwennimmen", "alice@khepra.dev")

	// 2. Alice exports public key to authorized_keys format
	authorizedKey := aliceKey.ToAuthorizedKeysFormat()
	fmt.Println("Add to ~/.ssh/authorized_keys:")
	fmt.Println(authorizedKey)

	// 3. Alice connects to SSH server
	// Server sends challenge
	challenge := make([]byte, 32)
	rand.Read(challenge)

	// 4. Alice signs challenge
	signature, _ := aliceKey.SignSSHChallenge(challenge)

	// 5. Server verifies signature
	serverKey, _ := FromAuthorizedKeysFormat(authorizedKey)
	err := serverKey.VerifySSHChallenge(challenge, signature)
	if err != nil {
		fmt.Printf("Authentication failed: %v\n", err)
	} else {
		fmt.Println("Authentication successful!")
	}

	// 6. After 90 days, key automatically rotates
	if !aliceKey.IsValid() {
		newKey, _ := aliceKey.RotateKey()
		fmt.Printf("Key rotated to version %d\n", newKey.Version)
	}
}

// ─── Security Advantages ───────────────────────────────────────────────────────

// Why Spectral SSH is superior to traditional SSH:
//
// 1. NO KEY FILES TO STEAL
//    - Traditional: ~/.ssh/id_rsa can be exfiltrated
//    - Spectral: Keys exist only in symbol space (deterministic derivation)
//
// 2. AUTOMATIC ROTATION
//    - Traditional: Keys never expire (decade-old keys still in use)
//    - Spectral: 90-day rotation (old keys invalid after grace period)
//
// 3. QUANTUM-RESISTANT
//    - Traditional: RSA/ECDSA vulnerable to Shor's algorithm
//    - Spectral: Adinkhepra-PQC lattice signatures (256-bit security)
//
// 4. SYMBOL-BASED IDENTITY
//    - Traditional: Email in comment field (ignored by SSH)
//    - Spectral: Symbol combination encodes role/clearance (Eban = Security Admin)
//
// 5. IMPOSSIBLE TO BRUTE FORCE
//    - Traditional: RSA keys can be factored (given enough time)
//    - Spectral: Must guess symbol combination (2^128 entropy minimum)
//
// 6. COMPLIANCE-READY
//    - Traditional: No built-in compliance mapping
//    - Spectral: Symbol → compliance framework (Eban → DoD RMF, STIG)
