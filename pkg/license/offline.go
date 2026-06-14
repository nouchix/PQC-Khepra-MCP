package license

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// LicenseClaims represents the data authenticated by the license
type LicenseClaims struct {
	Tenant       string    `json:"tenant"`
	HostID       string    `json:"host_id"`
	Expiry       time.Time `json:"expiry"`
	Capabilities []string  `json:"capabilities"`
}

// OfflineLicense represents the file format for offline licenses
type OfflineLicense struct {
	Claims    LicenseClaims `json:"claims"`
	Signature string        `json:"signature"` // Hex encoded ML-DSA-65 signature
}

// Generate creates a signed offline license
func Generate(privKeyBytes []byte, claims LicenseClaims) (*OfflineLicense, error) {
	if len(privKeyBytes) != mldsa65.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key size: expected %d, got %d",
			mldsa65.PrivateKeySize, len(privKeyBytes))
	}

	var privateKey mldsa65.PrivateKey
	var keyBuf [mldsa65.PrivateKeySize]byte
	copy(keyBuf[:], privKeyBytes)
	privateKey.Unpack(&keyBuf)

	// Canonicalize claims for signing
	claimsData, err := json.Marshal(claims)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal claims: %w", err)
	}

	signature := make([]byte, mldsa65.SignatureSize)
	mldsa65.SignTo(&privateKey, claimsData, nil, false, signature)

	return &OfflineLicense{
		Claims:    claims,
		Signature: hex.EncodeToString(signature),
	}, nil
}

// Verify checks a license file against a Master Public Key
func Verify(path string, pubKeyBytes []byte) (*LicenseClaims, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read license file: %w", err)
	}

	var license OfflineLicense
	if err := json.Unmarshal(data, &license); err != nil {
		return nil, fmt.Errorf("failed to parse license file: %w", err)
	}

	// Canonicalize claims for verification
	claimsData, err := json.Marshal(license.Claims)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal claims: %w", err)
	}

	signature, err := hex.DecodeString(license.Signature)
	if err != nil {
		return nil, fmt.Errorf("invalid signature hex: %w", err)
	}

	if len(pubKeyBytes) != mldsa65.PublicKeySize {
		return nil, fmt.Errorf("invalid public key size: expected %d, got %d",
			mldsa65.PublicKeySize, len(pubKeyBytes))
	}

	var publicKey mldsa65.PublicKey
	var keyBuf [mldsa65.PublicKeySize]byte
	copy(keyBuf[:], pubKeyBytes)
	publicKey.Unpack(&keyBuf)

	// Verify(pk *PublicKey, msg, ctx, sig []byte) bool
	if !mldsa65.Verify(&publicKey, claimsData, nil, signature) {
		return nil, fmt.Errorf("signature verification failed")
	}

	// Check Expiry
	if time.Now().After(license.Claims.Expiry) {
		return &license.Claims, fmt.Errorf("license expired on %s", license.Claims.Expiry.Format(time.RFC3339))
	}

	return &license.Claims, nil
}

// GetHostID is a compatibility alias for the legacy CLI
func GetHostID() (string, error) {
	return GenerateMachineID(), nil
}
