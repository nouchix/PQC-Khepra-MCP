package license

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"
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
	Signature string        `json:"signature"` // Hex encoded ML-DSA-87 signature
}

// Generate creates a signed offline license. privKeyBytes is an ML-DSA-87
// private key in 32-byte seed form.
func Generate(privKeyBytes []byte, claims LicenseClaims) (*OfflineLicense, error) {
	// Canonicalize claims for signing
	claimsData, err := json.Marshal(claims)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal claims: %w", err)
	}

	signature, err := signWith(licenseContext, privKeyBytes, claimsData)
	if err != nil {
		return nil, err
	}

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

	if err := verifyWithRoot(licenseContext, pubKeyBytes, claimsData, signature); err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
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
