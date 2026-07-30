// Package license provides offline ML-DSA-65 license validation for KHEPRA MCP.
//
// License files (.adinkhepra) are JSON documents signed by the NouchiX
// ML-DSA-65 private key. The binary validates them against the embedded
// public key — no network required.
//
// License keys (KHEPRA_LICENSE_KEY) follow the industry-standard API-key format:
//
//	kphr_{tier}_{base64url-encoded signed JSON payload}
//
// Examples:
//
//	kphr_com_eyJ...   # Community
//	kphr_sov_eyJ...   # Sovereign
//	kphr_pha_eyJ...   # Pharaoh
//
// The validator checks KHEPRA_LICENSE_KEY first, then falls back to
// KHEPRA_LICENSE_PATH (file-based, for air-gap / SCIF delivery).
//
// NOTE on types: this file defines ParsedLicense for file-based validation.
// The node-quota / EgyptianTier License struct lives in egyptian_tiers.go.
// The sovereign device-bound KhepraLicense lives in sovereign.go.
// TierCommunity is declared as an untyped string const in sovereign.go — use that.
package license

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	_ "embed"
)

// ---------------------------------------------------------------------------
// Embedded public key — replace with actual ML-DSA-65 public key bytes
// generated via: khepra-admin keygen --algorithm ml-dsa-65
// ---------------------------------------------------------------------------

//go:embed keys/khepra_signing.pub
var embeddedPublicKey []byte

// ---------------------------------------------------------------------------
// Tier constants for file-based (.adinkhepra) validation.
//
// TierCommunity is intentionally NOT redeclared here — sovereign.go already
// declares it as an untyped string constant ("community").
// ---------------------------------------------------------------------------

const (
	// TierSovereign grants NHI inventory, ERT crypto, and STIG automation.
	TierSovereign = "sovereign"
	// TierPharaoh grants all features including priority support and SLA.
	TierPharaoh = "pharaoh"
)

// ---------------------------------------------------------------------------
// ParsedLicense — result of validating a .adinkhepra file.
// For EgyptianTier node-quota licensing, see egyptian_tiers.go.
// For sovereign device-bound licenses,  see sovereign.go / KhepraLicense.
// ---------------------------------------------------------------------------

// ParsedLicense is the validated in-memory representation of a .adinkhepra file.
type ParsedLicense struct {
	LicenseKey string    `json:"license_key"`
	Tier       string    `json:"tier"`
	CustomerID string    `json:"customer_id"`
	IssuedAt   time.Time `json:"issued_at_parsed"`
	ExpiresAt  time.Time `json:"expires_at_parsed"`
	MachineID  string    `json:"machine_id,omitempty"`
}

// licenseFile is the raw JSON structure of a .adinkhepra file.
type licenseFile struct {
	LicenseKey string `json:"license_key"`
	Tier       string `json:"tier"`
	CustomerID string `json:"customer_id"`
	IssuedAt   string `json:"issued_at"`
	ExpiresAt  string `json:"expires_at"`
	Version    string `json:"version"`
	Algorithm  string `json:"algorithm"`
	MachineID  string `json:"machine_id,omitempty"`
	Signature  string `json:"signature"` // base64
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

// ErrNoLicense is returned when no license file is found (community mode).
var ErrNoLicense = fmt.Errorf("no license file configured")

// Validate reads and validates a .adinkhepra license file.
// Returns ErrNoLicense if path is empty (caller falls back to community tier).
func Validate(licensePath string) (*ParsedLicense, error) {
	if licensePath == "" {
		return communityLicense(), ErrNoLicense
	}

	data, err := os.ReadFile(licensePath)
	if err != nil {
		return nil, fmt.Errorf("license file not found at %q: %w", licensePath, err)
	}

	var lf licenseFile
	if err := json.Unmarshal(data, &lf); err != nil {
		return nil, fmt.Errorf("invalid license file format: %w", err)
	}

	// 1. Verify algorithm
	if lf.Algorithm != "ML-DSA-65" {
		return nil, fmt.Errorf("unsupported signing algorithm: %q (expected ML-DSA-65)", lf.Algorithm)
	}

	// 2. Verify signature (offline, against embedded public key)
	if err := verifySignature(lf); err != nil {
		return nil, fmt.Errorf("license signature invalid — possible tampering: %w", err)
	}

	// 3. Parse and check expiry
	expires, err := time.Parse(time.RFC3339, lf.ExpiresAt)
	if err != nil {
		return nil, fmt.Errorf("invalid expires_at format: %w", err)
	}
	if time.Now().After(expires) {
		return nil, fmt.Errorf("license expired on %s — renew at https://nouchix.com", expires.Format("2006-01-02"))
	}

	issued, _ := time.Parse(time.RFC3339, lf.IssuedAt)

	return &ParsedLicense{
		LicenseKey: lf.LicenseKey,
		Tier:       lf.Tier,
		CustomerID: lf.CustomerID,
		IssuedAt:   issued,
		ExpiresAt:  expires,
		MachineID:  lf.MachineID,
	}, nil
}

// ValidateFromEnv reads KHEPRA_LICENSE_PATH and validates the license.
// Falls back to community tier (ErrNoLicense) if the variable is unset.
//
// Prefer ValidateEnv() for new call-sites — it checks KHEPRA_LICENSE_KEY first.
func ValidateFromEnv() (*ParsedLicense, error) {
	return Validate(os.Getenv("KHEPRA_LICENSE_PATH"))
}

// ValidateFromKeyEnv reads KHEPRA_LICENSE_KEY (kphr_{tier}_{base64url-payload})
// and validates it. Falls back to community tier (ErrNoLicense) if unset.
func ValidateFromKeyEnv() (*ParsedLicense, error) {
	key := os.Getenv("KHEPRA_LICENSE_KEY")
	if key == "" {
		return communityLicense(), ErrNoLicense
	}
	return ValidateAPIKey(key)
}

// ValidateEnv is the unified bootstrap entry point. It resolves licenses in
// priority order:
//  1. KHEPRA_LICENSE_KEY  — API-key format (kphr_{tier}_{base64url-payload})
//  2. KHEPRA_LICENSE_PATH — file-based format (.adinkhepra), for air-gap/SCIF
//  3. Community tier fallback (ErrNoLicense)
func ValidateEnv() (*ParsedLicense, error) {
	if key := os.Getenv("KHEPRA_LICENSE_KEY"); key != "" {
		return ValidateAPIKey(key)
	}
	return ValidateFromEnv()
}

// ValidateAPIKey parses and validates a KHEPRA API key string.
//
// Format: kphr_{tier}_{base64url-encoded signed licenseFile JSON}
//
// The payload is the same JSON document that lives in a .adinkhepra file;
// validation runs through the identical verifySignature / expiry path.
func ValidateAPIKey(key string) (*ParsedLicense, error) {
	lf, err := ParseAPIKey(key)
	if err != nil {
		return nil, err
	}

	// 1. Verify algorithm
	if lf.Algorithm != "ML-DSA-65" {
		return nil, fmt.Errorf("unsupported signing algorithm: %q (expected ML-DSA-65)", lf.Algorithm)
	}

	// 2. Verify signature (offline, against embedded public key)
	if err := verifySignature(*lf); err != nil {
		return nil, fmt.Errorf("license signature invalid — possible tampering: %w", err)
	}

	// 3. Parse and check expiry
	expires, err := time.Parse(time.RFC3339, lf.ExpiresAt)
	if err != nil {
		return nil, fmt.Errorf("invalid expires_at format: %w", err)
	}
	if time.Now().After(expires) {
		return nil, fmt.Errorf("license expired on %s — renew at https://nouchix.com", expires.Format("2006-01-02"))
	}

	issued, _ := time.Parse(time.RFC3339, lf.IssuedAt)

	return &ParsedLicense{
		LicenseKey: lf.LicenseKey,
		Tier:       lf.Tier,
		CustomerID: lf.CustomerID,
		IssuedAt:   issued,
		ExpiresAt:  expires,
		MachineID:  lf.MachineID,
	}, nil
}

// ParseAPIKey decodes a kphr_{tier}_{base64url-payload} string into a raw
// licenseFile without running signature or expiry checks. Most callers should
// use ValidateAPIKey instead.
//
// Returns an error if the prefix, tier slug, or base64url payload are malformed.
func ParseAPIKey(key string) (*licenseFile, error) {
	// Expected: kphr_{tier}_{payload} — minimum 3 underscore-separated segments
	if !strings.HasPrefix(key, "kphr_") {
		return nil, fmt.Errorf("invalid license key: must start with \"kphr_\" (got %q)", truncate(key, 12))
	}

	// Split on _ with a limit of 3 parts: ["kphr", tier, payload]
	// payload itself may contain base64url chars but not underscores.
	parts := strings.SplitN(key, "_", 3)
	if len(parts) != 3 || parts[1] == "" || parts[2] == "" {
		return nil, fmt.Errorf("invalid license key format: expected kphr_{tier}_{payload}")
	}

	tierSlug := parts[1]
	if !isValidTierSlug(tierSlug) {
		return nil, fmt.Errorf("unknown tier slug %q in license key (valid: com, sov, pha)", tierSlug)
	}

	// base64url (no padding) decode
	payload, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("license key payload is not valid base64url: %w", err)
	}

	var lf licenseFile
	if err := json.Unmarshal(payload, &lf); err != nil {
		return nil, fmt.Errorf("license key payload is not valid JSON: %w", err)
	}

	// Sanity-check the tier slug matches the embedded tier
	if slugForTier(lf.Tier) != tierSlug {
		return nil, fmt.Errorf("tier mismatch: key claims %q but payload contains tier %q", tierSlug, lf.Tier)
	}

	return &lf, nil
}

// ---------------------------------------------------------------------------
// API-key format helpers
// ---------------------------------------------------------------------------

// EncodeAPIKey encodes a signed licenseFile as a kphr_{tier}_{base64url} string
// ready for use as KHEPRA_LICENSE_KEY in a .env file.
func EncodeAPIKey(lf licenseFile) (string, error) {
	payload, err := json.Marshal(lf)
	if err != nil {
		return "", fmt.Errorf("license: marshal for API key: %w", err)
	}
	slug := slugForTier(lf.Tier)
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	return "kphr_" + slug + "_" + encoded, nil
}

// slugForTier returns the two- or three-letter tier slug used in the key prefix.
func slugForTier(tier string) string {
	switch strings.ToLower(tier) {
	case TierCommunity:
		return "com"
	case TierSovereign:
		return "sov"
	case TierPharaoh:
		return "pha"
	default:
		return "unk"
	}
}

// isValidTierSlug reports whether s is a known tier slug.
func isValidTierSlug(s string) bool {
	switch s {
	case "com", "sov", "pha":
		return true
	}
	return false
}

// truncate returns up to n chars of s with "..." appended if truncated.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}



// ---------------------------------------------------------------------------
// Signature verification
//
// NOTE: This currently uses HMAC-SHA256 as a placeholder.
// Replace verifySignature() with the actual ML-DSA-65 verification once
// the Go NIST PQC library (golang.org/x/crypto or circl) is integrated.
//
// Recommended library: cloudflare/circl (CRYSTALS-Dilithium / ML-DSA)
//   go get github.com/cloudflare/circl
//   import "github.com/cloudflare/circl/sign/mldsa/mldsa65"
// ---------------------------------------------------------------------------

func verifySignature(lf licenseFile) error {
	// Build the canonical payload (same fields signed by Edge Function)
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

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	sig, err := base64.StdEncoding.DecodeString(lf.Signature)
	if err != nil {
		return fmt.Errorf("malformed signature encoding: %w", err)
	}

	// TODO: Replace with mldsa65.Verify(embeddedPublicKey, payloadJSON, sig)
	// Placeholder HMAC verification (uses embedded key as HMAC secret):
	mac := hmac.New(sha256.New, embeddedPublicKey)
	mac.Write(payloadJSON)
	expected := mac.Sum(nil)

	if !hmac.Equal(sig, expected) {
		return fmt.Errorf("signature mismatch")
	}
	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func communityLicense() *ParsedLicense {
	return &ParsedLicense{
		LicenseKey: "COMMUNITY",
		Tier:       TierCommunity, // from sovereign.go: const TierCommunity = "community"
		ExpiresAt:  time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC),
	}
}

// HasFeature returns true if the license tier includes the requested feature.
func (l *ParsedLicense) HasFeature(feature string) bool {
	switch feature {
	case "ert_scan", "stig_check", "cmmc_assess", "godfather_report",
		"agent_record", "dag_attestation":
		return l.Tier == TierSovereign || l.Tier == TierPharaoh
	case "priority_support", "sla":
		return l.Tier == TierPharaoh
	default:
		// Community tools always available
		return true
	}
}

// DaysUntilExpiry returns days remaining on the license (negative = expired).
func (l *ParsedLicense) DaysUntilExpiry() int {
	return int(time.Until(l.ExpiresAt).Hours() / 24)
}
