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
// The node-quota License struct lives in license_tiers.go.
// The sovereign device-bound KhepraLicense lives in sovereign.go.
// TierCommunity and TierSovereign are declared as untyped string consts in
// sovereign.go — use those, not local redeclarations.
package license

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/nouchix/khepra-pqc/sign"
	"github.com/google/uuid"
)

// apiKeyTrustedRoot returns the public key that API-key signatures must verify
// under. It is the compiled-in MasterPublicKey; tests substitute a throwaway
// key. Nothing at runtime (environment, files) can change it.
var apiKeyTrustedRoot = func() []byte { return MasterPublicKey }

// legacyHMACSignatureSize is the length of the HMAC-SHA256 tags that API keys
// carried before ML-DSA issuance was required. Those keys were MAC'd with a
// key that shipped in the public repository, so they can no longer be trusted.
const legacyHMACSignatureSize = 32

// ---------------------------------------------------------------------------
// Tier constants for file-based (.adinkhepra) validation.
//
// TierCommunity and TierSovereign are intentionally NOT redeclared here —
// sovereign.go already declares them as untyped string constants
// ("community", "sovereign"). TierPharaoh is a legacy tier value specific to
// this file-based validation path only; it predates and is unrelated to the
// current Community/Pro/Enterprise/Sovereign pricing ladder.
// ---------------------------------------------------------------------------

const (
	// TierPharaoh grants all features including priority support and SLA.
	// Legacy .adinkhepra file tier — not part of the current pricing ladder.
	TierPharaoh = "pharaoh"
)

// ---------------------------------------------------------------------------
// ParsedLicense — result of validating a .adinkhepra file.
// For node-quota licensing, see license_tiers.go.
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
	if lf.Algorithm != "ML-DSA-87" && lf.Algorithm != "ML-DSA-65" {
		return nil, fmt.Errorf("unsupported signing algorithm: %q (expected ML-DSA-87)", lf.Algorithm)
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

	// 4. Check compiled-in revocation denylist (offline, non-bypassable)
	if err := CheckRevocationDenylist(lf.LicenseKey); err != nil {
		return nil, fmt.Errorf("license revoked: %w", err)
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
	if lf.Algorithm != "ML-DSA-87" && lf.Algorithm != "ML-DSA-65" {
		return nil, fmt.Errorf("unsupported signing algorithm: %q (expected ML-DSA-87)", lf.Algorithm)
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

	// 4. Check compiled-in revocation denylist (offline, non-bypassable)
	if err := CheckRevocationDenylist(lf.LicenseKey); err != nil {
		return nil, fmt.Errorf("license revoked: %w", err)
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
	case TierPro:
		return "pro"
	case TierEnterprise:
		return "ent"
	case TierSovereign:
		return "sov"
	case TierMaster:
		return "mas"
	case TierPharaoh:
		return "pha"
	default:
		return "unk"
	}
}

// isValidTierSlug reports whether s is a known tier slug.
func isValidTierSlug(s string) bool {
	switch strings.ToLower(s) {
	case "com", "pro", "ent", "sov", "mas", "pha":
		return true
	}
	return false
}

// TierFromSlug maps a slug ("com", "pro", "ent", "sov", "mas", "pha") to its canonical tier constant.
func TierFromSlug(slug string) string {
	switch strings.ToLower(slug) {
	case "com":
		return TierCommunity
	case "pro":
		return TierPro
	case "ent":
		return TierEnterprise
	case "sov":
		return TierSovereign
	case "mas":
		return TierMaster
	case "pha":
		return TierPharaoh
	default:
		return TierCommunity
	}
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
// The signature must be ML-DSA-65 (FIPS 204) and verify under the pinned
// MasterPublicKey (master_pubkey.go). There is no fallback: the HMAC-SHA256
// path that used to exist was keyed by a file published in the repository,
// so anyone could mint a key for any tier.
// ---------------------------------------------------------------------------

func verifySignature(lf licenseFile) error {
	// Build the canonical payload (same fields signed by Edge Function / License Authority)
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

	if len(sig) == legacyHMACSignatureSize {
		return fmt.Errorf("this key was issued with a retired signing method and is no longer accepted; " +
			"unset KHEPRA_LICENSE_KEY to run as Community, or request a new key")
	}

	// ML-DSA-87 under khepra/v3/apikey, or the historical ML-DSA-65 root.
	if err := verifyWithRoot(sign.ContextAPIKey, apiKeyTrustedRoot(), payloadJSON, sig); err != nil {
		return fmt.Errorf("signature mismatch")
	}
	return nil
}

// GenerateSignedAPIKey creates a signed API key string formatted as kphr_{tier}_{base64url}.
// signerKey must be an ML-DSA-87 private key (32-byte seed) whose public half
// is the root that validators trust; anything else is an error.
func GenerateSignedAPIKey(signerKey []byte, tier, customerID string, expiry time.Time, machineID string) (string, error) {
	if !isValidTier(tier) {
		return "", fmt.Errorf("license: invalid tier %q", tier)
	}
	if len(signerKey) != sign.SeedSize {
		return "", fmt.Errorf("license: an ML-DSA-87 private key (32-byte seed) is required to issue API keys (got %d bytes)", len(signerKey))
	}

	licenseKey := "KHRPA-" + strings.ToUpper(uuid.New().String()[:8]) + "-" + strings.ToUpper(uuid.New().String()[:8])
	lf := licenseFile{
		LicenseKey: licenseKey,
		Tier:       tier,
		CustomerID: customerID,
		IssuedAt:   time.Now().UTC().Format(time.RFC3339),
		ExpiresAt:  expiry.UTC().Format(time.RFC3339),
		Version:    "1",
		Algorithm:  "ML-DSA-87",
		MachineID:  machineID,
	}

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
		return "", fmt.Errorf("license: marshal payload: %w", err)
	}

	sig, err := signWith(sign.ContextAPIKey, signerKey, payloadJSON)
	if err != nil {
		return "", fmt.Errorf("license: sign API key: %w", err)
	}
	lf.Signature = base64.StdEncoding.EncodeToString(sig)

	return EncodeAPIKey(lf)
}

func isValidTier(tier string) bool {
	switch strings.ToLower(tier) {
	case TierCommunity, TierPro, TierEnterprise, TierSovereign, TierMaster, TierPharaoh:
		return true
	}
	return false
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
		return l.Tier == TierSovereign || l.Tier == TierPharaoh || l.Tier == TierEnterprise || l.Tier == TierPro
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
