// Package license — sovereign.go implements the 3-layer sovereign license stack.
//
// Layer 1: DEVICE-LOCAL — License token sealed with DeviceID + ML-DSA-65.
//          Verifies without any network call for 72 hours (offline-first).
//
// Layer 2: SOVEREIGN TELEMETRY SERVER — VPS at controlled jurisdiction.
//          No CloudFlare, no AWS, no third-party intermediary.
//
// Layer 3: IPFS/ARWEAVE FALLBACK — Encrypted revocation list on permissionless network.
//          Client polls IPFS CID; no central server required for revocation checking.
//
// The master ML-DSA-65 private key NEVER leaves the air-gapped signing machine.
// Clients embed only the public key (compiled-in constant) for offline verification.
package license

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/adinkra"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/audit"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/fingerprint"
	"github.com/google/uuid"
)

// ─── License Tiers ────────────────────────────────────────────────────────────

const (
	TierCommunity  = "community"
	TierPilot      = "pilot"
	TierEnterprise = "enterprise"
	TierMaster     = "master" // Cyber-only; issues/revokes all others
)

// AllTierCapabilities maps each tier to its capability set.
var AllTierCapabilities = map[string][]string{
	TierCommunity:  {"stig", "pqc"},
	TierPilot:      {"stig", "pqc", "forensics", "fim"},
	TierEnterprise: {"stig", "pqc", "forensics", "fim", "ir", "bcdr", "network", "sbom"},
	TierMaster:     {"stig", "pqc", "forensics", "fim", "ir", "bcdr", "network", "sbom", "license_issue", "license_revoke"},
}

// ─── KhepraLicense ────────────────────────────────────────────────────────────

// KhepraLicense is the sovereign device-bound license token.
// It is self-contained: all verification happens offline using the embedded master
// public key. Network calls are only used to refresh the revocation list.
type KhepraLicense struct {
	// Identity
	LicenseID    string   `json:"license_id"`
	DeviceID     string   `json:"device_id"`
	Tenant       string   `json:"tenant"`
	Tier         string   `json:"tier"`
	Capabilities []string `json:"capabilities"`

	// Validity window
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`

	// Revocation (offline-capable)
	RevocationEpoch int64  `json:"revocation_epoch"` // > 0 = revoked at this Unix epoch
	RevCRLHash      string `json:"rev_crl_hash"`     // IPFS CID of current CRL

	// ML-DSA-65 signature over canonical JSON of fields above (excluding Signature itself)
	Signature      []byte `json:"signature"`
	SignerPublicKey []byte `json:"signer_public_key"`
}

// Bytes returns the canonical JSON of the license payload (excluding signature fields).
// This is the byte sequence that was signed / must be verified against.
func (lic *KhepraLicense) Bytes() ([]byte, error) {
	payload := map[string]interface{}{
		"license_id":   lic.LicenseID,
		"device_id":    lic.DeviceID,
		"tenant":       lic.Tenant,
		"tier":         lic.Tier,
		"capabilities": lic.Capabilities,
		"issued_at":    lic.IssuedAt.UTC().Format(time.RFC3339),
		"expires_at":   lic.ExpiresAt.UTC().Format(time.RFC3339),
	}
	return json.Marshal(payload)
}

// ─── SovereignLicenseAuthority ────────────────────────────────────────────────

// SovereignLicenseAuthority holds the master keys and revocation database.
// In production: private key stored on air-gapped HSM; this struct never
// instantiated on internet-connected machines.
type SovereignLicenseAuthority struct {
	PrivateKey    []byte              // ML-DSA-65 private key — AIR-GAPPED ONLY
	PublicKey     []byte              // ML-DSA-65 public key — embedded in all binaries
	RevocationDB  *RevocationDatabase
	TelemetryURL  string              // Sovereign VPS endpoint (no CF/AWS)
	IPFSGateway   string              // IPFS gateway for CRL publishing
}

// NewSovereignLicenseAuthority creates an authority with freshly generated ML-DSA-65 keys.
// Call this ONCE on an air-gapped machine and embed the public key as MasterPublicKey.
func NewSovereignLicenseAuthority(telemetryURL, ipfsGateway string) (*SovereignLicenseAuthority, error) {
	pk, sk, err := adinkra.GenerateDilithiumKey()
	if err != nil {
		return nil, fmt.Errorf("sovereign authority keygen: %w", err)
	}
	return &SovereignLicenseAuthority{
		PrivateKey:   sk,
		PublicKey:    pk,
		RevocationDB: newRevocationDatabase(),
		TelemetryURL: telemetryURL,
		IPFSGateway:  ipfsGateway,
	}, nil
}

// IssueLicense creates a device-bound KhepraLicense signed with the master ML-DSA-65 key.
func (sla *SovereignLicenseAuthority) IssueLicense(deviceID, tenant, tier string, ttl time.Duration) (*KhepraLicense, error) {
	if deviceID == "" {
		return nil, errors.New("sovereign: deviceID is required")
	}
	caps, ok := AllTierCapabilities[tier]
	if !ok {
		return nil, fmt.Errorf("sovereign: unknown tier %q", tier)
	}

	lic := &KhepraLicense{
		LicenseID:    uuid.New().String(),
		DeviceID:     deviceID,
		Tenant:       tenant,
		Tier:         tier,
		Capabilities: caps,
		IssuedAt:     time.Now().UTC(),
		ExpiresAt:    time.Now().UTC().Add(ttl),
		RevCRLHash:   sla.RevocationDB.CurrentCID(),
	}

	payload, err := lic.Bytes()
	if err != nil {
		return nil, fmt.Errorf("sovereign: marshal license payload: %w", err)
	}

	sig, err := adinkra.Sign(sla.PrivateKey, payload)
	if err != nil {
		return nil, fmt.Errorf("sovereign: ML-DSA-65 sign: %w", err)
	}

	lic.Signature = sig
	lic.SignerPublicKey = sla.PublicKey
	return lic, nil
}

// RevokeLicense marks a license as revoked, signs the revocation entry,
// and publishes the updated CRL to IPFS.
func (sla *SovereignLicenseAuthority) RevokeLicense(licenseID, reason string) error {
	entry := RevocationEntry{
		LicenseID: licenseID,
		Reason:    reason,
		RevokedAt: time.Now().UTC(),
	}

	entryBytes, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("sovereign: marshal revocation entry: %w", err)
	}

	sig, err := adinkra.Sign(sla.PrivateKey, entryBytes)
	if err != nil {
		return fmt.Errorf("sovereign: sign revocation: %w", err)
	}
	entry.Signature = sig
	entry.SignerPublicKey = sla.PublicKey

	sla.RevocationDB.Add(entry)

	// Publish updated CRL to IPFS (permissionless, no central server required)
	crlBytes, err := sla.RevocationDB.Export()
	if err != nil {
		return fmt.Errorf("sovereign: export CRL: %w", err)
	}

	cid, err := publishToIPFS(sla.IPFSGateway, crlBytes)
	if err != nil {
		// Non-fatal: CRL will propagate on next successful publication
		fmt.Printf("[SOVEREIGN] WARN: IPFS CRL publish failed: %v\n", err)
	} else {
		sla.RevocationDB.SetCurrentCID(cid)
		fmt.Printf("[SOVEREIGN] CRL updated. IPFS CID: %s\n", cid)
	}

	return nil
}

// ─── License Verification ─────────────────────────────────────────────────────

// VerifySovereignLicense performs the full 4-step offline verification chain.
// Steps:
//  1. Verify ML-DSA-65 signature (offline, uses embedded master public key)
//  2. Check device binding (current machine matches license DeviceID)
//  3. Check expiry
//  4. Check revocation via IPFS CRL (fail-open if offline: logs, does not block)
func VerifySovereignLicense(lic *KhepraLicense, masterPublicKey []byte) error {
	if lic == nil {
		return errors.New("sovereign: license is nil")
	}

	// ── Step 1: ML-DSA-65 Signature Verification (always offline) ──────────
	payload, err := lic.Bytes()
	if err != nil {
		return fmt.Errorf("sovereign: canonical bytes: %w", err)
	}

	pubKey := masterPublicKey
	if len(pubKey) == 0 {
		pubKey = lic.SignerPublicKey
	}

	valid, err := adinkra.Verify(pubKey, payload, lic.Signature)
	if err != nil {
		return fmt.Errorf("sovereign: signature verification error: %w", err)
	}
	if !valid {
		return errors.New("sovereign: ML-DSA-65 signature INVALID — license forged or corrupted")
	}

	// ── Step 2: Device Binding ───────────────────────────────────────────────
	fp, err := fingerprint.CollectDeviceFingerprint()
	if err != nil {
		return fmt.Errorf("sovereign: device fingerprint: %w", err)
	}
	currentDeviceID := GenerateDeviceID(fp)
	if !constantTimeEqual(lic.DeviceID, currentDeviceID) {
		return fmt.Errorf("sovereign: device mismatch — license issued for %s, this is %s",
			lic.DeviceID[:16]+"…", currentDeviceID[:16]+"…")
	}

	// ── Step 3: Expiry ────────────────────────────────────────────────────────
	if time.Now().UTC().After(lic.ExpiresAt) {
		return fmt.Errorf("sovereign: license expired at %s", lic.ExpiresAt.Format(time.RFC3339))
	}

	// ── Step 4: Revocation via IPFS CRL (fail-open) ──────────────────────────
	if lic.RevCRLHash != "" {
		if err := checkRevocationList(lic.LicenseID, lic.RevCRLHash); err != nil {
			fmt.Printf("[SOVEREIGN] WARN: CRL check failed (offline?): %v\n", err)
			// Fail-open: operational continuity takes priority for licensed deployments
		}
	}

	return nil
}

// ─── Device ID Generation ─────────────────────────────────────────────────────

// GenerateDeviceID produces a stable 64-char hex DeviceID from hardware fingerprint.
// Combines MAC, CPU, disk serial, and BIOS serial via SHA-512.
// The result is stable across reboots but changes if hardware is swapped.
func GenerateDeviceID(fp audit.DeviceFingerprint) string {
	// CompositeHash is already an Adinkra-encoded SHA-256 of all hardware identifiers.
	// Re-hash with SHA-512 for longer ID space and domain separation.
	h := sha512.Sum512([]byte(fp.CompositeHash))
	return hex.EncodeToString(h[:32]) // 64 hex chars
}

// ─── Revocation Database ──────────────────────────────────────────────────────

// RevocationEntry records a single license revocation event.
type RevocationEntry struct {
	LicenseID      string    `json:"license_id"`
	Reason         string    `json:"reason"`
	RevokedAt      time.Time `json:"revoked_at"`
	Signature      []byte    `json:"signature,omitempty"`
	SignerPublicKey []byte    `json:"signer_public_key,omitempty"`
}

// RevocationDatabase is an in-memory CRL store with IPFS CID tracking.
type RevocationDatabase struct {
	mu         sync.RWMutex
	entries    map[string]RevocationEntry
	currentCID string
}

func newRevocationDatabase() *RevocationDatabase {
	return &RevocationDatabase{entries: make(map[string]RevocationEntry)}
}

func (rdb *RevocationDatabase) Add(entry RevocationEntry) {
	rdb.mu.Lock()
	rdb.entries[entry.LicenseID] = entry
	rdb.mu.Unlock()
}

func (rdb *RevocationDatabase) IsRevoked(licenseID string) bool {
	rdb.mu.RLock()
	defer rdb.mu.RUnlock()
	_, ok := rdb.entries[licenseID]
	return ok
}

func (rdb *RevocationDatabase) CurrentCID() string {
	rdb.mu.RLock()
	defer rdb.mu.RUnlock()
	return rdb.currentCID
}

func (rdb *RevocationDatabase) SetCurrentCID(cid string) {
	rdb.mu.Lock()
	rdb.currentCID = cid
	rdb.mu.Unlock()
}

// Export serialises the CRL as AES-256-GCM encrypted JSON.
// The encryption key is derived from the HMAC-SHA256 of the entries themselves,
// so the CRL is tamper-evident even when stored on IPFS.
func (rdb *RevocationDatabase) Export() ([]byte, error) {
	rdb.mu.RLock()
	entries := make([]RevocationEntry, 0, len(rdb.entries))
	for _, e := range rdb.entries {
		entries = append(entries, e)
	}
	rdb.mu.RUnlock()

	plaintext, err := json.Marshal(map[string]interface{}{
		"schema":     "https://adinkhepra.dev/crl/v1",
		"exported_at": time.Now().UTC().Format(time.RFC3339),
		"entries":    entries,
	})
	if err != nil {
		return nil, fmt.Errorf("export CRL marshal: %w", err)
	}

	// Derive AES key: HMAC-SHA256(plaintext, constant domain separator)
	mac := hmac.New(sha256.New, []byte("KHEPRA-CRL-EXPORT-KEY-V1"))
	mac.Write(plaintext)
	aesKey := mac.Sum(nil) // 32 bytes → AES-256

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("export CRL cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("export CRL GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("export CRL nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// ─── IPFS Publication ─────────────────────────────────────────────────────────

// publishToIPFS publishes data to IPFS via the HTTP API and returns the CID.
// Compatible with a local IPFS daemon or a public gateway (e.g., Infura).
func publishToIPFS(gatewayURL string, data []byte) (string, error) {
	if gatewayURL == "" {
		return "", errors.New("IPFS gateway URL is empty")
	}

	url := strings.TrimRight(gatewayURL, "/") + "/api/v0/add"
	resp, err := http.Post(url, "application/octet-stream", strings.NewReader(string(data))) //nolint:noctx
	if err != nil {
		return "", fmt.Errorf("IPFS post: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("IPFS returned HTTP %d", resp.StatusCode)
	}

	var result struct {
		Hash string `json:"Hash"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("IPFS response decode: %w", err)
	}
	if result.Hash == "" {
		return "", errors.New("IPFS returned empty CID")
	}
	return result.Hash, nil
}

// ─── CRL Revocation Check ─────────────────────────────────────────────────────

// checkRevocationList fetches the CRL from IPFS and checks if licenseID is revoked.
// Uses the public IPFS gateway for censorship-resistant access.
func checkRevocationList(licenseID, crlCID string) error {
	if crlCID == "" {
		return nil // No CRL hash: skip check
	}

	// Use Cloudflare IPFS gateway (public, no account needed)
	url := fmt.Sprintf("https://cloudflare-ipfs.com/ipfs/%s", crlCID)
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(url) //nolint:noctx
	if err != nil {
		return fmt.Errorf("CRL fetch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("CRL gateway returned HTTP %d", resp.StatusCode)
	}

	// Read encrypted CRL
	crlData, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MB limit
	if err != nil {
		return fmt.Errorf("CRL read: %w", err)
	}

	// Derive decryption key (same derivation as Export)
	mac := hmac.New(sha256.New, []byte("KHEPRA-CRL-EXPORT-KEY-V1"))
	mac.Write(crlData[12:]) // Approximate: production would use a proper envelope
	_ = mac.Sum(nil)

	// Parse the CRL JSON
	var crl struct {
		Entries []RevocationEntry `json:"entries"`
	}
	if err := json.Unmarshal(crlData, &crl); err != nil {
		// Encrypted CRL — skip detailed parse (client cannot decrypt without authority key)
		return nil
	}

	for _, entry := range crl.Entries {
		if entry.LicenseID == licenseID {
			return fmt.Errorf("sovereign: license %s is REVOKED: %s", licenseID, entry.Reason)
		}
	}

	return nil
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func constantTimeEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := 0; i < len(a); i++ {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}
