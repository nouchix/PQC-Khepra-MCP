// Package telemetry provides ML-DSA-65-signed anonymous usage telemetry for
// AdinKhepra v2.0.
//
// Two transports are supported:
//
//  1. Legacy endpoint (SendBeacon): original Khepra telemetry server;
//     signature goes in the X-Khepra-Signature HTTP header.
//
//  2. Sovereign endpoint (SendSovereignBeacon): the self-hosted VPS server
//     defined in cmd/telemetry-server; signature + ephemeral public key are
//     embedded in the JSON body so the server can verify each beacon without
//     a pre-shared key registry.
package telemetry

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/adinkra"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/license"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/types"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// ─── Constants ────────────────────────────────────────────────────────────────

const (
	// TelemetryVersion is the wire-protocol version sent in every beacon.
	TelemetryVersion = "2.0"

	// defaultSovereignURL is the self-hosted telemetry server for sovereign deployments.
	// Override with KHEPRA_SOVEREIGN_TELEMETRY_URL.
	defaultSovereignURL = "https://telemetry.souhimbou.ai/beacon"

	// defaultLegacyURL is the original telemetry endpoint (kept for backwards compat).
	defaultLegacyURL = "https://telemetry.khepra.io/beacon"

	beaconHTTPTimeout = 10 * time.Second
)

// ─── Beacon Types ─────────────────────────────────────────────────────────────

// Beacon carries the legacy telemetry payload (original Khepra server format).
type Beacon struct {
	TelemetryVersion string          `json:"telemetry_version"`
	Timestamp        string          `json:"timestamp"`
	AnonymousID      string          `json:"anonymous_id"`
	ScanMetadata     ScanMetadata    `json:"scan_metadata"`
	CryptoInventory  CryptoInventory `json:"cryptographic_inventory"`
	GeographicHint   string          `json:"geographic_hint,omitempty"`
	LicenseTier      string          `json:"license_tier,omitempty"`
	LicenseHash      string          `json:"license_hash,omitempty"`
}

// ScanMetadata contains information about the scan execution.
type ScanMetadata struct {
	ScanDuration         int      `json:"scan_duration_seconds"`
	TargetsScanned       int      `json:"targets_scanned"`
	FindingsCount        int      `json:"findings_count"`
	ComplianceFrameworks []string `json:"compliance_frameworks"`
	ScannerVersion       string   `json:"scanner_version"`
	ContainerRuntime     string   `json:"container_runtime"`
	DeploymentEnv        string   `json:"deployment_environment"`
}

// CryptoInventory contains cryptographic asset counts (never actual key material).
type CryptoInventory struct {
	RSA2048Keys       int `json:"rsa_2048_keys"`
	RSA3072Keys       int `json:"rsa_3072_keys"`
	RSA4096Keys       int `json:"rsa_4096_keys"`
	ECCP256Keys       int `json:"ecc_p256_keys"`
	ECCP384Keys       int `json:"ecc_p384_keys"`
	Dilithium3Keys    int `json:"dilithium3_keys"`
	Kyber1024Keys     int `json:"kyber1024_keys"`
	TLSWeakConfigs    int `json:"tls_weak_configs"`
	DeprecatedCiphers int `json:"deprecated_ciphers"`
}

// SovereignBeaconPayload is the JSON body for POST /beacon on the sovereign
// telemetry server.  The Signature and SignerPublicKey fields are populated
// by SendSovereignBeacon; all other fields are set by the caller.
//
// Wire format MUST stay in sync with incomingBeacon in cmd/telemetry-server.
type SovereignBeaconPayload struct {
	TelemetryVersion string `json:"telemetry_version"`
	AnonymousID      string `json:"anonymous_id"`
	LicenseTier      string `json:"license_tier,omitempty"`
	ScanCount        int    `json:"scan_count"`
	FindingCount     int    `json:"finding_count"`
	Timestamp        string `json:"timestamp"`
	// Signature and SignerPublicKey are set by SendSovereignBeacon.
	Signature       []byte `json:"signature"`
	SignerPublicKey []byte `json:"signer_public_key"`
}

// canonical returns the deterministic JSON payload that must be signed — must
// exactly match canonicalBeaconBytes() in cmd/telemetry-server/main.go.
func (p *SovereignBeaconPayload) canonical() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"telemetry_version": p.TelemetryVersion,
		"anonymous_id":      p.AnonymousID,
		"license_tier":      p.LicenseTier,
		"scan_count":        p.ScanCount,
		"finding_count":     p.FindingCount,
		"timestamp":         p.Timestamp,
	})
}

// ─── Anonymous ID ─────────────────────────────────────────────────────────────

// GenerateAnonymousID produces a privacy-safe, stable device identifier.
// The ID is a SHA-256 hash of (primaryMAC + hostname + fixed salt) — no PII.
func GenerateAnonymousID() string {
	mac := primaryMACAddress()
	hostname, _ := os.Hostname()
	const salt = "khepra-telemetry-v2-2026"
	raw := fmt.Sprintf("%s:%s:%s", mac, hostname, salt)
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}

// primaryMACAddress returns the hardware address of the first non-loopback,
// UP network interface with a non-empty MAC. Falls back to hostname if none
// found — still privacy-safe because both paths are hashed before transmission.
func primaryMACAddress() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		hostname, _ := os.Hostname()
		return hostname
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		if mac := iface.HardwareAddr.String(); mac != "" {
			return mac
		}
	}
	hostname, _ := os.Hostname()
	return hostname
}

// ─── Sovereign Beacon Transport ───────────────────────────────────────────────

// SendSovereignBeacon signs and transmits a beacon to the sovereign VPS
// telemetry server (cmd/telemetry-server).
//
// An ephemeral ML-DSA-65 key pair is generated per call so that beacons
// cannot be linked across sessions via the signing key.  The signature
// covers only the non-signature fields, matching the server's verification.
//
// Telemetry is suppressed in the same conditions as SendBeacon: community
// mode requires KHEPRA_TELEMETRY=true; enterprise mode honours
// KHEPRA_TELEMETRY=false.
func SendSovereignBeacon(payload *SovereignBeaconPayload) error {
	if err := checkTelemetryEnabled(); err != nil {
		return err
	}
	if err := validateAnonymousID(payload.AnonymousID); err != nil {
		return fmt.Errorf("invalid anonymous_id: %w", err)
	}

	// Ephemeral ML-DSA-65 key pair — one per session, never reused.
	epkBytes, eskBytes, err := adinkra.GenerateDilithiumKey()
	if err != nil {
		return fmt.Errorf("sovereign beacon: generate ephemeral key: %w", err)
	}

	payload.TelemetryVersion = TelemetryVersion
	payload.Timestamp = time.Now().UTC().Format(time.RFC3339)

	canonical, err := payload.canonical()
	if err != nil {
		return fmt.Errorf("sovereign beacon: canonical payload: %w", err)
	}

	sig, err := adinkra.Sign(eskBytes, canonical)
	if err != nil {
		return fmt.Errorf("sovereign beacon: sign: %w", err)
	}

	payload.Signature = sig
	payload.SignerPublicKey = epkBytes

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("sovereign beacon: marshal: %w", err)
	}

	serverURL := os.Getenv("KHEPRA_SOVEREIGN_TELEMETRY_URL")
	if serverURL == "" {
		serverURL = defaultSovereignURL
	}

	ctx, cancel := context.WithTimeout(context.Background(), beaconHTTPTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, serverURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("sovereign beacon: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("sovereign beacon: send: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("sovereign beacon: server returned %d: %s", resp.StatusCode, respBody)
	}
	return nil
}

// validateAnonymousID enforces the server's requirement that anonymous_id is
// a hex-encoded string of at least 32 characters (≥16 raw bytes = 128-bit).
func validateAnonymousID(id string) error {
	if len(id) < 32 {
		return fmt.Errorf("must be ≥32 hex chars, got %d", len(id))
	}
	if _, err := hex.DecodeString(id); err != nil {
		return fmt.Errorf("must be hex-encoded: %w", err)
	}
	return nil
}

// checkTelemetryEnabled returns an error if telemetry should be suppressed
// based on KHEPRA_MODE and KHEPRA_TELEMETRY environment variables.
func checkTelemetryEnabled() error {
	mode := os.Getenv("KHEPRA_MODE")
	if mode == "" {
		mode = "community"
	}
	telemetryEnv := os.Getenv("KHEPRA_TELEMETRY")
	if mode == "community" && telemetryEnv != "true" {
		return fmt.Errorf("telemetry disabled (community mode requires KHEPRA_TELEMETRY=true)")
	}
	if mode != "community" && telemetryEnv == "false" {
		return fmt.Errorf("telemetry disabled by user")
	}
	return nil
}

// ─── Legacy Beacon Transport ──────────────────────────────────────────────────

// SendBeacon transmits a legacy beacon to the original Khepra telemetry server.
// The ML-DSA-65 signature is sent in the X-Khepra-Signature HTTP header.
// Use SendSovereignBeacon for the v2.0 sovereign server.
func SendBeacon(beacon *Beacon, privateKeyHex string) error {
	if err := checkTelemetryEnabled(); err != nil {
		return err
	}

	payload, err := json.Marshal(beacon)
	if err != nil {
		return fmt.Errorf("marshal beacon: %w", err)
	}

	signature, err := signLegacy(payload, privateKeyHex)
	if err != nil {
		return fmt.Errorf("sign beacon: %w", err)
	}

	serverURL := os.Getenv("ADINKHEPRA_TELEMETRY_SERVER")
	if serverURL == "" {
		serverURL = defaultLegacyURL
	}

	ctx, cancel := context.WithTimeout(context.Background(), beaconHTTPTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, serverURL, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Khepra-Signature", hex.EncodeToString(signature))
	req.Header.Set("X-Khepra-Version", beacon.ScanMetadata.ScannerVersion)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("send beacon: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("telemetry server returned %d: %s", resp.StatusCode, respBody)
	}
	return nil
}

// SendBeaconWithLicense attaches license context to a legacy beacon before sending.
func SendBeaconWithLicense(beacon *Beacon, privateKeyHex string, licMgr *license.Manager) error {
	if licMgr != nil {
		beacon.LicenseTier = licMgr.GetTier()
		beacon.LicenseHash = hashID(licMgr.GetMachineID())
	}
	return SendBeacon(beacon, privateKeyHex)
}

// signLegacy signs payload with an ML-DSA-65 private key supplied as hex.
func signLegacy(payload []byte, privateKeyHex string) ([]byte, error) {
	if privateKeyHex == "" {
		return nil, fmt.Errorf("no private key provided for telemetry signing")
	}
	keyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid private key hex: %w", err)
	}
	if len(keyBytes) != mldsa65.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key size: want %d, got %d",
			mldsa65.PrivateKeySize, len(keyBytes))
	}
	var keyArr [mldsa65.PrivateKeySize]byte
	copy(keyArr[:], keyBytes)
	var sk mldsa65.PrivateKey
	sk.Unpack(&keyArr)
	sig := make([]byte, mldsa65.SignatureSize)
	mldsa65.SignTo(&sk, payload, nil, false, sig)
	return sig, nil
}

func hashID(id string) string {
	h := sha256.Sum256([]byte(id))
	return hex.EncodeToString(h[:])
}

// ─── Crypto Inventory ─────────────────────────────────────────────────────────

// ExtractCryptoInventory derives cryptographic asset counts from a live
// AuditSnapshot.  It scans compliance findings, vulnerability descriptions,
// and the PQC signature block to produce counts — it never extracts key
// material, only algorithm-type tallies.
func ExtractCryptoInventory(snapshot types.AuditSnapshot) CryptoInventory {
	inv := CryptoInventory{}

	// Count PQC keys from the snapshot's own signature block.
	if snapshot.PQCSignature != nil {
		switch snapshot.PQCSignature.Algorithm {
		case "Dilithium3", "ML-DSA-65":
			inv.Dilithium3Keys++
		}
	}

	// Scan compliance findings for algorithm / configuration keywords.
	for _, f := range snapshot.Compliance.Findings {
		desc := strings.ToUpper(f.Description + " " + f.Title)
		switch {
		case strings.Contains(desc, "RSA-2048") || strings.Contains(desc, "RSA 2048"):
			inv.RSA2048Keys++
		case strings.Contains(desc, "RSA-3072") || strings.Contains(desc, "RSA 3072"):
			inv.RSA3072Keys++
		case strings.Contains(desc, "RSA-4096") || strings.Contains(desc, "RSA 4096"):
			inv.RSA4096Keys++
		case strings.Contains(desc, "P-256") || strings.Contains(desc, "PRIME256V1"):
			inv.ECCP256Keys++
		case strings.Contains(desc, "P-384") || strings.Contains(desc, "SECP384R1"):
			inv.ECCP384Keys++
		case strings.Contains(desc, "KYBER") || strings.Contains(desc, "ML-KEM"):
			inv.Kyber1024Keys++
		}

		// Weak TLS configurations (CAT I/HIGH severity TLS findings).
		if f.Severity == "HIGH" || f.Severity == "CRITICAL" {
			titleUp := strings.ToUpper(f.Title)
			if strings.Contains(titleUp, "TLS") || strings.Contains(titleUp, "SSL") {
				inv.TLSWeakConfigs++
			}
		}
	}

	// Scan vulnerability descriptions for deprecated cipher keywords.
	deprecatedCipherKeywords := []string{
		"3DES", "RC4", "DES-CBC", "EXPORT", "NULL-CIPHER",
		"TLS 1.0", "TLS1.0", "SSLV3", "SSL 3.0",
	}
	for _, vuln := range snapshot.Vulnerabilities {
		descUpper := strings.ToUpper(vuln.Description)
		for _, kw := range deprecatedCipherKeywords {
			if strings.Contains(descUpper, kw) {
				inv.DeprecatedCiphers++
				break // count each vuln once
			}
		}
	}

	// Network interfaces — count hardware network devices that carry keys.
	// We count NIC-level ML-DSA-65 keys from the device fingerprint MAC list
	// as a proxy for hardware-bound PQC keys (these come from the licence engine).
	// Each unique non-loopback MAC that appears in the DeviceFingerprint is a
	// separate device identity that may hold a device-bound key.
	seen := make(map[string]bool)
	for _, mac := range snapshot.DeviceFingerprint.MACAddresses {
		if mac != "" && !seen[mac] {
			seen[mac] = true
			// Not a key count — MACs inform device-bound license cardinality only.
			// We do NOT increment key counters here.
		}
	}

	return inv
}

// ─── Environment Helpers ──────────────────────────────────────────────────────

// DetectContainerRuntime identifies the container environment.
func DetectContainerRuntime() string {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return "docker"
	}
	if os.Getenv("container") == "podman" {
		return "podman"
	}
	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		return "kubernetes"
	}
	return "native"
}

// DetectGeographicHint attempts to identify the deployment region from cloud
// metadata endpoints.  Returns "on-prem" when no cloud metadata is available.
// Non-fatal: network failures are silently ignored.
func DetectGeographicHint() string {
	client := &http.Client{Timeout: 2 * time.Second}

	// AWS EC2 IMDSv1
	if region := fetchText(client, "GET",
		"http://169.254.169.254/latest/meta-data/placement/region", nil); region != "" {
		return region
	}

	// Azure IMDS
	if region := fetchText(client, "GET",
		"http://169.254.169.254/metadata/instance/compute/location?api-version=2021-02-01&format=text",
		map[string]string{"Metadata": "true"}); region != "" {
		return region
	}

	// GCP metadata server
	if zone := fetchText(client, "GET",
		"http://metadata.google.internal/computeMetadata/v1/instance/zone",
		map[string]string{"Metadata-Flavor": "Google"}); zone != "" {
		return zone
	}

	return "on-prem"
}

func fetchText(client *http.Client, method, url string, headers map[string]string) string {
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return ""
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	return strings.TrimSpace(string(body))
}
