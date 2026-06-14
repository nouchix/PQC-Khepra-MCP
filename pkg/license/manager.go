package license

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// Manager handles license validation lifecycle
type Manager struct {
	client           *LicenseClient
	cachedValidation *ValidateResponse
	lastValidated    time.Time
	validationMu     sync.RWMutex
	heartbeatStopCh  chan struct{}
	enrollmentToken  string          // Optional enrollment token for auto-registration
	egyptianMgr      *LicenseManager // Internal Egyptian Tier license manager
}

// NewManager creates license manager
func NewManager(serverURL string) (*Manager, error) {
	// Generate or retrieve the hardware-bound Machine ID
	machineID := GenerateMachineID()

	// Load or generate the persistent ML-DSA-65 private key for signing requests.
	// This ensures the machine has a stable cryptographic identity.
	privKey, err := loadOrGenerateKey()
	if err != nil {
		log.Printf("[LICENSE] Warning: Failed to load/generate PQC key: %v. Requests will be unsigned.", err)
	}

	client := &LicenseClient{
		ServerURL:  serverURL,
		MachineID:  machineID,
		PrivateKey: privKey,
		HTTPClient: &http.Client{Timeout: 10 * time.Second},
	}

	// Initialize Egyptian Tier license manager with persistence
	home, _ := os.UserHomeDir()
	if home == "" {
		home = "."
	}
	tierStorePath := filepath.Join(home, ".khepra", "tiers.json")

	return &Manager{
		client:      client,
		egyptianMgr: NewLicenseManager(tierStorePath),
	}, nil
}

func loadOrGenerateKey() (string, error) {
	// 1. Check environment variable first
	if key := os.Getenv("KHEPRA_LICENSE_KEY"); key != "" {
		return key, nil
	}

	// 2. Check persistent storage (DoD/Enterprise Standard: Save to .khepra/license.key)
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	keyPath := filepath.Join(home, ".khepra", "license.key")

	if data, err := os.ReadFile(keyPath); err == nil {
		return strings.TrimSpace(string(data)), nil
	}

	// 3. Generate new ML-DSA-65 key if none found
	log.Println("[LICENSE] No PQC key found. Generating new identity...")
	_, priv, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		return "", fmt.Errorf("failed to generate ML-DSA-65 key: %w", err)
	}

	privBytes, _ := priv.MarshalBinary()
	keyHex := hex.EncodeToString(privBytes)

	// Persist the key
	os.MkdirAll(filepath.Dir(keyPath), 0700)
	if err := os.WriteFile(keyPath, []byte(keyHex), 0600); err != nil {
		log.Printf("[LICENSE] Warning: Could not persist key to %s: %v", keyPath, err)
	} else {
		log.Printf("[LICENSE] Persistent identity saved to %s", keyPath)
	}

	return keyHex, nil
}

// SetPrivateKey allows setting the Dilithium key for signing requests
func (m *Manager) SetPrivateKey(privateKey string) {
	m.client.PrivateKey = privateKey
}

// SetEnrollmentToken sets the enrollment token for auto-registration
func (m *Manager) SetEnrollmentToken(token string) {
	m.enrollmentToken = token
}

// GetMachineID returns the machine ID
func (m *Manager) GetMachineID() string {
	return m.client.MachineID
}

// Initialize validates license and starts heartbeat daemon.
// Offline .khepra files are checked first; the telemetry server is only
// contacted when no valid offline license is present.
func (m *Manager) Initialize() error {
	if resp, err := m.tryOfflineLicense(); err == nil {
		m.updateCachedValidation(resp)
		log.Printf("[LICENSE] ✅ Offline license: %s (%s) expires %s",
			resp.Organization, resp.LicenseTier, resp.ExpiresAt)
		return nil
	}

	resp, err := m.client.Validate()
	if err != nil {
		log.Printf("[LICENSE] Initial validation failed: %v", err)
		resp, err = m.handleInitialFailure()
		if err != nil {
			return err
		}
	}

	m.updateCachedValidation(resp)

	if !resp.Valid {
		return m.handleInvalidLicense(resp)
	}

	log.Printf("[LICENSE] ✅ License validated: %s (%s)", resp.Organization, resp.LicenseTier)
	log.Printf("[LICENSE] Expires: %s", resp.ExpiresAt)

	m.heartbeatStopCh = make(chan struct{})
	m.client.StartHeartbeatDaemon(m.heartbeatStopCh)
	return nil
}

// tryOfflineLicense looks for a signed .khepra file and verifies it offline
// using the master ML-DSA-65 public key. Returns a ValidateResponse on success.
// Search order: KHEPRA_LICENSE_FILE env → ~/.khepra/license.khepra → any *.khepra in ~/.khepra/.
func (m *Manager) tryOfflineLicense() (*ValidateResponse, error) {
	pubKeyBytes, err := loadMasterPublicKey()
	if err != nil {
		return nil, fmt.Errorf("no master public key: %w", err)
	}

	path, err := findKhepraFile()
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	// SignedLicense is the format produced by cmd/keygen/license_gen.go.
	// ALL fields must match LicenseBlob exactly — the signature covers the full JSON.
	var signed struct {
		License struct {
			Version      string   `json:"version"`
			MachineID    string   `json:"machine_id"`
			Organization string   `json:"organization"`
			Tier         string   `json:"tier"`
			Features     []string `json:"features"`
			IssuedAt     int64    `json:"issued_at"`
			ExpiresAt    int64    `json:"expires_at,omitempty"`
			Issuer       string   `json:"issuer"`
			SignedWith   string   `json:"signed_with"`
		} `json:"license"`
		Signature string `json:"signature"`
	}
	if err := json.Unmarshal(data, &signed); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	// The signature covers the canonical JSON of the inner license blob.
	blobJSON, err := json.Marshal(signed.License)
	if err != nil {
		return nil, fmt.Errorf("re-marshal license blob: %w", err)
	}

	sigBytes, err := hex.DecodeString(signed.Signature)
	if err != nil {
		return nil, fmt.Errorf("decode signature: %w", err)
	}

	if len(pubKeyBytes) != mldsa65.PublicKeySize {
		return nil, fmt.Errorf("master public key wrong size: got %d want %d", len(pubKeyBytes), mldsa65.PublicKeySize)
	}
	var pubKey mldsa65.PublicKey
	var keyBuf [mldsa65.PublicKeySize]byte
	copy(keyBuf[:], pubKeyBytes)
	pubKey.Unpack(&keyBuf)

	if !mldsa65.Verify(&pubKey, blobJSON, nil, sigBytes) {
		return nil, fmt.Errorf("ML-DSA-65 signature invalid for %s", path)
	}

	// Device binding
	machineID := GenerateMachineID()
	if signed.License.MachineID != machineID {
		return nil, fmt.Errorf("license machine_id %s does not match this node %s",
			signed.License.MachineID, machineID)
	}

	// Expiry (0 = perpetual)
	var expiresStr string
	if signed.License.ExpiresAt > 0 {
		exp := time.Unix(signed.License.ExpiresAt, 0)
		if time.Now().After(exp) {
			return nil, fmt.Errorf("offline license expired at %s", exp.Format(time.RFC3339))
		}
		expiresStr = exp.Format(time.RFC3339)
	} else {
		expiresStr = "perpetual"
	}

	return &ValidateResponse{
		Valid:        true,
		Organization: signed.License.Organization,
		LicenseTier:  signed.License.Tier,
		Features:     signed.License.Features,
		IssuedAt:     time.Unix(signed.License.IssuedAt, 0).Format(time.RFC3339),
		ExpiresAt:    expiresStr,
		ValidatedAt:  time.Now().Format(time.RFC3339),
	}, nil
}

// findKhepraFile returns the path to the first valid .khepra file.
func findKhepraFile() (string, error) {
	if p := os.Getenv("KHEPRA_LICENSE_FILE"); p != "" {
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}

	home, _ := os.UserHomeDir()
	if home == "" {
		home = "."
	}

	// Canonical path first
	canonical := filepath.Join(home, ".khepra", "license.khepra")
	if _, err := os.Stat(canonical); err == nil {
		return canonical, nil
	}

	// Glob for any *.khepra in ~/.khepra/
	matches, _ := filepath.Glob(filepath.Join(home, ".khepra", "*.khepra"))
	if len(matches) > 0 {
		return matches[0], nil
	}

	return "", fmt.Errorf("no .khepra license file found in ~/.khepra/")
}

// loadMasterPublicKey returns the ML-DSA-65 master public key bytes.
// Sources (in priority order):
//  1. KHEPRA_MASTER_PUBLIC_KEY env var (hex)
//  2. KHEPRA_MASTER_PUBLIC_KEY_PATH env var
//  3. ~/.khepra/master.pub
//  4. keys/offline/OFFLINE_ROOT_KEY.pub (dev/build machine fallback)
func loadMasterPublicKey() ([]byte, error) {
	if raw := os.Getenv("KHEPRA_MASTER_PUBLIC_KEY"); raw != "" {
		return hex.DecodeString(strings.TrimSpace(raw))
	}

	paths := []string{}
	if p := os.Getenv("KHEPRA_MASTER_PUBLIC_KEY_PATH"); p != "" {
		paths = append(paths, p)
	}
	if home, err := os.UserHomeDir(); err == nil {
		paths = append(paths, filepath.Join(home, ".khepra", "master.pub"))
	}
	paths = append(paths, "keys/offline/OFFLINE_ROOT_KEY.pub")

	for _, p := range paths {
		if data, err := os.ReadFile(p); err == nil {
			return hex.DecodeString(strings.TrimSpace(string(data)))
		}
	}

	return nil, fmt.Errorf("master public key not found; set KHEPRA_MASTER_PUBLIC_KEY or place key at ~/.khepra/master.pub")
}

func (m *Manager) handleInitialFailure() (*ValidateResponse, error) {
	if m.enrollmentToken != "" {
		log.Printf("[LICENSE] Attempting auto-registration...")
		regResp, regErr := m.client.Register(m.enrollmentToken)
		if regErr == nil && (regResp.Status == "registered" || regResp.Status == "already_registered") {
			log.Printf("[LICENSE] ✅ Auto-registration successful: %s", regResp.Organization)
			return m.client.Validate()
		}
		log.Printf("[LICENSE] Registration failed or incomplete: %v", regErr)
	}

	// Fallback/Grace period check logic would go here
	return nil, fmt.Errorf("license validation failed and registration unavailable")
}

func (m *Manager) handleInvalidLicense(resp *ValidateResponse) error {
	log.Printf("[LICENSE] License invalid: %s", resp.Error)
	if resp.FallbackAvailable {
		log.Printf("[LICENSE] Falling back to community edition")
		return nil
	}
	return fmt.Errorf("license invalid: %s", resp.Error)
}

func (m *Manager) updateCachedValidation(resp *ValidateResponse) {
	m.validationMu.Lock()
	defer m.validationMu.Unlock()
	m.cachedValidation = resp
	m.lastValidated = time.Now()
}

// HasFeature checks if license includes specific feature
func (m *Manager) HasFeature(feature string) bool {
	m.validationMu.RLock()
	defer m.validationMu.RUnlock()

	// Grace Period Check: If cached validation is expired > 30 days, force fail
	if time.Since(m.lastValidated) > 30*24*time.Hour {
		return false
	}

	if m.cachedValidation == nil || !m.cachedValidation.Valid {
		return false // Community edition
	}

	for _, f := range m.cachedValidation.Features {
		if f == feature {
			return true
		}
	}

	return false
}

// GetTier returns license tier
func (m *Manager) GetTier() string {
	m.validationMu.RLock()
	defer m.validationMu.RUnlock()

	// Grace Period Check
	if time.Since(m.lastValidated) > 30*24*time.Hour {
		return "community" // Expired grace period
	}

	if m.cachedValidation == nil || !m.cachedValidation.Valid {
		return "community"
	}

	return m.cachedValidation.LicenseTier
}

// GetFullStatus returns the full license status response
func (m *Manager) GetFullStatus() *ValidateResponse {
	m.validationMu.RLock()
	defer m.validationMu.RUnlock()

	var resp *ValidateResponse
	if m.cachedValidation == nil {
		resp = &ValidateResponse{
			Valid:       false,
			LicenseTier: "community",
			Error:       "no_cached_validation",
		}
	} else {
		// Create a copy to avoid mutation issues
		r := *m.cachedValidation
		resp = &r
	}

	// Try to populate LicenseID from the Egyptian Manager if missing
	if resp.LicenseID == "" && m.egyptianMgr != nil {
		licenses := m.egyptianMgr.GetAllLicenses()
		if len(licenses) > 0 {
			resp.LicenseID = licenses[0].ID
		}
	}

	return resp
}

// Stop stops heartbeat daemon
func (m *Manager) Stop() {
	if m.heartbeatStopCh != nil {
		close(m.heartbeatStopCh)
	}
}

// CreateLicense creates a new Egyptian tier license
func (m *Manager) CreateLicense(id string, tier EgyptianTier, days int) (*License, error) {
	return m.egyptianMgr.CreateLicense(id, tier, days)
}

// GetLicense retrieves a license by ID
func (m *Manager) GetLicense(id string) (*License, error) {
	return m.egyptianMgr.GetLicense(id)
}

// GetAllLicenses returns all managed licenses
func (m *Manager) GetAllLicenses() []*License {
	return m.egyptianMgr.GetAllLicenses()
}

// UpgradeLicense upgrades a license to a higher tier
func (m *Manager) UpgradeLicense(id string, newTier EgyptianTier) error {
	return m.egyptianMgr.UpgradeLicense(id, newTier)
}

// Register registers the machine with a token
func (m *Manager) Register(token string) (*RegisterResponse, error) {
	return m.client.Register(token)
}

// Heartbeat sends a heartbeat to the telemetry server
func (m *Manager) Heartbeat() (*HeartbeatResponse, error) {
	statusData := map[string]interface{}{
		"manual_trigger": true,
		"timestamp":      time.Now().Unix(),
	}
	resp, err := m.client.SendHeartbeat(statusData)
	if err == nil && resp.Status == "active" {
		// The heartbeat RPC confirms server-side liveness only; a full Validate() call
		// is required to refresh the cached tier/feature set.
		log.Printf("[LICENSE] Manual heartbeat successful: %s", resp.Message)
	}
	return resp, err
}

// RevokeLicense marks the current license as revoked in-memory.
// Sets Valid=false and Error="revoked" on the cached validation so that
// GetStatus().Revoked == true and IsValid() == false for this process lifetime.
// On the next server restart the telemetry server will be re-queried.
func (m *Manager) RevokeLicense(stripeEventID, reason string) error {
	m.validationMu.Lock()
	defer m.validationMu.Unlock()
	if m.cachedValidation != nil {
		m.cachedValidation.Valid = false
		m.cachedValidation.Error = "revoked"
	}
	log.Printf("[LICENSE] License revoked: stripe_event=%s reason=%s", stripeEventID, reason)
	return nil
}
