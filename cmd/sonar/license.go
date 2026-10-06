package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	stdlog "log"

	khlicense "github.com/nouchix/PQC-Khepra-MCP/pkg/license"
)

var (
	// Simple logger wrapper
	logger = &SimpleLogger{}
	// Version injected by build
	version = "dev"
)

type SimpleLogger struct{}

func (l *SimpleLogger) Info(args ...interface{}) {
	stdlog.Println(append([]interface{}{"[INFO] "}, args...)...)
}
func (l *SimpleLogger) Infof(format string, args ...interface{}) {
	stdlog.Printf("[INFO] "+format, args...)
}
func (l *SimpleLogger) Warn(args ...interface{}) {
	stdlog.Println(append([]interface{}{"[WARN] "}, args...)...)
}
func (l *SimpleLogger) Warnf(format string, args ...interface{}) {
	stdlog.Printf("[WARN] "+format, args...)
}
func (l *SimpleLogger) Error(args ...interface{}) {
	stdlog.Println(append([]interface{}{"[ERROR] "}, args...)...)
}
func (l *SimpleLogger) Errorf(format string, args ...interface{}) {
	stdlog.Printf("[ERROR] "+format, args...)
}

// License validation configuration
const (
	ValidationURL     = "https://telemetry.souhimbou.ai/license/validate"
	HeartbeatURL      = "https://telemetry.souhimbou.ai/license/heartbeat"
	ValidationTimeout = 10 * time.Second
	HeartbeatInterval = 1 * time.Hour
)

// LicenseResponse represents the server's license validation response
type LicenseResponse struct {
	Valid             bool          `json:"valid"`
	Features          []string      `json:"features"`
	LicenseTier       string        `json:"license_tier"`
	Organization      string        `json:"organization"`
	ExpiresAt         string        `json:"expires_at"`
	IssuedAt          string        `json:"issued_at"`
	ValidatedAt       string        `json:"validated_at"`
	ClientCountry     string        `json:"client_country"`
	LegalNotice       string        `json:"legal_notice"`
	Limits            LicenseLimits `json:"limits"`
	Error             string        `json:"error,omitempty"`
	Message           string        `json:"message,omitempty"`
	FallbackAvailable bool          `json:"fallback_available,omitempty"`
}

type LicenseLimits struct {
	MaxDevices         int `json:"max_devices"`
	MaxConcurrentScans int `json:"max_concurrent_scans"`
	RetentionDays      int `json:"retention_days"`
	AICreditsMonthly   int `json:"ai_credits_monthly"`
}

// LicenseState holds the current license status
type LicenseState struct {
	Valid            bool
	Features         []string
	Tier             string
	Limits           LicenseLimits
	UsePremiumCrypto bool
	UseHSM           bool
}

var (
	// Global license state
	currentLicense LicenseState

	// Offline root public key (ML-DSA-87, hex) for air-gapped license.sig
	// files. Empty until the ML-DSA-87 offline root is created; the previous
	// root was a pre-standard Dilithium3 key and is no longer trusted. With no
	// root pinned, offline validation fails and sonar runs as community.
	offlineRootPublicKey = ""
)

// initLicense performs license validation at startup
func initLicense() error {
	// Check if telemetry/licensing is disabled via environment
	if os.Getenv("KHEPRA_TELEMETRY") == "false" || os.Getenv("KHEPRA_LICENSE_DISABLE") == "true" {
		logger.Warn("License validation disabled via environment variable, using community edition")
		currentLicense = LicenseState{
			Valid:            false,
			Features:         []string{"basic_pqc"},
			Tier:             "community",
			Limits:           LicenseLimits{MaxConcurrentScans: 5, RetentionDays: 1, AICreditsMonthly: 50},
			UsePremiumCrypto: false,
			UseHSM:           false,
		}
		return nil
	}

	// Generate unique machine ID
	machineID, err := generateMachineID()
	if err != nil {
		logger.Errorf("Failed to generate machine ID: %v", err)
		return fallbackToCommunity("machine ID generation failed")
	}

	// Validate license with server (ML-DSA-87 device signature)
	license, err := validateLicense(machineID)
	if err != nil {
		logger.Warnf("Online validation failed: %v", err)

		// Attempt offline validation (Air-Gap Support)
		offlineParams := OfflineLicenseParams{
			Details:   "Checked local license.sig",
			PublicKey: offlineRootPublicKey,
		}
		logger.Warnf("Attempting offline validation: %+v", offlineParams)

		if offlineLicense, offlineErr := tryOfflineValidation(machineID); offlineErr == nil {
			logger.Info("✅ Offline License validated successfully (Air-Gap Mode)")

			// Use offline license data
			currentLicense = LicenseState{
				Valid:            true,
				Features:         offlineLicense.Features,
				Tier:             offlineLicense.LicenseTier,
				Limits:           offlineLicense.Limits,
				UsePremiumCrypto: contains(offlineLicense.Features, "premium_pqc"),
				UseHSM:           contains(offlineLicense.Features, "hsm_integration"),
			}
			logger.Infof("Features enabled: %v", offlineLicense.Features)
			return nil
		} else {
			logger.Warnf("Offline validation failed: %v", offlineErr)
			return fallbackToCommunity(fmt.Sprintf("validation error: %v; offline: %v", err, offlineErr))
		}
	}

	if !license.Valid {
		logger.Warnf("License invalid: %s", license.Message)
		return fallbackToCommunity(license.Message)
	}

	// License is valid - configure premium features
	currentLicense = LicenseState{
		Valid:            true,
		Features:         license.Features,
		Tier:             license.LicenseTier,
		Limits:           license.Limits,
		UsePremiumCrypto: contains(license.Features, "premium_pqc"),
		UseHSM:           contains(license.Features, "hsm_integration"),
	}

	logger.Infof("✅ License validated: %s (%s)", license.Organization, license.LicenseTier)
	logger.Infof("Features enabled: %v", license.Features)

	if license.ExpiresAt != "" && license.ExpiresAt != "null" {
		logger.Infof("License expires: %s", license.ExpiresAt)
	} else {
		logger.Info("License type: Perpetual")
	}

	// Start heartbeat goroutine
	go licenseHeartbeat(machineID)

	return nil
}

// generateMachineID creates a unique, reproducible identifier for this installation
func generateMachineID() (string, error) {
	components := []string{
		getHostname(),
		getMACAddress(),
		getCPUInfo(),
		getInstallPath(),
	}

	// Join all components and hash
	data := strings.Join(components, "|")
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:]), nil
}

// getHostname returns the system hostname
func getHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return hostname
}

// getMACAddress returns the primary MAC address
func getMACAddress() string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "00:00:00:00:00:00"
	}

	// Try to find physical interface (usually not loopback and has MAC)
	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue // skip loopback
		}
		if iface.Flags&net.FlagUp == 0 {
			continue // skip down interfaces
		}
		if len(iface.HardwareAddr) > 0 {
			return iface.HardwareAddr.String()
		}
	}

	return "00:00:00:00:00:00"
}

// getCPUInfo returns CPU information
func getCPUInfo() string {
	return runtime.GOARCH + "-" + runtime.GOOS
}

// getInstallPath returns the installation directory
func getInstallPath() string {
	exe, err := os.Executable()
	if err != nil {
		return "/unknown"
	}
	return exe
}

// signDeviceMessage signs a license server call with this machine's ML-DSA-87
// device key (shared with pkg/license: ~/.khepra/license.key).
func signDeviceMessage(operation, machineID string) (string, int64, error) {
	keyHex, err := khlicense.LoadOrCreateDeviceKey()
	if err != nil {
		return "", 0, fmt.Errorf("device key: %w", err)
	}
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return "", 0, fmt.Errorf("device key: %w", err)
	}
	ts := time.Now().Unix()
	sig, err := khlicense.SignDeviceMessage(key, operation, machineID, ts)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(sig), ts, nil
}

// validateLicense sends validation request to telemetry server
func validateLicense(machineID string) (*LicenseResponse, error) {
	signature, ts, err := signDeviceMessage("validate", machineID)
	if err != nil {
		return nil, fmt.Errorf("failed to sign validation request: %w", err)
	}

	// Build request payload
	payload := map[string]interface{}{
		"machine_id":      machineID,
		"timestamp":       ts,
		"signature":       signature,
		"version":         version, // Global version variable
		"installation_id": machineID,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: ValidationTimeout,
	}

	// Send POST request
	resp, err := client.Post(ValidationURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to send validation request: %w", err)
	}
	defer resp.Body.Close()

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Parse response
	var license LicenseResponse
	if err := json.Unmarshal(body, &license); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &license, nil
}

// licenseHeartbeat sends periodic heartbeats to maintain license validity
func licenseHeartbeat(machineID string) {
	ticker := time.NewTicker(HeartbeatInterval)
	defer ticker.Stop()

	for range ticker.C {
		signature, ts, err := signDeviceMessage("heartbeat", machineID)
		if err != nil {
			logger.Errorf("Failed to sign heartbeat: %v", err)
			continue
		}

		// Build heartbeat payload
		payload := map[string]interface{}{
			"machine_id": machineID,
			"timestamp":  ts,
			"signature":  signature,
			"status_data": map[string]interface{}{
				"uptime":  time.Now().Unix(),
				"version": version,
			},
		}

		jsonData, err := json.Marshal(payload)
		if err != nil {
			logger.Errorf("Failed to marshal heartbeat: %v", err)
			continue
		}

		// Send heartbeat
		client := &http.Client{Timeout: ValidationTimeout}
		resp, err := client.Post(HeartbeatURL, "application/json", bytes.NewBuffer(jsonData))
		if err != nil {
			logger.Errorf("Heartbeat failed: %v", err)
			continue
		}

		// Check response
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		var heartbeatResp struct {
			Status string `json:"status"`
			Action string `json:"action"`
		}
		if err := json.Unmarshal(body, &heartbeatResp); err == nil {
			if heartbeatResp.Status == "revoked" || heartbeatResp.Status == "expired" {
				logger.Errorf("License %s: %s", heartbeatResp.Status, heartbeatResp.Action)
				// Disable premium features immediately
				currentLicense.UsePremiumCrypto = false
				currentLicense.UseHSM = false
				logger.Warn("Premium features disabled, falling back to community edition")
				return // Exit heartbeat loop
			}
		}
	}
}

// fallbackToCommunity configures the system to use community edition
func fallbackToCommunity(reason string) error {
	logger.Warnf("Falling back to community edition: %s", reason)
	currentLicense = LicenseState{
		Valid:            false,
		Features:         []string{"basic_pqc"},
		Tier:             "community",
		Limits:           LicenseLimits{MaxConcurrentScans: 5, RetentionDays: 1, AICreditsMonthly: 50},
		UsePremiumCrypto: false,
		UseHSM:           false,
	}
	logger.Info("Using Cloudflare CIRCL for post-quantum cryptography")
	return nil
}

// contains checks if a string slice contains a value
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// Exported accessors removed as they were unused (isPremiumLicensed, isHSMEnabled, etc)

// OfflineLicenseParams used for offline validation logging
type OfflineLicenseParams struct {
	Details   string
	PublicKey string
}

// tryOfflineValidation verifies a local license.sig file against the Offline Root Key
func tryOfflineValidation(_ string) (*LicenseResponse, error) {
	// Look for license file
	licensePath := "license.sig"
	if _, err := os.Stat(licensePath); os.IsNotExist(err) {
		return nil, fmt.Errorf("license.sig not found")
	}

	// Read license file (JSON content + Signature)
	content, err := os.ReadFile(licensePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read license file: %w", err)
	}

	var envelope struct {
		Payload   string `json:"payload"`
		Signature string `json:"signature"`
	}
	if err := json.Unmarshal(content, &envelope); err != nil {
		return nil, fmt.Errorf("invalid license file format: %w", err)
	}

	// Verify signature (ML-DSA-87 offline root, license context)
	if offlineRootPublicKey == "" {
		return nil, fmt.Errorf("no ML-DSA-87 offline root is pinned in this build")
	}
	pkBytes, err := hex.DecodeString(offlineRootPublicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid root key: %w", err)
	}

	sigBytes, err := hex.DecodeString(envelope.Signature)
	if err != nil {
		return nil, fmt.Errorf("invalid signature hex: %w", err)
	}

	if err := khlicense.VerifyRootSignature(pkBytes, []byte(envelope.Payload), sigBytes); err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}

	// Payload is the JSON string of LicenseResponse
	var license LicenseResponse
	if err := json.Unmarshal([]byte(envelope.Payload), &license); err != nil {
		return nil, fmt.Errorf("failed to parse license payload: %w", err)
	}

	// Check Expiry
	if license.ExpiresAt != "" && license.ExpiresAt != "null" {
		expiry, err := time.Parse("2006-01-02", license.ExpiresAt)
		if err == nil {
			if time.Now().After(expiry) {
				return nil, fmt.Errorf("license expired on %s", license.ExpiresAt)
			}
		}
	}

	return &license, nil
}
