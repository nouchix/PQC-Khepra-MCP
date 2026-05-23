// License Signer - Local ML-DSA-65 signing daemon
//
// This script runs on your local machine and:
// 1. Polls the telemetry server for pending license requests
// 2. Signs each license with your local ML-DSA-65 private key
// 3. Submits the signed license back to the server
//
// Run with: go run scripts/license-signer.go
//
// Environment variables:
//   KHEPRA_PRIVATE_KEY_PATH - Path to ML-DSA-65 private key file
//   KHEPRA_TELEMETRY_URL    - Telemetry server URL (default: https://telemetry.souhimbou.org)
//   KHEPRA_ADMIN_TOKEN      - Admin JWT token for authentication
//   KHEPRA_POLL_INTERVAL    - Poll interval in seconds (default: 30)
//
// Usage via Cloudflare Tunnel:
//   The telemetry server is accessed via agent.souhimbou.org tunnel

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

// Config holds the signer configuration
type Config struct {
	PrivateKeyPath string
	TelemetryURL   string
	AdminToken     string
	PollInterval   time.Duration
}

// LicenseRequest from the telemetry server
type LicenseRequest struct {
	RequestID       string   `json:"request_id"`
	MachineID       string   `json:"machine_id"`
	Organization    string   `json:"organization"`
	CustomerEmail   string   `json:"customer_email"`
	LicenseTier     string   `json:"license_tier"`
	Features        []string `json:"features"`
	Limits          Limits   `json:"limits"`
	RequestedAt     string   `json:"requested_at"`
	Source          string   `json:"source"`
	StripeSessionID string   `json:"stripe_session_id,omitempty"`
	PilotID         string   `json:"pilot_id,omitempty"`
}

type Limits struct {
	MaxDevices          int `json:"max_devices"`
	MaxConcurrentScans  int `json:"max_concurrent_scans"`
	RetentionDays       int `json:"retention_days"`
	AICreditsMonthly    int `json:"ai_credits_monthly"`
}

// PendingResponse from GET /api/licenses/pending
type PendingResponse struct {
	Pending []LicenseRequest `json:"pending"`
	Count   int              `json:"count"`
}

// LicenseBlob is the signed license structure
type LicenseBlob struct {
	Version      string   `json:"version"`
	MachineID    string   `json:"machine_id"`
	Organization string   `json:"organization"`
	Tier         string   `json:"tier"`
	Features     []string `json:"features"`
	Limits       Limits   `json:"limits"`
	IssuedAt     int64    `json:"issued_at"`
	ExpiresAt    int64    `json:"expires_at,omitempty"`
	Issuer       string   `json:"issuer"`
	SignedWith   string   `json:"signed_with"`
}

// SignedLicense is the complete license with signature
type SignedLicense struct {
	License   LicenseBlob `json:"license"`
	Signature string      `json:"signature"` // Hex-encoded ML-DSA-65 signature
}

func main() {
	fmt.Println("╔═══════════════════════════════════════════════════════════╗")
	fmt.Println("║       KHEPRA Protocol - License Signing Daemon            ║")
	fmt.Println("║              ML-DSA-65 Post-Quantum Signatures            ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════╝")
	fmt.Println()

	config := loadConfig()

	// Load private key
	privateKey, err := loadPrivateKey(config.PrivateKeyPath)
	if err != nil {
		fmt.Printf("❌ Failed to load private key: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("✅ Private key loaded from: %s\n", config.PrivateKeyPath)
	fmt.Printf("📡 Telemetry URL: %s\n", config.TelemetryURL)
	fmt.Printf("⏱️  Poll interval: %v\n", config.PollInterval)
	fmt.Println()

	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Create HTTP client
	client := &http.Client{Timeout: 30 * time.Second}

	// Main polling loop
	ticker := time.NewTicker(config.PollInterval)
	defer ticker.Stop()

	fmt.Println("🔄 Starting license signing daemon...")
	fmt.Println("   Press Ctrl+C to stop")
	fmt.Println()

	// Run immediately, then on interval
	processLicenses(client, config, privateKey)

	for {
		select {
		case <-ticker.C:
			processLicenses(client, config, privateKey)
		case sig := <-sigChan:
			fmt.Printf("\n⚡ Received signal %v, shutting down...\n", sig)
			return
		}
	}
}

func loadConfig() Config {
	config := Config{
		PrivateKeyPath: os.Getenv("KHEPRA_PRIVATE_KEY_PATH"),
		TelemetryURL:   os.Getenv("KHEPRA_TELEMETRY_URL"),
		AdminToken:     os.Getenv("KHEPRA_ADMIN_TOKEN"),
	}

	// Default values
	if config.TelemetryURL == "" {
		config.TelemetryURL = "https://telemetry.souhimbou.org"
	}

	if config.PrivateKeyPath == "" {
		// Check common locations
		homeDir, _ := os.UserHomeDir()
		possiblePaths := []string{
			"./khepra_master.key",
			homeDir + "/.khepra/master.key",
			homeDir + "/khepra_master.key",
		}
		for _, p := range possiblePaths {
			if _, err := os.Stat(p); err == nil {
				config.PrivateKeyPath = p
				break
			}
		}
	}

	if config.PrivateKeyPath == "" {
		fmt.Println("❌ KHEPRA_PRIVATE_KEY_PATH not set and no key found in default locations")
		fmt.Println("   Set the environment variable or place key in ./khepra_master.key")
		os.Exit(1)
	}

	if config.AdminToken == "" {
		fmt.Println("❌ KHEPRA_ADMIN_TOKEN not set")
		fmt.Println("   Get a token from: POST /admin/login")
		os.Exit(1)
	}

	// Parse poll interval
	intervalStr := os.Getenv("KHEPRA_POLL_INTERVAL")
	if intervalStr != "" {
		if secs, err := time.ParseDuration(intervalStr + "s"); err == nil {
			config.PollInterval = secs
		}
	}
	if config.PollInterval == 0 {
		config.PollInterval = 30 * time.Second
	}

	return config
}

func loadPrivateKey(path string) (*mldsa65.PrivateKey, error) {
	keyData, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	// Try hex decoding first
	keyBytes, err := hex.DecodeString(string(keyData))
	if err != nil {
		// Assume raw bytes
		keyBytes = keyData
	}

	// ML-DSA-65 private key is 4032 bytes
	if len(keyBytes) != mldsa65.PrivateKeySize {
		return nil, fmt.Errorf("invalid key size: got %d, expected %d", len(keyBytes), mldsa65.PrivateKeySize)
	}

	var keyBuf [mldsa65.PrivateKeySize]byte
	copy(keyBuf[:], keyBytes)

	var privateKey mldsa65.PrivateKey
	privateKey.Unpack(&keyBuf)

	return &privateKey, nil
}

func processLicenses(client *http.Client, config Config, privateKey *mldsa65.PrivateKey) {
	// Fetch pending licenses
	pending, err := fetchPendingLicenses(client, config)
	if err != nil {
		fmt.Printf("⚠️  Failed to fetch pending licenses: %v\n", err)
		return
	}

	if len(pending) == 0 {
		fmt.Printf("[%s] No pending licenses\n", time.Now().Format("15:04:05"))
		return
	}

	fmt.Printf("📋 Found %d pending license(s)\n", len(pending))

	for _, req := range pending {
		err := signAndSubmitLicense(client, config, privateKey, req)
		if err != nil {
			fmt.Printf("   ❌ %s: %v\n", req.RequestID, err)
		} else {
			fmt.Printf("   ✅ %s: Signed and submitted (%s - %s)\n",
				req.RequestID, req.Organization, req.LicenseTier)
		}
	}
	fmt.Println()
}

func fetchPendingLicenses(client *http.Client, config Config) ([]LicenseRequest, error) {
	url := config.TelemetryURL + "/api/licenses/pending"

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+config.AdminToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 {
		return nil, fmt.Errorf("unauthorized - check your admin token")
	}

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	var pendingResp PendingResponse
	if err := json.NewDecoder(resp.Body).Decode(&pendingResp); err != nil {
		return nil, err
	}

	return pendingResp.Pending, nil
}

func signAndSubmitLicense(client *http.Client, config Config, privateKey *mldsa65.PrivateKey, licReq LicenseRequest) error {
	now := time.Now().Unix()

	// Calculate expiration based on tier
	var expiresAt int64
	switch licReq.LicenseTier {
	case "pilot":
		expiresAt = now + (30 * 86400) // 30 days
	case "pro":
		expiresAt = now + (365 * 86400) // 1 year
	case "enterprise":
		expiresAt = now + (365 * 86400) // 1 year
	case "government":
		expiresAt = 0 // Perpetual
	default:
		expiresAt = now + (30 * 86400) // Default 30 days
	}

	// Create license blob
	licenseBlob := LicenseBlob{
		Version:      "1.0",
		MachineID:    licReq.MachineID,
		Organization: licReq.Organization,
		Tier:         licReq.LicenseTier,
		Features:     licReq.Features,
		Limits:       licReq.Limits,
		IssuedAt:     now,
		ExpiresAt:    expiresAt,
		Issuer:       "SECRED KNOWLEDGE INC.",
		SignedWith:   "ML-DSA-65",
	}

	// Serialize license for signing
	licenseJSON, err := json.Marshal(licenseBlob)
	if err != nil {
		return fmt.Errorf("failed to serialize license: %w", err)
	}

	// Sign with ML-DSA-65
	signature := make([]byte, mldsa65.SignatureSize)
	mldsa65.SignTo(privateKey, licenseJSON, nil, false, signature)

	signatureHex := hex.EncodeToString(signature)

	// Create full signed license blob
	signedLicense := SignedLicense{
		License:   licenseBlob,
		Signature: signatureHex,
	}

	signedLicenseJSON, err := json.Marshal(signedLicense)
	if err != nil {
		return fmt.Errorf("failed to serialize signed license: %w", err)
	}

	// Submit to server
	submitPayload := map[string]interface{}{
		"request_id":   licReq.RequestID,
		"machine_id":   licReq.MachineID,
		"signature":    signatureHex,
		"license_blob": string(signedLicenseJSON),
	}

	if expiresAt > 0 {
		daysRemaining := (expiresAt - now) / 86400
		submitPayload["expires_in_days"] = daysRemaining
	}

	payloadJSON, _ := json.Marshal(submitPayload)

	url := config.TelemetryURL + "/api/licenses/complete"
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(payloadJSON))
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Bearer "+config.AdminToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 201 && resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// Helper function for testing - generates a new keypair
func generateTestKeypair() {
	pub, priv, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Printf("Failed to generate keypair: %v\n", err)
		return
	}

	pubBytes, err := pub.MarshalBinary()
	if err != nil {
		fmt.Printf("Failed to marshal public key: %v\n", err)
		return
	}

	privBytes, err := priv.MarshalBinary()
	if err != nil {
		fmt.Printf("Failed to marshal private key: %v\n", err)
		return
	}

	fmt.Println("Generated ML-DSA-65 keypair:")
	fmt.Printf("Public key (%d bytes):\n%s\n\n", len(pubBytes), hex.EncodeToString(pubBytes))
	fmt.Printf("Private key (%d bytes):\n%s\n", len(privBytes), hex.EncodeToString(privBytes))
}
