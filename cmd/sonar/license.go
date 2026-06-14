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

	"github.com/cloudflare/circl/sign/dilithium/mode3"
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
	ValidationURL     = "https://telemetry.souhimbou.org/license/validate"
	HeartbeatURL      = "https://telemetry.souhimbou.org/license/heartbeat"
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

	// Embedded Dilithium3 private key for signing machine IDs
	// This will be set via build arg: -ldflags "-X main.dilithiumPrivateKey=..."
	dilithiumPrivateKey string

	// Offline Root Public Key (Dilithium3)
	// Generated for Air-Gapped Environments. Trust anchor for license.sig.
	offlineRootPublicKey = "54e1c77b0632c73c83ac9a78bc43031b575a4af1944b5defcd31c84a0ce3ea93823696d677b2cce2fbb669665efe9ad31f451808f4156b51bc90aefd1b1a43416c5dac518b83bda82404343dd3fc302440f6121b1036af8ff2ab85578f0c0e5576c0a9754641b07508033cd0b96c6b71f78a9899568ce57a1c155f3e0f5cbbd9b7f65071bd1c3c1d401fe8df032fcc665afedd85e904f1abd0cc47fe2a661a8682a4dec30ad0c95f62f73f7d218cfdaf9301f9ba3ff48db507cf20dc1dc1b2aba1ece160dd2e017f5a4ab5779d0c8b1c3fe929e68dce346638c2e18643e8e880edc58c5c7ffa0703c748b5728e7168da27fcfb10957e28e63c5b53ec8678ed81986b862f199f39fca05a71dd7a86ed12542e44ad32c892b722e75ba6bd65eb41163de1549712d1c2a040f5c5535075011fe7fac794b681ba2c0bf1a2836c2bb0cc48d7a46b3dad82906ad4b4eb910e7d232f5c16065421a899c83682487d8d99068709bf6655a27cd1ca9b7871b67c9dd7143d8418d9a7c982598ac070f3741e25c8a681da4ce38390d0270f0d1975e5f2d0101dfdcff1faf0daed9b682cc7253559200915e0199b2ef97c30b257cb668068bbe4702f50eb0bd8537f53934b73e8f98a6547ecfbd6254b294d58fe80adb960c40fb39b44e16c02182996875e8e5eb0341933e60cbaa58e842180442c762694ba88b1c2395563bd0d13526371c8413f07da7079cf3a357465de5881c2afb02aef4b4838b5079e249101ec1775950e05392492128dbd2cb3b1d6b382ee8d55bb02833769358e3d6b9edf8b69c6d74583dfdb7a2222447f6463b1421798c5201912ef1b515610633fa87217752b0d7a178338f11d69d010a9c8dde88f39edd7d1a275469b76d7675f9e7095dbcc40aecff9557b7b5597d74b94cb978442dbaca7a3ecd77a691cb5d456f58ef5a83d62d9b8edbb74f4b88a1588682d82334680313011f23baaf4be7cc3b20b8093198683b975c9440ee2f15715f1f0b6d54b4ce731bd93eb279f23c4713cb759a226b7f9eb9e1e89e72c91a5ce82eaf41314a33327f986ad0c6fc45832ffc457a77ad4b679c78562a18435fcad0c87c452f1420554477995377eb4316864042620a7021434e1f4db5d323fd3bf55d40ef4ba6b69611b6d41a12838f6d41910f2134fa3f61a3ad9be718e89422a67f91ef2a47c22000dedf8685849b6ba50a8e199a32849529b1fb00cc0c0f6dc8ea48b250c2c1f2e200749ca0525ab50ce94f1a9146ad3995447c631474959a794a5a5488f127923fc4f36327bd5a7d42e8d946fdaee9f561ac362949961f06e899d982897bc666bed8ea441b2b4849b8f4421b100edfec7289ffe1aa31000302888f13ae01224e3439be311b76e485474bd5ecb6c2948f12e641d9ee9a880f29baaf756ee873e90e0c50b529a9bfd8a1348c6d0a2bd0db7d04b99716e07f6c76385d1fd65ebffc6c5792400abe7c44319f852dbeac147e22bda0576eefff738ca820829b2d8d2a3ac3879a2ec1ca99068b51390eaca374278ef5fb82c80d6e98c5aa29140f23cc842e02b3896abfe8b77ecc2ffd577528743be5eb57a4b2b5787faacb36bea04ec9fb5d41903ca2dcbc664e2a3bee787f4870e0d2af43b720863cddf0d9b7c5f16ff3e9e4dcfb55f621ca2a1a647419e470beecf703f8957e11278f4886c731eca81d7b71710641c4b377eff0118bd95c63aa56f8f6b42e0f7a34d168e6efe2d9f827ceda3d8f3461247394323db11856031f816dbdd93f7c72048dcdbc5accce5033b36d254f6294b7d3b9068e032d7d7451b4c8faa429290a4d5ead3a6960131f36e253330f2880177581db4db9348acb960e416a97fd9eedd5faa77d5e5658e1d9b0a6fa34465ad30cfb71173bb83e093d382b779034e1b36a14dad6b62d1ac7ba41719457a18d925f6a8b632ee919237750051b5a2c7d39fb33cf7db8185401298bc539b01c757e036900224894647eb3428a546785e2b92de8d249b05eaf9f76267a5ce28eb4363bc83f77698bbb2322d45718fcaf1b685a005cb220504392b63a39a86358d1c6703198f1742f6efa007bf4404b642990afeb7e1912d4939ab0823662b39c184cbc7ed7a857904403425d0e81f0d8ba6580e8e5fb13f5c88e2f86330d4ce205d971df416b7cd465234c89ee8721b6971ddbafb51806a22a71ce81231a3134e354941dfb01822d104576bbac14e60771fe9f681f5ad321de4383c34e4703177c8e3481273e882c966a4bc2f1d0e357bffd6245f7807daa4816ab75a66f1904c7951a7da44732d9cc48ad0a91dc5110a258088e7eb71154602f9fa3278c45c8c4b271f5805bb222423436609e5da444dc991f35869e8e8d239be7a0eda8146c2058e8ee414e5d84bf67c4c6b543f52b924542a61ad2e4fd619213ce2da3a2cd11c4ce87022d63ff4de7ae8eedc38b99807170ce81f5b7f5fc2d04c3af3b4c44c476f771e2463b811e7f590921c0ca53446d61dd82bb633b8c611cfa3ffce34936cb81e204d103762a2328f43abc6b0c7ddc758ba126c4b50d956cfb66ed500aeecc9d9fbb951d73d4d2b55a19f13a580fbf73c38610fbf0f4387cb4dbe904cb7571ee525aad78ba6e5cc5dd3108374eba16323f88b2704496efde4df7b09af9f8851ebf9a9c661ca80066378873962252a97b9d25d4da93b610941aea2d01b7bc7afd65b9eaf814004e98b22def31efa0b4df26788285598de7a4c87512da59fa8b20bef7d9f"
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

	// Sign machine ID with Dilithium3
	signature, err := signMachineID(machineID)
	if err != nil {
		logger.Errorf("Failed to sign machine ID: %v", err)
		return fallbackToCommunity("signature generation failed")
	}

	// Validate license with server
	license, err := validateLicense(machineID, signature)
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
	go licenseHeartbeat(machineID, signature)

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

// signMachineID creates a Dilithium3 signature of the machine ID
func signMachineID(machineID string) (string, error) {
	var sk *mode3.PrivateKey
	var err error

	// Check if we have an embedded private key
	if dilithiumPrivateKey == "" {
		// No embedded key - use ephemeral key (community edition behavior)
		logger.Warn("No embedded Dilithium3 key, generating ephemeral key")
		// Correctly pass rand.Reader
		_, sk, err = mode3.GenerateKey(nil)
		if err != nil {
			return "", fmt.Errorf("failed to generate ephemeral key: %w", err)
		}
	} else {
		// Decode embedded private key
		skBytes, err := hex.DecodeString(dilithiumPrivateKey)
		if err != nil {
			return "", fmt.Errorf("failed to decode private key: %w", err)
		}

		// Unmarshal private key
		sk = new(mode3.PrivateKey)
		if err := sk.UnmarshalBinary(skBytes); err != nil {
			return "", fmt.Errorf("failed to unmarshal private key: %w", err)
		}
	}

	// Sign machine ID using SignTo
	var sig [mode3.SignatureSize]byte
	mode3.SignTo(sk, []byte(machineID), sig[:])

	return hex.EncodeToString(sig[:]), nil
}

// validateLicense sends validation request to telemetry server
func validateLicense(machineID, signature string) (*LicenseResponse, error) {
	// Build request payload
	payload := map[string]interface{}{
		"machine_id":      machineID,
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
func licenseHeartbeat(machineID, signature string) {
	ticker := time.NewTicker(HeartbeatInterval)
	defer ticker.Stop()

	for range ticker.C {
		// Build heartbeat payload
		payload := map[string]interface{}{
			"machine_id": machineID,
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

	// Verify signature
	pkBytes, err := hex.DecodeString(offlineRootPublicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid root key: %w", err)
	}

	var pk mode3.PublicKey
	pk.Unpack((*[mode3.PublicKeySize]byte)(pkBytes))

	sigBytes, err := hex.DecodeString(envelope.Signature)
	if err != nil {
		return nil, fmt.Errorf("invalid signature hex: %w", err)
	}
	var sig [mode3.SignatureSize]byte
	copy(sig[:], sigBytes)

	// Verify signature against payload
	if !mode3.Verify(&pk, []byte(envelope.Payload), sig[:]) {
		return nil, fmt.Errorf("signature verification failed")
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
