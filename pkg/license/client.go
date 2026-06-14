package license

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

const MIMEApplicationJSON = "application/json"

// AgentVersion is set at build time via:
//
//	go build -ldflags "-X github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/license.AgentVersion=$(git describe --tags --always --dirty)"
//
// Falls back to the default below when built without ldflags (local/dev builds).
var AgentVersion = "v1.5.0-NUCLEAR"

// LicenseClient handles license validation with telemetry server
type LicenseClient struct {
	ServerURL  string
	MachineID  string
	PrivateKey string // Hex-encoded Dilithium3 private key
	HTTPClient *http.Client
}

// SendRequest is a helper for JSON POST requests
func (lc *LicenseClient) SendRequest(method, url string, payload interface{}) ([]byte, *http.Response, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, nil, err
	}

	client := lc.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}

	req, err := http.NewRequest(method, url, bytes.NewBuffer(data))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Content-Type", MIMEApplicationJSON)

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	return body, resp, err
}

// ValidateRequest sent to /license/validate
type ValidateRequest struct {
	MachineID      string `json:"machine_id"`
	Signature      string `json:"signature"` // Dilithium3 signature
	Version        string `json:"version"`
	InstallationID string `json:"installation_id"`
}

// ValidateResponse from /license/validate
type ValidateResponse struct {
	Valid             bool     `json:"valid"`
	LicenseID         string   `json:"license_id,omitempty"`
	Features          []string `json:"features"`
	LicenseTier       string   `json:"license_tier"`
	Organization      string   `json:"organization"`
	ExpiresAt         string   `json:"expires_at"`
	IssuedAt          string   `json:"issued_at"`
	ValidatedAt       string   `json:"validated_at"`
	Error             string   `json:"error,omitempty"`
	FallbackAvailable bool     `json:"fallback_available,omitempty"`
}

// HeartbeatRequest sent to /license/heartbeat
type HeartbeatRequest struct {
	MachineID  string                 `json:"machine_id"`
	Signature  string                 `json:"signature"`
	StatusData map[string]interface{} `json:"status_data"`
}

// HeartbeatResponse from /license/heartbeat
type HeartbeatResponse struct {
	Status          string `json:"status"` // 'active', 'revoked', 'expired'
	Action          string `json:"action,omitempty"`
	Message         string `json:"message,omitempty"`
	NextHeartbeatIn int    `json:"next_heartbeat_in"`
}

// RegisterRequest sent to /license/register for auto-enrollment
type RegisterRequest struct {
	MachineID       string `json:"machine_id"`
	EnrollmentToken string `json:"enrollment_token"`
	Hostname        string `json:"hostname"`
	Platform        string `json:"platform"`
	AgentVersion    string `json:"agent_version"`
}

// RegisterResponse from /license/register
type RegisterResponse struct {
	Status        string   `json:"status"` // 'registered', 'already_registered', error
	MachineID     string   `json:"machine_id"`
	Organization  string   `json:"organization"`
	Features      []string `json:"features"`
	LicenseTier   string   `json:"license_tier"`
	IssuedAt      string   `json:"issued_at"`
	ExpiresAt     string   `json:"expires_at"`
	DaysRemaining int      `json:"days_remaining"`
	Message       string   `json:"message"`
	Error         string   `json:"error,omitempty"`
	Help          string   `json:"help,omitempty"`
}

// Register attempts to auto-register the agent using an enrollment token
func (lc *LicenseClient) Register(enrollmentToken string) (*RegisterResponse, error) {
	hostname, _ := os.Hostname()
	req := RegisterRequest{
		MachineID:       lc.MachineID,
		EnrollmentToken: enrollmentToken,
		Hostname:        hostname,
		Platform:        fmt.Sprintf("%s-%s", runtime.GOOS, runtime.GOARCH),
		AgentVersion:    AgentVersion,
	}

	body, resp, err := lc.SendRequest(http.MethodPost, lc.ServerURL+"/license/register", req)
	if err != nil {
		return nil, fmt.Errorf("registration failed: %w", err)
	}

	var registerResp RegisterResponse
	if err := json.Unmarshal(body, &registerResp); err != nil {
		return nil, err
	}

	if resp.StatusCode >= 400 {
		return &registerResp, fmt.Errorf("registration failed: %s", registerResp.Error)
	}

	return &registerResp, nil
}

// Validate sends license validation request to telemetry server
func (lc *LicenseClient) Validate() (*ValidateResponse, error) {
	signature, err := lc.signData([]byte(lc.MachineID))
	if err != nil {
		return nil, fmt.Errorf("failed to sign license request: %w", err)
	}

	req := ValidateRequest{
		MachineID:      lc.MachineID,
		Signature:      signature,
		Version:        AgentVersion,
		InstallationID: lc.MachineID,
	}

	body, resp, err := lc.SendRequest(http.MethodPost, lc.ServerURL+"/license/validate", req)
	if err != nil {
		return nil, fmt.Errorf("license server unreachable: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("license server returned status: %d", resp.StatusCode)
	}

	var validateResp ValidateResponse
	if err := json.Unmarshal(body, &validateResp); err != nil {
		return nil, err
	}

	return &validateResp, nil
}

// SendHeartbeat sends periodic heartbeat to maintain license validity
func (lc *LicenseClient) SendHeartbeat(statusData map[string]interface{}) (*HeartbeatResponse, error) {
	signature, err := lc.signData([]byte(lc.MachineID))
	if err != nil {
		return nil, err
	}

	req := HeartbeatRequest{
		MachineID:  lc.MachineID,
		Signature:  signature,
		StatusData: statusData,
	}

	body, _, err := lc.SendRequest(http.MethodPost, lc.ServerURL+"/license/heartbeat", req)
	if err != nil {
		return nil, fmt.Errorf("heartbeat failed: %w", err)
	}

	var heartbeatResp HeartbeatResponse
	if err := json.Unmarshal(body, &heartbeatResp); err != nil {
		return nil, err
	}

	return &heartbeatResp, nil
}

var packageStartTime = time.Now()

// StartHeartbeatDaemon starts background heartbeat (every hour)
func (lc *LicenseClient) StartHeartbeatDaemon(stopCh chan struct{}) {
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				statusData := map[string]interface{}{
					"uptime_hours": time.Since(packageStartTime).Hours(),
					"go_version":   runtime.Version(),
				}
				_, _ = lc.SendHeartbeat(statusData)
			case <-stopCh:
				return
			}
		}
	}()
}

// signData signs data with ML-DSA-65 private key
func (lc *LicenseClient) signData(data []byte) (string, error) {
	if lc.PrivateKey == "" {
		return "", fmt.Errorf("no private key")
	}

	keyBytes, err := hex.DecodeString(lc.PrivateKey)
	if err != nil {
		return "", err
	}

	if len(keyBytes) != mldsa65.PrivateKeySize {
		return "", fmt.Errorf("invalid key size")
	}

	var keyBuf [mldsa65.PrivateKeySize]byte
	copy(keyBuf[:], keyBytes)

	var sk mldsa65.PrivateKey
	sk.Unpack(&keyBuf)

	signature := make([]byte, mldsa65.SignatureSize)
	mldsa65.SignTo(&sk, data, nil, false, signature)

	return hex.EncodeToString(signature), nil
}
