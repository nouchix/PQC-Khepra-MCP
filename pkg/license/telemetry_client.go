package license

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// TelemetryClient manages communication with the Cloudflare telemetry server
// for license validation, heartbeats, and enrollment
type TelemetryClient struct {
	serverURL     string
	httpClient    *http.Client
	enrollmentKey string
	timeout       time.Duration
}

// TelemetryConfig holds telemetry server configuration
type TelemetryConfig struct {
	ServerURL     string        // e.g., "https://telemetry.souhimbou.org"
	EnrollmentKey string        // Enrollment token for auto-registration
	Timeout       time.Duration // HTTP timeout (default: 10s)
	MaxRetries    int           // Retry count for failed requests
}

// LicenseValidateRequest sent to telemetry server
type LicenseValidateRequest struct {
	MachineID      string `json:"machine_id"`
	Signature      string `json:"signature"`       // Dilithium3 signature
	Version        string `json:"version"`         // Client version
	InstallationID string `json:"installation_id"` // Unique install ID
}

// LicenseValidateResponse from telemetry server
type LicenseValidateResponse struct {
	Valid       bool      `json:"valid"`
	LicenseID   string    `json:"license_id,omitempty"`
	Tier        string    `json:"tier,omitempty"`
	ExpiresAt   time.Time `json:"expires_at,omitempty"`
	Error       string    `json:"error,omitempty"`
	Message     string    `json:"message,omitempty"`
	Revoked     bool      `json:"revoked,omitempty"`
	GracePeriod int       `json:"grace_period_days,omitempty"` // Days remaining before offline
}

// LicenseHeartbeatRequest sent to telemetry server
type LicenseHeartbeatRequest struct {
	LicenseID      string `json:"license_id"`
	MachineID      string `json:"machine_id"`
	Signature      string `json:"signature"`
	LastCheck      string `json:"last_check"` // ISO8601 timestamp
	NodesCreated   int    `json:"nodes_created"`
	NodeQuotaUsed  int    `json:"node_quota_used"`
	OfflineSince   string `json:"offline_since,omitempty"` // ISO8601, if applicable
	LicenseVersion int    `json:"license_version"`
}

// LicenseHeartbeatResponse from telemetry server
type LicenseHeartbeatResponse struct {
	OK             bool   `json:"ok"`
	NextCheckAfter string `json:"next_check_after"` // Duration as string
	Error          string `json:"error,omitempty"`
	Revoked        bool   `json:"revoked,omitempty"`
}

// EnrollmentTokenRequest for auto-registration
type EnrollmentTokenRequest struct {
	EnrollmentToken string `json:"enrollment_token"`
	MachineID       string `json:"machine_id"`
	CustomerName    string `json:"customer_name"`
	Tier            string `json:"tier"`
}

// EnrollmentTokenResponse from telemetry server
type EnrollmentTokenResponse struct {
	LicenseID string    `json:"license_id,omitempty"`
	Tier      string    `json:"tier,omitempty"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
	Error     string    `json:"error,omitempty"`
	Message   string    `json:"message,omitempty"`
}

// NewTelemetryClient creates a new telemetry client with default configuration
func NewTelemetryClient(config TelemetryConfig) *TelemetryClient {
	if config.ServerURL == "" {
		config.ServerURL = os.Getenv("ADINKHEPRA_TELEMETRY_SERVER")
		if config.ServerURL == "" {
			config.ServerURL = "https://telemetry.souhimbou.org"
		}
	}

	if config.EnrollmentKey == "" {
		config.EnrollmentKey = os.Getenv("KHEPRA_ENROLLMENT_TOKEN")
	}

	if config.Timeout == 0 {
		config.Timeout = 10 * time.Second
	}

	if config.MaxRetries == 0 {
		config.MaxRetries = 3
	}

	return &TelemetryClient{
		serverURL:     config.ServerURL,
		enrollmentKey: config.EnrollmentKey,
		timeout:       config.Timeout,
		httpClient: &http.Client{
			Timeout: config.Timeout,
		},
	}
}

// ValidateLicense calls the telemetry server to validate a license
func (tc *TelemetryClient) ValidateLicense(machineID, signature, version, installationID string) (*LicenseValidateResponse, error) {
	req := &LicenseValidateRequest{
		MachineID:      machineID,
		Signature:      signature,
		Version:        version,
		InstallationID: installationID,
	}

	var resp LicenseValidateResponse
	if err := tc.post("/license/validate", req, &resp); err != nil {
		return nil, err
	}

	return &resp, nil
}

// HeartbeatLicense sends a heartbeat to the telemetry server
func (tc *TelemetryClient) HeartbeatLicense(licenseID, machineID, signature string, nodesCreated, nodeQuotaUsed int) (*LicenseHeartbeatResponse, error) {
	req := &LicenseHeartbeatRequest{
		LicenseID:      licenseID,
		MachineID:      machineID,
		Signature:      signature,
		LastCheck:      time.Now().UTC().Format(time.RFC3339),
		NodesCreated:   nodesCreated,
		NodeQuotaUsed:  nodeQuotaUsed,
		LicenseVersion: 1,
	}

	var resp LicenseHeartbeatResponse
	if err := tc.post("/license/heartbeat", req, &resp); err != nil {
		return nil, err
	}

	return &resp, nil
}

// RegisterWithEnrollmentToken uses an enrollment token for auto-registration
func (tc *TelemetryClient) RegisterWithEnrollmentToken(machineID, customerName, tier string) (*EnrollmentTokenResponse, error) {
	req := &EnrollmentTokenRequest{
		EnrollmentToken: tc.enrollmentKey,
		MachineID:       machineID,
		CustomerName:    customerName,
		Tier:            tier,
	}

	var resp EnrollmentTokenResponse
	if err := tc.post("/license/register", req, &resp); err != nil {
		return nil, err
	}

	return &resp, nil
}

// post sends a POST request to the telemetry server with retry logic
func (tc *TelemetryClient) post(endpoint string, reqBody interface{}, respBody interface{}) error {
	url := tc.serverURL + endpoint

	// Marshal request
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	// Retry logic
	var lastErr error
	maxAttempts := int(tc.timeout.Seconds()/3) + 1
	if maxAttempts < 1 {
		maxAttempts = 1
	}
	for attempt := 0; attempt < maxAttempts; attempt++ {
		resp, err := tc.httpClient.Post(url, "application/json", bytes.NewReader(bodyBytes))
		if err != nil {
			lastErr = err
			time.Sleep(time.Duration((attempt+1)*100) * time.Millisecond)
			continue
		}
		defer resp.Body.Close()

		// Read response
		respBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			lastErr = fmt.Errorf("failed to read response: %w", err)
			time.Sleep(time.Duration((attempt+1)*100) * time.Millisecond)
			continue
		}

		// Parse response
		if err := json.Unmarshal(respBytes, respBody); err != nil {
			lastErr = fmt.Errorf("failed to unmarshal response: %w", err)
			time.Sleep(time.Duration((attempt+1)*100) * time.Millisecond)
			continue
		}

		// Success
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil
		}

		// Non-transient error
		if resp.StatusCode >= 400 && resp.StatusCode < 500 {
			return fmt.Errorf("server returned %d: %s", resp.StatusCode, string(respBytes))
		}

		lastErr = fmt.Errorf("server returned %d", resp.StatusCode)
	}

	return fmt.Errorf("failed after retries: %w", lastErr)
}

// HealthCheck verifies connectivity to the telemetry server
func (tc *TelemetryClient) HealthCheck() (bool, error) {
	resp, err := tc.httpClient.Get(tc.serverURL + "/health")
	if err != nil {
		return false, fmt.Errorf("failed to reach telemetry server: %w", err)
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK, nil
}

// GetServerURL returns the configured telemetry server URL
func (tc *TelemetryClient) GetServerURL() string {
	return tc.serverURL
}

// SetServerURL updates the telemetry server URL
func (tc *TelemetryClient) SetServerURL(url string) {
	tc.serverURL = url
}
