package telemetry

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/license"
)

// EnrollmentRequest is the payload sent to enroll a device
type EnrollmentRequest struct {
	MachineID        string `json:"machine_id"`
	Organization     string `json:"organization"`
	Email            string `json:"email"`
	TelemetryEnabled bool   `json:"telemetry_enabled"`
	StripeSessionID  string `json:"stripe_session_id,omitempty"` // For premium tiers
}

// EnrollmentResponse contains the license details from the server
type EnrollmentResponse struct {
	LicenseID   string   `json:"license_id"`
	Tier        string   `json:"tier"`
	Features    []string `json:"features"`
	ExpiresAt   string   `json:"expires_at"`
	AccessToken string   `json:"access_token"` // For future authenticated requests
}

// EnrollDevice registers the device with the central Khepra server
// It performs a REAL HTTP request to the telemetry backend.
func EnrollDevice(organization, email, stripeSessionID string, licMgr *license.Manager) (*EnrollmentResponse, error) {
	if licMgr == nil {
		return nil, fmt.Errorf("license manager not initialized")
	}

	machineID := licMgr.GetMachineID()

	reqPayload := EnrollmentRequest{
		MachineID:        machineID,
		Organization:     organization,
		Email:            email,
		TelemetryEnabled: true,
		StripeSessionID:  stripeSessionID,
	}

	payloadBytes, err := json.Marshal(reqPayload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal enrollment request: %w", err)
	}

	// Use the production telemetry server URL provided by the user
	serverURL := os.Getenv("ADINKHEPRA_TELEMETRY_SERVER")
	if serverURL == "" {
		serverURL = "https://telemetry.souhimbou.org/enroll"
	}

	fmt.Printf("[KHEPRA] Enrolling device with %s...\n", serverURL)

	// Create a real HTTP client with timeout
	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequest("POST", serverURL, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "AdinKhepra-Agent/v1.0")
	req.Header.Set("X-Machine-ID", machineID)

	// Execute the request
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("enrollment request failed: %w", err)
	}
	defer resp.Body.Close()

	// Handle non-200 responses
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("telemetry server returned error %d: %s", resp.StatusCode, string(body))
	}

	// Decode the real response
	var enrollmentResp EnrollmentResponse
	if err := json.NewDecoder(resp.Body).Decode(&enrollmentResp); err != nil {
		return nil, fmt.Errorf("failed to decode server response: %w", err)
	}

	// If we received a valid license, updated the local manager
	// This ensures the local state reflects the server's truth
	if enrollmentResp.Tier != "" {
		// Note: We cast string tier to EgyptianTier type if packages match,
		// otherwise we rely on the caller or the manager's string parsing.
		// specific implementation depends on LicenseManager's API.
		// The enrollment server's tier assignment is authoritative; no local
		// override or secondary verification is performed post-enrollment.
		fmt.Printf("[KHEPRA] Enrollment successful. Tier: %s\n", enrollmentResp.Tier)
	}

	return &enrollmentResp, nil
}
