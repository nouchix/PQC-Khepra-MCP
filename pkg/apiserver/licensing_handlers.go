//go:build saas

package apiserver

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/license"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

const (
	msgLicenseIDRequired = "license_id parameter is required"

	// Tier shortcuts used by Stripe webhook handler.
	licenseRaTier        = license.TierRa
	licenseCommunityTier = license.TierKhepri
)

// Merkaba Egyptian Licensing System Handlers (Version 2)
// Integrates with Scarab/Motherboard API server (apiserver)
//
// These handlers provide REST endpoints for:
// - License information retrieval
// - Egyptian tier management (Khepri, Ra, Atum, Osiris)
// - Telemetry enrollment and heartbeats
// - License usage tracking
//
// Note: This version assumes the license Manager is already initialized
// and provides read-only operations. License creation is handled by the
// telemetry enrollment process.

// handleCreateLicense creates a new Egyptian tier license
// POST /api/v1/license/create
// Body: {"tier": "khepri|ra|atum|osiris", "customer": "...", "duration_days": 365}
func (s *Server) handleCreateLicense(c *gin.Context) {
	var req struct {
		Tier         string `json:"tier" binding:"required"`
		Customer     string `json:"customer" binding:"required"`
		DurationDays int    `json:"duration_days" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "invalid_request",
			Message: err.Error(),
			Code:    http.StatusBadRequest,
		})
		return
	}

	// Map tier string to EgyptianTier enum
	tierMap := map[string]license.EgyptianTier{
		"khepri": license.TierKhepri,
		"ra":     license.TierRa,
		"atum":   license.TierAtum,
		"osiris": license.TierOsiris,
	}

	tier, ok := tierMap[req.Tier]
	if !ok {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "invalid_tier",
			Message: fmt.Sprintf("Tier must be one of: khepri, ra, atum, osiris (got: %s)", req.Tier),
			Code:    http.StatusBadRequest,
		})
		return
	}

	// Generate license ID (e.g. atum-machineid)
	licenseID := string(tier) + "-" + uuid.New().String()[:8]

	// Create real license via manager
	lic, err := s.licMgr.CreateLicense(licenseID, tier, req.DurationDays)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "license_creation_failed",
			Message: err.Error(),
			Code:    http.StatusInternalServerError,
		})
		return
	}

	c.JSON(http.StatusCreated, lic)
}

// handleGetLicense retrieves a license by ID
// GET /api/v1/license/:license_id
func (s *Server) handleGetLicense(c *gin.Context) {
	licenseID := c.Param("license_id")
	if licenseID == "" {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "missing_license_id",
			Message: msgLicenseIDRequired,
			Code:    http.StatusBadRequest,
		})
		return
	}

	lic, err := s.licMgr.GetLicense(licenseID)
	if err != nil {
		c.JSON(http.StatusNotFound, ErrorResponse{
			Error:   "license_not_found",
			Message: err.Error(),
			Code:    http.StatusNotFound,
		})
		return
	}

	c.JSON(http.StatusOK, lic)
}

// handleUpgradeLicense upgrades a license to a higher tier
// POST /api/v1/license/:license_id/upgrade
// Body: {"new_tier": "ra|atum|osiris"}
func (s *Server) handleUpgradeLicense(c *gin.Context) {
	licenseID := c.Param("license_id")
	if licenseID == "" {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "missing_license_id",
			Message: msgLicenseIDRequired,
			Code:    http.StatusBadRequest,
		})
		return
	}

	var req struct {
		NewTier string `json:"new_tier" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "invalid_request",
			Message: err.Error(),
			Code:    http.StatusBadRequest,
		})
		return
	}

	// Map tier string
	tierMap := map[string]license.EgyptianTier{
		"khepri": license.TierKhepri,
		"ra":     license.TierRa,
		"atum":   license.TierAtum,
		"osiris": license.TierOsiris,
	}

	newTier, ok := tierMap[req.NewTier]
	if !ok {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "invalid_tier",
			Message: fmt.Sprintf("Invalid tier: %s", req.NewTier),
			Code:    http.StatusBadRequest,
		})
		return
	}

	// Perform upgrade via manager
	err := s.licMgr.UpgradeLicense(licenseID, newTier)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "upgrade_failed",
			Message: err.Error(),
			Code:    http.StatusInternalServerError,
		})
		return
	}

	// Return updated license
	lic, _ := s.licMgr.GetLicense(licenseID)
	c.JSON(http.StatusOK, lic)
}

// handleGetLicenseUsage returns usage stats for a license
// GET /api/v1/license/:license_id/usage
// OWASP API1:2023 - Broken Object Level Authorization mitigation
func (s *Server) handleGetLicenseUsage(c *gin.Context) {
	licenseID := c.Param("license_id")
	if licenseID == "" {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "missing_license_id",
			Message: msgLicenseIDRequired,
			Code:    http.StatusBadRequest,
		})
		return
	}

	// Authorization Check:
	// 1. Service accounts (admin) can access any license
	// 2. Regular users (API key/Machine ID) can only access licenses they own
	authType, _ := c.Get("auth_type")
	if authType != "service" {
		// For non-service auth, we verify the license belongs to this machine
		// In this implementation, we check if the requested license is the active one
		fullStatus := s.licMgr.GetFullStatus()
		if fullStatus.LicenseID != licenseID {
			c.JSON(http.StatusForbidden, ErrorResponse{
				Error:   "forbidden",
				Message: "Access to another user's license usage is prohibited",
				Code:    http.StatusForbidden,
			})
			return
		}
	}

	lic, err := s.licMgr.GetLicense(licenseID)
	if err != nil {
		c.JSON(http.StatusNotFound, ErrorResponse{
			Error:   "license_not_found",
			Message: err.Error(),
			Code:    http.StatusNotFound,
		})
		return
	}

	c.JSON(http.StatusOK, map[string]interface{}{
		"license_id":        lic.ID,
		"tier":              lic.Tier,
		"node_quota":        lic.NodeQuota,
		"nodes_created":     lic.NodeCount,
		"nodes_remaining":   lic.NodeQuota - lic.NodeCount,
		"percent_used":      fmt.Sprintf("%.1f%%", float64(lic.NodeCount)/float64(lic.NodeQuota)*100),
		"expires_at":        lic.ExpiresAt,
		"asset_criticality": license.TierConfigurations[lic.Tier].AssetCriticality,
	})
}

// handleListLicenses returns all licenses (admin endpoint)
// GET /api/v1/license/admin/list
func (s *Server) handleListLicenses(c *gin.Context) {
	licenses := s.licMgr.GetAllLicenses()

	c.JSON(http.StatusOK, map[string]interface{}{
		"count":    len(licenses),
		"licenses": licenses,
	})
}

// handleTelemetryEnroll enrolls machine with telemetry server using enrollment token
func (s *Server) handleTelemetryEnroll(c *gin.Context) {
	var req struct {
		EnrollmentToken string `json:"enrollment_token" binding:"required"`
		StripeSessionID string `json:"stripe_session_id,omitempty"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "invalid_request",
			Message: err.Error(),
			Code:    http.StatusBadRequest,
		})
		return
	}

	resp, err := s.licMgr.Register(req.EnrollmentToken)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "enrollment_failed",
			Message: err.Error(),
			Code:    http.StatusInternalServerError,
		})
		return
	}

	c.JSON(http.StatusOK, resp)
}

// handleTelemetryHeartbeat sends usage heartbeat to telemetry server
// POST /api/v1/license/telemetry/heartbeat
// Body: {"license_id": "...", "nodes_created": N, "node_quota_used": N}
func (s *Server) handleTelemetryHeartbeat(c *gin.Context) {
	var req struct {
		LicenseID     string `json:"license_id" binding:"required"`
		NodesCreated  int    `json:"nodes_created"`
		NodeQuotaUsed int    `json:"node_quota_used"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "invalid_request",
			Message: err.Error(),
			Code:    http.StatusBadRequest,
		})
		return
	}

	resp, err := s.licMgr.Heartbeat()
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "heartbeat_failed",
			Message: err.Error(),
			Code:    http.StatusInternalServerError,
		})
		return
	}

	c.JSON(http.StatusOK, resp)
}

// handleTelemetryStatus returns telemetry server connection status
func (s *Server) handleTelemetryStatus(c *gin.Context) {
	full := s.licMgr.GetFullStatus()

	status := "online"
	if !full.Valid && full.Error == "license_server_unreachable" {
		status = "offline"
	}

	c.JSON(http.StatusOK, map[string]interface{}{
		"status":             status,
		"telemetry_server":   "https://telemetry.souhimbou.org",
		"machine_id":         s.licMgr.GetMachineID(),
		"mode":               os.Getenv("KHEPRA_MODE"),
		"license_valid":      full.Valid,
		"license_tier":       full.LicenseTier,
		"supports_enroll":    true,
		"supports_validate":  true,
		"supports_heartbeat": true,
	})
}

// handleStripeWebhook processes Stripe webhook events to activate / revoke licenses.
//
// Route: POST /api/v1/stripe/webhook  (public — no API-key auth, verified by HMAC)
//
// Supported events:
//   - checkout.session.completed  → activate license for machine_id in metadata
//   - customer.subscription.deleted → revoke license for that machine_id
//
// Security: raw body is read BEFORE gin parses JSON so the Stripe-Signature
// HMAC can be verified against STRIPE_WEBHOOK_SECRET.  Any event that fails
// verification is rejected with 400.
func (s *Server) handleStripeWebhook(c *gin.Context) {
	const maxBodyBytes = int64(65536)

	webhookSecret := os.Getenv("STRIPE_WEBHOOK_SECRET")
	if webhookSecret == "" {
		c.JSON(http.StatusInternalServerError, ErrorResponse{
			Error:   "webhook_misconfigured",
			Message: "STRIPE_WEBHOOK_SECRET is not set on the server.",
			Code:    http.StatusInternalServerError,
		})
		return
	}

	// Read raw body — must happen before any c.Bind* calls.
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBodyBytes)
	payload, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "body_read_error",
			Message: "Could not read request body.",
			Code:    http.StatusBadRequest,
		})
		return
	}

	// Verify HMAC signature — rejects any spoofed webhook.
	sigHeader := c.GetHeader("Stripe-Signature")
	if err := verifyStripeSignature(payload, sigHeader, webhookSecret); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "invalid_signature",
			Message: "Stripe webhook signature verification failed.",
			Code:    http.StatusBadRequest,
		})
		return
	}

	// Parse the minimal event envelope.
	var event stripeWebhookEvent
	if err := json.Unmarshal(payload, &event); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "parse_error",
			Message: "Could not parse Stripe event payload.",
			Code:    http.StatusBadRequest,
		})
		return
	}

	switch event.Type {
	case "checkout.session.completed":
		s.handleCheckoutCompleted(event)
	case "customer.subscription.deleted":
		s.handleSubscriptionDeleted(event)
	default:
		// Acknowledge unhandled events silently — don't return 4xx (causes Stripe retries).
	}

	c.JSON(http.StatusOK, gin.H{"received": true})
}

// handleCheckoutCompleted activates a Ra-tier license for the machine_id in
// the checkout session metadata and broadcasts the activation over WebSocket.
func (s *Server) handleCheckoutCompleted(event stripeWebhookEvent) {
	machineID := event.Data.Object.ClientReferenceID
	if machineID == "" {
		machineID = event.Data.Object.Metadata["machine_id"]
	}
	if machineID == "" {
		// No machine ID — log and ack (avoid Stripe retry storm).
		fmt.Printf("[STRIPE] checkout.session.completed received but no machine_id in metadata\n")
		return
	}

	// Activate a Ra-tier (Hunter) 365-day license for this machine.
	licenseID := "ra-" + machineID[:min(8, len(machineID))]
	if _, err := s.licMgr.CreateLicense(licenseID, licenseRaTier, 365); err != nil {
		fmt.Printf("[STRIPE] license activation failed for machine %s: %v\n", machineID, err)
		// Still return 200 — Stripe will not retry; log for manual recovery.
	} else {
		fmt.Printf("[STRIPE] License activated: %s → machine %s\n", licenseID, machineID)
	}

	// Broadcast activation over WebSocket so the CLI poll loop sees it.
	if s.wsHub != nil {
		s.wsHub.BroadcastScanUpdate(map[string]interface{}{
			"type":       "license_activated",
			"machine_id": machineID,
			"license_id": licenseID,
			"tier":       "ra",
		})
	}
}

// handleSubscriptionDeleted revokes a license when a Stripe subscription ends.
func (s *Server) handleSubscriptionDeleted(event stripeWebhookEvent) {
	machineID := event.Data.Object.Metadata["machine_id"]
	if machineID != "" {
		licenseID := "ra-" + machineID[:min(8, len(machineID))]
		fmt.Printf("[STRIPE] Subscription cancelled — revoking license %s\n", licenseID)
		// Upgrade to community (lowest tier) effectively revokes Ra access.
		_ = s.licMgr.UpgradeLicense(licenseID, licenseCommunityTier)
	}
}

// stripeWebhookEvent is the minimal envelope parsed from a Stripe webhook body.
type stripeWebhookEvent struct {
	ID   string `json:"id"`
	Type string `json:"type"`
	Data struct {
		Object struct {
			ClientReferenceID string            `json:"client_reference_id"`
			Metadata          map[string]string `json:"metadata"`
		} `json:"object"`
	} `json:"data"`
}

// verifyStripeSignature verifies the Stripe-Signature header HMAC.
// Stripe signs the raw payload with HMAC-SHA256 using the webhook secret.
// Format: "t=<timestamp>,v1=<sig>[,v1=<sig>...]"
func verifyStripeSignature(payload []byte, header, secret string) error {
	if header == "" {
		return fmt.Errorf("missing Stripe-Signature header")
	}

	var timestamp string
	var signatures []string
	for _, part := range strings.Split(header, ",") {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "t":
			timestamp = kv[1]
		case "v1":
			signatures = append(signatures, kv[1])
		}
	}
	if timestamp == "" || len(signatures) == 0 {
		return fmt.Errorf("malformed Stripe-Signature header")
	}

	// Reject timestamps older than 5 minutes (replay attack prevention).
	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil || time.Now().Unix()-ts > 300 {
		return fmt.Errorf("webhook timestamp too old or invalid")
	}

	signed := timestamp + "." + string(payload)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signed)) //nolint:errcheck
	expected := hex.EncodeToString(mac.Sum(nil))

	for _, sig := range signatures {
		if hmac.Equal([]byte(sig), []byte(expected)) {
			return nil
		}
	}
	return fmt.Errorf("signature mismatch")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}


// handleRevokeLicense marks a license as revoked following a Stripe subscription cancellation.
// POST /api/v1/license/revoke
// Body: {"stripe_event_id": "...", "reason": "..."}
//
// Internal-only: accepts requests from localhost or a matching ASAF_WEBHOOK_SECRET header.
// Registered on the public (unauthenticated) route group because the webhook service
// has no Bearer credentials — it calls our own API on loopback.
func (s *Server) handleRevokeLicense(c *gin.Context) {
	// Internal-only guard: localhost IP or shared webhook secret.
	webhookSecret := os.Getenv("ASAF_WEBHOOK_SECRET")
	clientIP := c.ClientIP()
	isLocalhost := clientIP == "127.0.0.1" || clientIP == "::1"
	authorized := isLocalhost ||
		(webhookSecret != "" && c.GetHeader("X-ASAF-Webhook-Secret") == webhookSecret)
	if !authorized {
		c.JSON(http.StatusForbidden, ErrorResponse{
			Error:   "forbidden",
			Message: "License revocation is restricted to internal services",
			Code:    http.StatusForbidden,
		})
		return
	}

	var req struct {
		StripeEventID string `json:"stripe_event_id"`
		Reason        string `json:"reason"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{
			Error:   "invalid_request",
			Message: err.Error(),
			Code:    http.StatusBadRequest,
		})
		return
	}

	// Mark license invalid in-memory (survives until next restart / re-validate).
	if s.licMgr != nil {
		if err := s.licMgr.RevokeLicense(req.StripeEventID, req.Reason); err != nil {
			log.Printf("[license] revocation warning: %v", err)
		}
	}

	// Write an immutable DAG node as the audit record of this revocation.
	if s.dagStore != nil {
		nodeID := "revoke-" + uuid.New().String()
		_ = s.dagStore.Add(nodeID, "license_revocation", []string{}, map[string]string{
			"stripe_event_id": req.StripeEventID,
			"reason":          req.Reason,
			"revoked_at":      time.Now().UTC().Format(time.RFC3339),
		})
	}

	log.Printf("[license] revoked via stripe_event=%s reason=%s caller=%s",
		req.StripeEventID, req.Reason, clientIP)

	c.JSON(http.StatusOK, gin.H{
		"status":  "revoked",
		"reason":  req.Reason,
		"message": "License access revoked. Active sessions will expire on next validation.",
	})
}
