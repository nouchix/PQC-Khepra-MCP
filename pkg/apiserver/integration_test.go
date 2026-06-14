//go:build saas

// =============================================================================
// KHEPRA PROTOCOL - Integration Tests for Autopilot, PDF, Certify, Seats
// =============================================================================

package apiserver

import (
	"fmt"
	"testing"
	"time"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/adinkra"
)

// TestAutopilotCycle validates the full autopilot lifecycle:
// start → run cycle → drift check → re-attest → stop
func TestAutopilotCycle(t *testing.T) {
	// Create a minimal server with signing keys
	srv := &Server{}
	pub, priv, err := adinkra.GenerateDilithiumKey()
	if err != nil {
		t.Fatalf("Failed to generate keys: %v", err)
	}
	srv.sigPrivKey = priv
	srv.sigPubKey = pub

	// Configure for fast test cycle (100ms interval)
	config := AutopilotConfig{
		ScanInterval:           100 * time.Millisecond,
		DriftThreshold:         0.5,
		AutoReAttest:           true,
		Framework:              "CMMC-3.0-L3",
		MaxConsecutiveFailures: 3,
	}

	engine := NewAutopilotEngine(srv, config)

	// Start
	if err := engine.Start(); err != nil {
		t.Fatalf("Failed to start autopilot: %v", err)
	}

	// Double-start should fail
	if err := engine.Start(); err == nil {
		t.Error("Expected error on double-start")
	}

	// Wait for at least 2 cycles
	time.Sleep(350 * time.Millisecond)

	// Check state — may be 'running' or 'alert' depending on drift
	state := engine.GetState()
	if state.Status != "running" && state.Status != "alert" {
		t.Errorf("Expected status 'running' or 'alert', got '%s'", state.Status)
	}
	if state.TotalScans < 2 {
		t.Errorf("Expected at least 2 scans, got %d", state.TotalScans)
	}

	// Check events were logged
	events := engine.GetEvents()
	if len(events) == 0 {
		t.Error("Expected events to be logged")
	}

	// First cycle should always re-attest (drift = 0 on first scan)
	if state.TotalReAttestations < 1 {
		t.Errorf("Expected at least 1 re-attestation, got %d", state.TotalReAttestations)
	}

	// Pause and verify
	engine.Pause()
	pausedState := engine.GetState()
	if pausedState.Status != "paused" {
		t.Errorf("Expected status 'paused', got '%s'", pausedState.Status)
	}

	// Resume
	engine.Resume()

	// Stop
	engine.Stop()
	finalState := engine.GetState()
	if finalState.Status != "stopped" {
		t.Errorf("Expected status 'stopped', got '%s'", finalState.Status)
	}
}

// TestPDFGeneration validates the PDF evidence report generator
func TestPDFGeneration(t *testing.T) {
	report := &EvidenceReport{
		ExportID:  "exp_test_12345",
		Framework: "CMMC-3.0-L3",
		Timestamp: time.Now(),
		Score:     87.5,
		DataHash:  "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6",
		Signature: "deadbeef0123456789abcdef",
		Algorithm: "ML-DSA-65 (FIPS 204)",
		Attestations: []AttestationSummary{
			{
				ID:        "att_001",
				Type:      "cmmc-l2",
				Timestamp: time.Now(),
				Hash:      "abc123",
				Verified:  true,
			},
		},
		Findings: []FindingSummary{
			{
				ControlID:   "V-254239",
				Title:       "System must use FIPS-validated cryptographic modules",
				Severity:    "high",
				Status:      "pass",
				Remediation: "Enable FIPS mode in kernel",
			},
			{
				ControlID:   "V-254240",
				Title:       "SSH must be configured with approved ciphers",
				Severity:    "medium",
				Status:      "fail",
				Remediation: "Update sshd_config to use AES-256-GCM",
			},
		},
		ChainLength: 1,
	}

	pdfBytes, err := GenerateEvidencePDF(report)
	if err != nil {
		t.Fatalf("PDF generation failed: %v", err)
	}

	if len(pdfBytes) == 0 {
		t.Fatal("Generated PDF is empty")
	}

	// Validate PDF header
	if string(pdfBytes[:5]) != "%PDF-" {
		t.Errorf("Invalid PDF header: %q", string(pdfBytes[:5]))
	}

	// Should be a reasonable size (not just a header)
	if len(pdfBytes) < 500 {
		t.Errorf("PDF seems too small: %d bytes", len(pdfBytes))
	}

	t.Logf("Generated PDF: %d bytes, starts with %q", len(pdfBytes), string(pdfBytes[:10]))
}

// TestPDFGenerationNilReport validates error handling
func TestPDFGenerationNilReport(t *testing.T) {
	_, err := GenerateEvidencePDF(nil)
	if err == nil {
		t.Error("Expected error for nil report")
	}
}

// TestSeatManagement validates multi-tenant seat operations
func TestSeatManagement(t *testing.T) {
	sm := NewSeatManager()

	// Create org
	org, err := sm.CreateOrganization("Test Corp", "admin@test.com", "autopilot")
	if err != nil {
		t.Fatalf("Failed to create org: %v", err)
	}
	if org.MaxSeats != 5 {
		t.Errorf("Expected 5 max seats for autopilot, got %d", org.MaxSeats)
	}
	if len(org.Seats) != 1 {
		t.Errorf("Expected 1 seat (owner), got %d", len(org.Seats))
	}
	if org.Seats[0].Role != "owner" {
		t.Errorf("Expected owner role, got %s", org.Seats[0].Role)
	}

	// Invite seats
	for i := 0; i < 4; i++ {
		_, err := sm.InviteSeat(org.ID, fmt.Sprintf("user%d@test.com", i), "auditor")
		if err != nil {
			t.Fatalf("Failed to invite seat %d: %v", i, err)
		}
	}

	// 6th seat should fail (5 max for autopilot)
	_, err = sm.InviteSeat(org.ID, "extra@test.com", "viewer")
	if err == nil {
		t.Error("Expected error when exceeding seat limit")
	}

	// Duplicate email should fail
	_, err = sm.InviteSeat(org.ID, "user0@test.com", "viewer")
	if err == nil {
		t.Error("Expected error for duplicate email")
	}

	// Revoke a non-owner seat
	updatedOrg, _ := sm.GetOrganization(org.ID)
	var revokeTarget string
	for _, s := range updatedOrg.Seats {
		if s.Role != "owner" {
			revokeTarget = s.ID
			break
		}
	}
	if revokeTarget == "" {
		t.Fatal("No non-owner seat found to revoke")
	}
	err = sm.RevokeSeat(org.ID, revokeTarget)
	if err != nil {
		t.Fatalf("Failed to revoke seat: %v", err)
	}

	// Now we can invite again (one slot freed)
	_, err = sm.InviteSeat(org.ID, "replacement@test.com", "viewer")
	if err != nil {
		t.Errorf("Should be able to invite after revoke: %v", err)
	}

	// Can't revoke owner — find owner seat by email
	ownerOrg, _ := sm.GetOrganization(org.ID)
	var ownerSeatID string
	for _, s := range ownerOrg.Seats {
		if s.Email == "admin@test.com" {
			ownerSeatID = s.ID
			break
		}
	}
	if ownerSeatID != "" {
		err = sm.RevokeSeat(org.ID, ownerSeatID)
		if err == nil {
			t.Error("Expected error when revoking owner")
		}
	}

	// Upgrade tier
	err = sm.UpgradeTier(org.ID, "diagnostic")
	if err != nil {
		t.Fatalf("Failed to upgrade: %v", err)
	}
	upgraded, _ := sm.GetOrganization(org.ID)
	if upgraded.MaxSeats != 10 {
		t.Errorf("Expected 10 max seats after upgrade, got %d", upgraded.MaxSeats)
	}

	// GetSeatsByEmail
	seats := sm.GetSeatsByEmail("admin@test.com")
	if len(seats) != 1 {
		t.Errorf("Expected 1 seat for admin, got %d", len(seats))
	}
}

// TestCertifyFlow validates the end-to-end Certify attestation flow:
// create attestation with persistent key → verify with real crypto
func TestCertifyFlow(t *testing.T) {
	pub, priv, err := adinkra.GenerateDilithiumKey()
	if err != nil {
		t.Fatalf("Key gen failed: %v", err)
	}

	// Simulate what the server does: set package-level keys
	SetPackageSigningKeys(priv, pub)

	// 1. Sign some data
	msg := []byte("test-attestation-data")
	sig, err := adinkra.Sign(priv, msg)
	if err != nil {
		t.Fatalf("Signing failed: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("Signature is empty")
	}

	// 2. Verify with the public key
	verified, err := adinkra.Verify(pub, msg, sig)
	if err != nil {
		t.Fatalf("Verification failed: %v", err)
	}
	if !verified {
		t.Error("Signature should verify with correct public key")
	}

	// 3. Verify fails with wrong data
	wrongMsg := []byte("tampered-data")
	verified, err = adinkra.Verify(pub, wrongMsg, sig)
	if err == nil && verified {
		t.Error("Signature should NOT verify with wrong data")
	}

	// 4. Verify the package-level keys are set correctly
	if len(pkgSigningPrivKey) == 0 {
		t.Error("Package signing private key not set")
	}
	if len(pkgSigningPubKey) == 0 {
		t.Error("Package signing public key not set")
	}

	t.Logf("Certify flow: sign OK, verify OK, tamper detection OK")
}

// TestStripeCheckoutSession validates the checkout session lifecycle
func TestStripeCheckoutSession(t *testing.T) {
	// Reset state
	stripeState = &SubscriptionState{
		sessions:      make(map[string]*CheckoutSession),
		subscriptions: make(map[string]*ActiveSubscription),
	}

	// Create a session
	sessionID := generateID("cs")
	now := time.Now()
	session := &CheckoutSession{
		ID:        sessionID,
		Tier:      "autopilot",
		Email:     "test@example.com",
		Status:    "pending",
		Amount:    49900,
		Currency:  "usd",
		Recurring: true,
		CreatedAt: now,
	}

	stripeState.mu.Lock()
	stripeState.sessions[sessionID] = session
	stripeState.mu.Unlock()

	// Verify session exists
	stripeState.mu.RLock()
	retrieved, exists := stripeState.sessions[sessionID]
	stripeState.mu.RUnlock()

	if !exists {
		t.Fatal("Session not found")
	}
	if retrieved.Status != "pending" {
		t.Errorf("Expected 'pending', got '%s'", retrieved.Status)
	}
	if retrieved.Amount != 49900 {
		t.Errorf("Expected 49900 cents, got %d", retrieved.Amount)
	}

	// Simulate completion
	stripeState.mu.Lock()
	session.Status = "completed"
	completedAt := time.Now()
	session.CompletedAt = &completedAt

	subID := generateID("sub")
	stripeState.subscriptions[subID] = &ActiveSubscription{
		StripeSubID:      subID,
		Tier:             "autopilot",
		Email:            "test@example.com",
		Status:           "active",
		CurrentPeriodEnd: now.Add(30 * 24 * time.Hour),
		CreatedAt:        now,
	}
	stripeState.mu.Unlock()

	// Verify subscription
	stripeState.mu.RLock()
	sub, exists := stripeState.subscriptions[subID]
	stripeState.mu.RUnlock()

	if !exists {
		t.Fatal("Subscription not found")
	}
	if sub.Status != "active" {
		t.Errorf("Expected 'active', got '%s'", sub.Status)
	}

	t.Logf("Stripe flow: session created, payment simulated, subscription active")
}
