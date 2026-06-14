// Integration tests for the NHI (Non-Human Identity) governance tracker.
// Tests validate end-to-end lifecycle: register, classify, revoke.
package nhi

import (
	"testing"
	"time"
)

func newTestRecord(id, owner, platform string, riskScore float64, scopes ...string) *NHIRecord {
	return &NHIRecord{
		ID:        id,
		Type:      NHITypeAPIKey,
		Owner:     owner,
		Platform:  platform,
		Scopes:    scopes,
		RiskScore: riskScore,
		LastUsed:  time.Now(),
		Managed:   true,
	}
}

// TestNHIRegisterAndRetrieve validates that a registered NHI record is
// retrievable and its fields are preserved exactly.
func TestNHIRegisterAndRetrieve(t *testing.T) {
	tracker := NewNHITracker()
	rec := newTestRecord("nhi-aws-001", "agt-ec2-scanner", "aws", 0.2, "s3:Read", "ec2:Describe")
	tracker.Register(rec)

	got := tracker.Get("nhi-aws-001")
	if got == nil {
		t.Fatal("Get returned nil for registered NHI")
	}
	if got.Owner != "agt-ec2-scanner" {
		t.Errorf("Owner mismatch: got %q", got.Owner)
	}
	if got.Platform != "aws" {
		t.Errorf("Platform mismatch: got %q", got.Platform)
	}
	if len(got.Scopes) != 2 {
		t.Errorf("Scopes length: got %d, want 2", len(got.Scopes))
	}
}

// TestNHIInventoryReturnsAllRecords verifies that Inventory returns every registered record.
func TestNHIInventoryReturnsAllRecords(t *testing.T) {
	tracker := NewNHITracker()
	for i := 0; i < 10; i++ {
		id := "nhi-" + string(rune('a'+i))
		tracker.Register(newTestRecord(id, "agt-x", "github", 0.1))
	}

	inventory, err := tracker.Inventory()
	if err != nil {
		t.Fatalf("Inventory error: %v", err)
	}
	if len(inventory) != 10 {
		t.Errorf("expected 10 records, got %d", len(inventory))
	}
}

// TestNHIIdentifyOrphans verifies that records with no owner or "unknown" owner
// are correctly classified as orphans.
func TestNHIIdentifyOrphans(t *testing.T) {
	tracker := NewNHITracker()
	tracker.Register(newTestRecord("nhi-orphan-1", "", "aws", 0.9))
	tracker.Register(newTestRecord("nhi-orphan-2", "unknown", "k8s", 0.8))
	tracker.Register(newTestRecord("nhi-owned", "agt-owned", "github", 0.1))

	orphans := tracker.IdentifyOrphans()
	if len(orphans) != 2 {
		t.Errorf("expected 2 orphans, got %d", len(orphans))
	}
	for _, o := range orphans {
		if o.ID == "nhi-owned" {
			t.Error("owned record incorrectly classified as orphan")
		}
	}
}

// TestNHIIdentifyExcessive validates detection of over-privileged or high-risk credentials.
func TestNHIIdentifyExcessive(t *testing.T) {
	tracker := NewNHITracker()
	// Excessive by scope count
	tracker.Register(newTestRecord("nhi-scope-heavy", "agt-1", "aws", 0.3,
		"s3:*", "ec2:*", "iam:*", "kms:*", "rds:*"))
	// Excessive by risk score
	tracker.Register(newTestRecord("nhi-high-risk", "agt-2", "slack", 0.95, "channels:read"))
	// Normal
	tracker.Register(newTestRecord("nhi-normal", "agt-3", "github", 0.1, "repo:read"))

	excessive := tracker.IdentifyExcessive(3, 0.8)
	if len(excessive) != 2 {
		t.Errorf("expected 2 excessive records, got %d", len(excessive))
	}
}

// TestNHIIdentifyExpired verifies that expired credentials are correctly flagged.
func TestNHIIdentifyExpired(t *testing.T) {
	tracker := NewNHITracker()

	past := time.Now().Add(-24 * time.Hour)
	future := time.Now().Add(30 * 24 * time.Hour)

	expiredRec := newTestRecord("nhi-expired", "agt-1", "okta", 0.5)
	expiredRec.ExpiresAt = &past
	tracker.Register(expiredRec)

	validRec := newTestRecord("nhi-valid", "agt-2", "okta", 0.2)
	validRec.ExpiresAt = &future
	tracker.Register(validRec)

	noExpiryRec := newTestRecord("nhi-no-expiry", "agt-3", "okta", 0.1)
	tracker.Register(noExpiryRec)

	expired := tracker.IdentifyExpired()
	if len(expired) != 1 {
		t.Errorf("expected 1 expired record, got %d", len(expired))
	}
	if expired[0].ID != "nhi-expired" {
		t.Errorf("wrong record identified as expired: %q", expired[0].ID)
	}
}

// TestNHIRevokeRemovesRecord verifies that RevokeNHI removes the record from the tracker.
func TestNHIRevokeRemovesRecord(t *testing.T) {
	tracker := NewNHITracker()
	tracker.Register(newTestRecord("nhi-to-revoke", "agt-1", "aws", 0.6))

	if err := tracker.RevokeNHI("nhi-to-revoke"); err != nil {
		t.Fatalf("RevokeNHI error: %v", err)
	}
	if got := tracker.Get("nhi-to-revoke"); got != nil {
		t.Error("record still present after revocation")
	}
}

// TestNHIRevokeNonExistentReturnsError verifies that revoking an unknown NHI
// returns a non-nil error (not a silent success).
func TestNHIRevokeNonExistentReturnsError(t *testing.T) {
	tracker := NewNHITracker()
	if err := tracker.RevokeNHI("nhi-does-not-exist"); err == nil {
		t.Error("expected error when revoking non-existent NHI, got nil")
	}
}

// TestNHIRevokeFuncCalled verifies that the RevokeFunc hook is invoked
// with the correct ID and platform when a credential is revoked.
func TestNHIRevokeFuncCalled(t *testing.T) {
	tracker := NewNHITracker()
	tracker.Register(newTestRecord("nhi-hook", "agt-1", "snowflake", 0.4))

	var calledID, calledPlatform string
	tracker.RevokeFunc = func(id, platform string) error {
		calledID = id
		calledPlatform = platform
		return nil
	}

	if err := tracker.RevokeNHI("nhi-hook"); err != nil {
		t.Fatalf("RevokeNHI error: %v", err)
	}
	if calledID != "nhi-hook" {
		t.Errorf("RevokeFunc called with wrong ID: %q", calledID)
	}
	if calledPlatform != "snowflake" {
		t.Errorf("RevokeFunc called with wrong platform: %q", calledPlatform)
	}
}

// TestNHIDaysUntilExpiry verifies correct days-to-expiry calculation.
func TestNHIDaysUntilExpiry(t *testing.T) {
	rec := newTestRecord("nhi-exp-calc", "agt-1", "aws", 0.1)

	// No expiry
	if rec.DaysUntilExpiry() != -1 {
		t.Error("expected -1 for no expiry")
	}

	// 30 days from now
	future := time.Now().Add(30 * 24 * time.Hour)
	rec.ExpiresAt = &future
	days := rec.DaysUntilExpiry()
	if days < 29 || days > 31 {
		t.Errorf("expected ~30 days until expiry, got %d", days)
	}
}
