// Integration tests for the Agent Control Plane (ACP).
// Tests validate PQC credential issuance, validation, revocation, and rotation
// using real AdinKhepra cryptographic operations.
package acp

import (
	"testing"
	"time"
)

// =============================================================================
// Credential Issuance
// =============================================================================

// TestIssueCredentialReturnsValidCredential verifies that IssueCredential
// creates a credential with all required fields populated.
func TestIssueCredentialReturnsValidCredential(t *testing.T) {
	acp, err := NewAgentControlPlane()
	if err != nil {
		t.Fatalf("NewAgentControlPlane: %v", err)
	}

	cred, err := acp.IssueCredential("agt-001", "Eban",
		[]string{"aws:s3:ReadOnly", "k8s:pods:List"}, time.Hour)
	if err != nil {
		t.Fatalf("IssueCredential: %v", err)
	}

	if cred.ID == "" {
		t.Error("credential ID is empty")
	}
	if cred.AgentID != "agt-001" {
		t.Errorf("AgentID: got %q", cred.AgentID)
	}
	if cred.Symbol != "Eban" {
		t.Errorf("Symbol: got %q", cred.Symbol)
	}
	if len(cred.PublicKey) == 0 {
		t.Error("PublicKey is empty")
	}
	if cred.Token == nil {
		t.Error("ZeroTrustToken is nil")
	}
	if len(cred.Scopes) != 2 {
		t.Errorf("Scopes: got %d, want 2", len(cred.Scopes))
	}
	if cred.ExpiresAt.Before(time.Now()) {
		t.Error("ExpiresAt is in the past")
	}
	if cred.DAGVertex == "" {
		t.Error("DAGVertex reference is empty — issuance not recorded in DAG")
	}
}

// TestIssueCredentialIsRecordedInDAG verifies that each credential issuance
// creates a unique DAG vertex (cryptographic audit trail).
func TestIssueCredentialIsRecordedInDAG(t *testing.T) {
	acp, err := NewAgentControlPlane()
	if err != nil {
		t.Fatalf("NewAgentControlPlane: %v", err)
	}

	cred1, _ := acp.IssueCredential("agt-001", "Eban", nil, time.Hour)
	cred2, _ := acp.IssueCredential("agt-002", "Fawohodie", nil, time.Hour)

	if cred1.DAGVertex == cred2.DAGVertex {
		t.Error("two distinct issuances share the same DAG vertex — audit integrity broken")
	}
}

// TestIssueCredentialUnknownSymbolUsesDefault verifies graceful handling
// of an unrecognized Adinkra symbol (should not panic).
func TestIssueCredentialUnknownSymbolUsesDefault(t *testing.T) {
	acp, err := NewAgentControlPlane()
	if err != nil {
		t.Fatalf("NewAgentControlPlane: %v", err)
	}
	_, err = acp.IssueCredential("agt-001", "UnknownSymbol", nil, time.Hour)
	// Should either succeed with a fallback or return a clear error — must not panic
	if err != nil {
		t.Logf("IssueCredential with unknown symbol returned error (acceptable): %v", err)
	}
}

// =============================================================================
// Credential Validation
// =============================================================================

// TestValidateCredentialAcceptsValidCredential verifies that a freshly
// issued credential passes validation.
func TestValidateCredentialAcceptsValidCredential(t *testing.T) {
	acp, err := NewAgentControlPlane()
	if err != nil {
		t.Fatalf("NewAgentControlPlane: %v", err)
	}
	cred, err := acp.IssueCredential("agt-valid", "Eban", []string{"read"}, time.Hour)
	if err != nil {
		t.Fatalf("IssueCredential: %v", err)
	}

	if err := acp.ValidateCredential(cred); err != nil {
		t.Errorf("ValidateCredential failed for valid credential: %v", err)
	}
}

// TestValidateCredentialRejectsExpired verifies that an expired credential
// fails validation.
func TestValidateCredentialRejectsExpired(t *testing.T) {
	acp, err := NewAgentControlPlane()
	if err != nil {
		t.Fatalf("NewAgentControlPlane: %v", err)
	}
	cred, _ := acp.IssueCredential("agt-exp", "Eban", nil, time.Hour)

	// Force expiry to the past
	cred.ExpiresAt = time.Now().Add(-1 * time.Second)

	if err := acp.ValidateCredential(cred); err == nil {
		t.Error("expected validation failure for expired credential")
	}
}

// TestValidateCredentialRejectsNilToken verifies that a credential with a
// nil ZeroTrustToken fails validation (tamper detection).
func TestValidateCredentialRejectsNilToken(t *testing.T) {
	acp, err := NewAgentControlPlane()
	if err != nil {
		t.Fatalf("NewAgentControlPlane: %v", err)
	}
	cred, _ := acp.IssueCredential("agt-nil-tok", "Eban", nil, time.Hour)
	cred.Token = nil

	if err := acp.ValidateCredential(cred); err == nil {
		t.Error("expected validation failure for nil ZeroTrustToken")
	}
}

// TestValidateCredentialRejectsEmptyPublicKey verifies that a credential
// with no public key fails validation.
func TestValidateCredentialRejectsEmptyPublicKey(t *testing.T) {
	acp, err := NewAgentControlPlane()
	if err != nil {
		t.Fatalf("NewAgentControlPlane: %v", err)
	}
	cred, _ := acp.IssueCredential("agt-no-pk", "Eban", nil, time.Hour)
	cred.PublicKey = nil

	if err := acp.ValidateCredential(cred); err == nil {
		t.Error("expected validation failure for empty public key")
	}
}

// =============================================================================
// Credential Revocation
// =============================================================================

// TestRevokeCredentialPreventsValidation verifies that after revocation,
// the credential no longer passes validation.
func TestRevokeCredentialPreventsValidation(t *testing.T) {
	acp, err := NewAgentControlPlane()
	if err != nil {
		t.Fatalf("NewAgentControlPlane: %v", err)
	}
	cred, _ := acp.IssueCredential("agt-revoke", "Fawohodie", []string{"admin"}, time.Hour)

	if err := acp.RevokeCredential(cred.ID); err != nil {
		t.Fatalf("RevokeCredential: %v", err)
	}

	// Credential should now be invalid
	if err := acp.ValidateCredential(cred); err == nil {
		t.Error("revoked credential should fail validation")
	}
}

// TestRevokeCredentialNonExistentReturnsError verifies that attempting to
// revoke an unknown ID returns an error.
func TestRevokeCredentialNonExistentReturnsError(t *testing.T) {
	acp, err := NewAgentControlPlane()
	if err != nil {
		t.Fatalf("NewAgentControlPlane: %v", err)
	}
	if err := acp.RevokeCredential("nhi-does-not-exist"); err == nil {
		t.Error("expected error when revoking non-existent credential")
	}
}

// TestRevokeCredentialIsAuditedInDAG verifies that revocation creates
// a new DAG vertex (the revocation action is cryptographically recorded).
func TestRevokeCredentialIsAuditedInDAG(t *testing.T) {
	acp, err := NewAgentControlPlane()
	if err != nil {
		t.Fatalf("NewAgentControlPlane: %v", err)
	}
	cred, _ := acp.IssueCredential("agt-audit-revoke", "Fawohodie", nil, time.Hour)
	issuanceVertex := cred.DAGVertex

	// Revoke
	_ = acp.RevokeCredential(cred.ID)

	// The DAG should have more vertices than just the issuance
	allVertices := acp.dag.All()
	if len(allVertices) < 2 {
		t.Errorf("expected at least 2 DAG vertices (issue + revoke), got %d", len(allVertices))
	}

	// The issuance vertex must still exist (immutable audit trail)
	found := false
	for _, v := range allVertices {
		if v.ID == issuanceVertex {
			found = true
			break
		}
	}
	if !found {
		t.Error("issuance DAG vertex removed — audit trail tampered")
	}
}

// =============================================================================
// Credential Rotation
// =============================================================================

// TestRotateCredentialIssuedNewCredential verifies that rotation produces
// a new credential with a different ID and new public key.
func TestRotateCredentialIssuedNewCredential(t *testing.T) {
	acp, err := NewAgentControlPlane()
	if err != nil {
		t.Fatalf("NewAgentControlPlane: %v", err)
	}
	original, _ := acp.IssueCredential("agt-rotate", "Nkyinkyim", []string{"read"}, time.Hour)

	rotated, err := acp.RotateCredential(original.ID)
	if err != nil {
		t.Fatalf("RotateCredential: %v", err)
	}

	if rotated.ID == original.ID {
		t.Error("rotated credential has same ID as original")
	}
	if string(rotated.PublicKey) == string(original.PublicKey) {
		t.Error("rotated credential has same public key as original (key not rotated)")
	}
	if rotated.AgentID != original.AgentID {
		t.Errorf("AgentID changed after rotation: got %q, want %q", rotated.AgentID, original.AgentID)
	}
}

// TestRotateCredentialInvalidatesOriginal verifies that after rotation,
// the original credential is no longer valid.
func TestRotateCredentialInvalidatesOriginal(t *testing.T) {
	acp, err := NewAgentControlPlane()
	if err != nil {
		t.Fatalf("NewAgentControlPlane: %v", err)
	}
	original, _ := acp.IssueCredential("agt-rot-inv", "Eban", nil, time.Hour)

	_, err = acp.RotateCredential(original.ID)
	if err != nil {
		t.Fatalf("RotateCredential: %v", err)
	}

	// Original should now be invalid (it was revoked during rotation)
	if err := acp.ValidateCredential(original); err == nil {
		t.Error("original credential should be invalid after rotation")
	}
}

// =============================================================================
// Credential Listing
// =============================================================================

// TestListCredentialsReturnsAllActive verifies that ListCredentials returns
// all credentials, excluding revoked ones.
func TestListCredentialsReturnsAllActive(t *testing.T) {
	acp, err := NewAgentControlPlane()
	if err != nil {
		t.Fatalf("NewAgentControlPlane: %v", err)
	}

	cred1, _ := acp.IssueCredential("agt-list-1", "Eban", nil, time.Hour)
	cred2, _ := acp.IssueCredential("agt-list-2", "Eban", nil, time.Hour)
	_, _ = acp.IssueCredential("agt-list-3", "Eban", nil, time.Hour)

	// Revoke cred1
	_ = acp.RevokeCredential(cred1.ID)

	creds := acp.ListCredentials()
	for _, c := range creds {
		if c.ID == cred1.ID {
			t.Error("revoked credential still appears in ListCredentials")
		}
	}

	// cred2 must still be present
	found := false
	for _, c := range creds {
		if c.ID == cred2.ID {
			found = true
			break
		}
	}
	if !found {
		t.Error("active credential missing from ListCredentials")
	}
}

// TestIssueCredentialConcurrency verifies that concurrent issuance operations
// are thread-safe and produce distinct credentials.
func TestIssueCredentialConcurrency(t *testing.T) {
	acp, err := NewAgentControlPlane()
	if err != nil {
		t.Fatalf("NewAgentControlPlane: %v", err)
	}
	done := make(chan string, 20)

	for i := 0; i < 20; i++ {
		go func(i int) {
			cred, err := acp.IssueCredential(
				"agt-concurrent",
				"Eban",
				[]string{"read"},
				time.Hour,
			)
			if err != nil {
				done <- ""
				return
			}
			done <- cred.ID
		}(i)
	}

	ids := make(map[string]bool)
	for i := 0; i < 20; i++ {
		id := <-done
		if id == "" {
			t.Error("concurrent IssueCredential returned empty ID")
			continue
		}
		if ids[id] {
			t.Errorf("duplicate credential ID issued concurrently: %q", id)
		}
		ids[id] = true
	}
}
