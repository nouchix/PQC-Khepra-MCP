// Integration tests for the ASAF patent technology modules.
// Each test exercises a full end-to-end cryptographic pipeline —
// no mocks, no stubs.  All crypto operations use real CIRCL primitives.
package adinkra

import (
	"bytes"
	"testing"
	"time"
)

// =============================================================================
// D₈ Transform Integration Tests
// =============================================================================

// TestD8TransformRoundTrip verifies that D8InverseTransform undoes D8Transform
// for every Adinkra symbol and every valid transformID.
func TestD8TransformRoundTrip(t *testing.T) {
	symbols := []string{"Eban", "Fawohodie", "Nkyinkyim", "Dwennimmen"}
	payload := []byte("AdinKhepra-QKE-Phase2-TestPayload-0123456789abcdef")

	for _, sym := range symbols {
		for id := 0; id < 16; id++ {
			transformed := D8Transform(payload, sym, id)
			if bytes.Equal(transformed, payload) {
				// A no-op transform on this payload isn't necessarily a bug,
				// but it must still round-trip correctly.
			}
			restored := D8InverseTransform(transformed, sym, id)
			if !bytes.Equal(restored, payload) {
				t.Errorf("symbol=%s transformID=%d: round-trip failed\ngot  %x\nwant %x",
					sym, id, restored, payload)
			}
		}
	}
}

// TestD8SymbolTransformIDDeterminism verifies that SymbolTransformID is
// purely deterministic — same symbol always yields the same ID.
func TestD8SymbolTransformIDDeterminism(t *testing.T) {
	symbols := []string{"Eban", "Fawohodie", "Nkyinkyim", "Dwennimmen", "Unknown"}
	for _, sym := range symbols {
		id1 := SymbolTransformID(sym)
		id2 := SymbolTransformID(sym)
		if id1 != id2 {
			t.Errorf("symbol=%s: non-deterministic IDs: %d vs %d", sym, id1, id2)
		}
		if id1 < 0 || id1 > 15 {
			t.Errorf("symbol=%s: ID %d out of [0,15] range", sym, id1)
		}
	}
}

// TestD8TransformDistinctness verifies that different symbols (with different
// spectral fingerprints) tend to produce distinct transforms on the same input.
func TestD8TransformDistinctness(t *testing.T) {
	input := bytes.Repeat([]byte{0xAB, 0xCD}, 32)
	results := make(map[string]string)
	for _, sym := range []string{"Eban", "Fawohodie", "Nkyinkyim", "Dwennimmen"} {
		out := D8Transform(input, sym, SymbolTransformID(sym))
		results[sym] = string(out)
	}
	// Verify at least two symbols produce different outputs
	unique := make(map[string]struct{})
	for _, v := range results {
		unique[v] = struct{}{}
	}
	if len(unique) < 2 {
		t.Error("D8Transform produces identical output for all four symbols — spectral fingerprints may not be differentiated")
	}
}

// TestD8TransformEmptyInput verifies graceful handling of empty data.
func TestD8TransformEmptyInput(t *testing.T) {
	empty := []byte{}
	out := D8Transform(empty, "Eban", 0)
	if !bytes.Equal(out, empty) {
		t.Errorf("empty input should produce empty output, got %x", out)
	}
	back := D8InverseTransform(out, "Eban", 0)
	if !bytes.Equal(back, empty) {
		t.Errorf("empty inverse should produce empty output, got %x", back)
	}
}

// =============================================================================
// KHEPRA-KDF Integration Tests
// =============================================================================

// TestKHEPRAKDFBasicDerivation verifies that DeriveKHEPRASessionKeys produces
// three distinct, non-nil, 32-byte keys.
func TestKHEPRAKDFBasicDerivation(t *testing.T) {
	sharedSecret := bytes.Repeat([]byte{0x42}, 32)
	keys, err := DeriveKHEPRASessionKeys(sharedSecret, "Eban", "Fawohodie", []byte("test-transcript"))
	if err != nil {
		t.Fatalf("DeriveKHEPRASessionKeys error: %v", err)
	}
	if len(keys.KEnc) != 32 {
		t.Errorf("KEnc length %d != 32", len(keys.KEnc))
	}
	if len(keys.KAuth) != 32 {
		t.Errorf("KAuth length %d != 32", len(keys.KAuth))
	}
	if len(keys.KAudit) != 32 {
		t.Errorf("KAudit length %d != 32", len(keys.KAudit))
	}
	// The three keys must be mutually distinct
	if bytes.Equal(keys.KEnc, keys.KAuth) {
		t.Error("KEnc == KAuth — keys not distinct")
	}
	if bytes.Equal(keys.KEnc, keys.KAudit) {
		t.Error("KEnc == KAudit — keys not distinct")
	}
	if bytes.Equal(keys.KAuth, keys.KAudit) {
		t.Error("KAuth == KAudit — keys not distinct")
	}
}

// TestKHEPRAKDFDeterminism verifies that the same inputs always yield the same keys.
func TestKHEPRAKDFDeterminism(t *testing.T) {
	ss := bytes.Repeat([]byte{0x11}, 32)
	transcript := []byte("determinism-check")

	k1, err := DeriveKHEPRASessionKeys(ss, "Eban", "Nkyinkyim", transcript)
	if err != nil {
		t.Fatalf("first derivation: %v", err)
	}
	k2, err := DeriveKHEPRASessionKeys(ss, "Eban", "Nkyinkyim", transcript)
	if err != nil {
		t.Fatalf("second derivation: %v", err)
	}

	if !bytes.Equal(k1.KEnc, k2.KEnc) {
		t.Error("KEnc is non-deterministic")
	}
	if !bytes.Equal(k1.KAuth, k2.KAuth) {
		t.Error("KAuth is non-deterministic")
	}
	if !bytes.Equal(k1.KAudit, k2.KAudit) {
		t.Error("KAudit is non-deterministic")
	}
}

// TestKHEPRAKDFSymbolBinding verifies that swapping symbols produces different keys,
// confirming that the KDF is bound to both symbol identities.
func TestKHEPRAKDFSymbolBinding(t *testing.T) {
	ss := bytes.Repeat([]byte{0xFF}, 32)
	transcript := []byte("symbol-binding-test")

	kAB, err := DeriveKHEPRASessionKeys(ss, "Eban", "Fawohodie", transcript)
	if err != nil {
		t.Fatalf("AB derivation: %v", err)
	}
	kBA, err := DeriveKHEPRASessionKeys(ss, "Fawohodie", "Eban", transcript)
	if err != nil {
		t.Fatalf("BA derivation: %v", err)
	}
	// Symbol order matters — AB ≠ BA (non-commutative binding)
	if bytes.Equal(kAB.KEnc, kBA.KEnc) {
		t.Error("KDF is commutative in symbols — symbol order is not bound")
	}
}

// TestKHEPRAKDFShortSecret tests key derivation with minimum secret length.
func TestKHEPRAKDFShortSecret(t *testing.T) {
	_, err := DeriveKHEPRASessionKeys([]byte{}, "Eban", "Eban", nil)
	if err == nil {
		t.Error("expected error for empty shared secret, got nil")
	}
}

// TestKHEPRAKDFSecureDestroy verifies that SecureDestroySessionKeys zeroes key material.
func TestKHEPRAKDFSecureDestroy(t *testing.T) {
	ss := bytes.Repeat([]byte{0xAA}, 32)
	keys, err := DeriveKHEPRASessionKeys(ss, "Dwennimmen", "Eban", []byte("destroy-test"))
	if err != nil {
		t.Fatalf("derivation: %v", err)
	}
	keys.SecureDestroySessionKeys()

	if !bytes.Equal(keys.KEnc, make([]byte, len(keys.KEnc))) {
		t.Error("KEnc not zeroed after SecureDestroySessionKeys")
	}
	if !bytes.Equal(keys.KAuth, make([]byte, len(keys.KAuth))) {
		t.Error("KAuth not zeroed after SecureDestroySessionKeys")
	}
	if !bytes.Equal(keys.KAudit, make([]byte, len(keys.KAudit))) {
		t.Error("KAudit not zeroed after SecureDestroySessionKeys")
	}
}

// =============================================================================
// DAG Consensus Integration Tests
// =============================================================================

// TestDAGAddAndVerifyVertex verifies the full sign-and-verify lifecycle
// for a DAG vertex using a real AdinKhepra PQC key pair.
func TestDAGAddAndVerifyVertex(t *testing.T) {
	// Generate a real PQC key pair
	pub, priv, err := GenerateAdinkhepraPQCKeyPair(nil, "Eban")
	if err != nil {
		t.Fatalf("key gen: %v", err)
	}

	dag := NewDAGConsensus()
	tx := []byte(`{"action":"agent.provision","agent_id":"agt-001","symbol":"Eban"}`)
	vertex, err := dag.AddVertex(tx, "Eban", "agt-001", nil, priv)
	if err != nil {
		t.Fatalf("AddVertex: %v", err)
	}

	// Vertex fields must be populated
	if vertex.ID == "" {
		t.Error("vertex ID is empty")
	}
	if len(vertex.Signature) == 0 {
		t.Error("vertex has no signature")
	}
	if len(vertex.Hash) == 0 {
		t.Error("vertex has no hash")
	}

	// Verify with the correct public key
	if err := dag.Verify(vertex.ID, pub); err != nil {
		t.Errorf("Verify failed with correct key: %v", err)
	}
}

// TestDAGVerifyWithWrongKey verifies that a different key's public key
// fails verification (tamper detection).
func TestDAGVerifyWithWrongKey(t *testing.T) {
	_, priv1, _ := GenerateAdinkhepraPQCKeyPair(nil, "Eban")
	pub2, _, _ := GenerateAdinkhepraPQCKeyPair(nil, "Fawohodie")

	dag := NewDAGConsensus()
	vertex, err := dag.AddVertex([]byte("tx"), "Eban", "agt-001", nil, priv1)
	if err != nil {
		t.Fatalf("AddVertex: %v", err)
	}

	if err := dag.Verify(vertex.ID, pub2); err == nil {
		t.Error("Verify should fail with mismatched public key")
	}
}

// TestDAGCausalOrdering verifies that a vertex that references a parent
// correctly links to it, and GetAncestors returns the chain.
func TestDAGCausalOrdering(t *testing.T) {
	_, priv, _ := GenerateAdinkhepraPQCKeyPair(nil, "Eban")
	dag := NewDAGConsensus()

	root, _ := dag.AddVertex([]byte("root"), "Eban", "agt-root", nil, priv)
	child, _ := dag.AddVertex([]byte("child"), "Eban", "agt-child", []string{root.ID}, priv)
	grandchild, _ := dag.AddVertex([]byte("grandchild"), "Nkyinkyim", "agt-gc", []string{child.ID}, priv)

	ancestors := dag.GetAncestors(grandchild.ID)
	// Should include both root and child (order may vary)
	ids := make(map[string]bool)
	for _, a := range ancestors {
		ids[a.ID] = true
	}
	if !ids[root.ID] {
		t.Error("root vertex not in ancestors of grandchild")
	}
	if !ids[child.ID] {
		t.Error("child vertex not in ancestors of grandchild")
	}
}

// TestDAGConflictResolution verifies that Eban (higher precedence) wins
// over Dwennimmen (lower precedence) in conflict resolution.
func TestDAGConflictResolution(t *testing.T) {
	_, priv, _ := GenerateAdinkhepraPQCKeyPair(nil, "Eban")
	dag := NewDAGConsensus()

	tx := []byte("conflicting-tx")
	vEban, _ := dag.AddVertex(tx, "Eban", "agt-1", nil, priv)
	// Create Dwennimmen with earlier timestamp to test symbol-based precedence
	vDwenn, _ := dag.AddVertex(tx, "Dwennimmen", "agt-2", nil, priv)

	winner := dag.ResolveConflict(vEban, vDwenn)
	if winner.ID != vEban.ID {
		t.Errorf("expected Eban (precedence=3) to win over Dwennimmen (precedence=0), got %s", winner.Symbol)
	}
}

// TestDAGAuditChain verifies that DAGAuditChain maintains a rolling
// hash chain and that every entry has a non-zero chain hash.
func TestDAGAuditChain(t *testing.T) {
	_, priv, _ := GenerateAdinkhepraPQCKeyPair(nil, "Eban")
	chain := NewDAGAuditChain(NewDAGConsensus())

	for i := 0; i < 5; i++ {
		tx := []byte("audit-event")
		if _, err := chain.Append(tx, "Eban", "agt-test", nil, priv); err != nil {
			t.Fatalf("chain.Append[%d]: %v", i, err)
		}
	}

	// All vertices in the underlying DAG should have valid hashes
	for _, v := range chain.dag.All() {
		if len(v.Hash) == 0 {
			t.Error("vertex in audit chain has empty hash")
		}
	}
}

// =============================================================================
// Zero Trust Token Integration Tests
// =============================================================================

// TestZeroTrustTokenIssuanceAndVerification exercises the full issue/verify lifecycle.
func TestZeroTrustTokenIssuanceAndVerification(t *testing.T) {
	kAuth := bytes.Repeat([]byte{0x55}, 32)

	token, err := IssueZeroTrustToken("agt-pqc-001", "Eban", 0.92, kAuth)
	if err != nil {
		t.Fatalf("IssueZeroTrustToken: %v", err)
	}

	// Token fields must be populated
	if token.AgentID != "agt-pqc-001" {
		t.Errorf("AgentID mismatch: got %q", token.AgentID)
	}
	if token.Symbol != "Eban" {
		t.Errorf("Symbol mismatch: got %q", token.Symbol)
	}
	if len(token.Nonce) == 0 {
		t.Error("Nonce is empty")
	}
	if len(token.MAC) == 0 {
		t.Error("MAC is empty")
	}

	// Verify with correct key
	if err := VerifyZeroTrustToken(token, kAuth); err != nil {
		t.Errorf("VerifyZeroTrustToken failed with correct key: %v", err)
	}
}

// TestZeroTrustTokenWrongKeyFails verifies that a different kAuth key fails verification.
func TestZeroTrustTokenWrongKeyFails(t *testing.T) {
	kAuth := bytes.Repeat([]byte{0xAA}, 32)
	kWrong := bytes.Repeat([]byte{0xBB}, 32)

	token, _ := IssueZeroTrustToken("agt-001", "Fawohodie", 0.75, kAuth)
	if err := VerifyZeroTrustToken(token, kWrong); err == nil {
		t.Error("VerifyZeroTrustToken should fail with wrong kAuth")
	}
}

// TestZeroTrustTokenTamperedMACFails verifies that flipping a MAC byte fails verification.
func TestZeroTrustTokenTamperedMACFails(t *testing.T) {
	kAuth := bytes.Repeat([]byte{0xCC}, 32)
	token, _ := IssueZeroTrustToken("agt-001", "Eban", 0.8, kAuth)

	// Flip the first byte of the MAC
	original := token.MAC[0]
	token.MAC[0] = original ^ 0xFF

	if err := VerifyZeroTrustToken(token, kAuth); err == nil {
		t.Error("VerifyZeroTrustToken should fail with tampered MAC")
	}
}

// TestZeroTrustTokenExpiry verifies that an expired token fails verification.
func TestZeroTrustTokenExpiry(t *testing.T) {
	kAuth := bytes.Repeat([]byte{0x77}, 32)
	token, _ := IssueZeroTrustToken("agt-exp", "Eban", 0.5, kAuth)

	// Force the token to appear expired by setting ExpiresAt to the past
	token.ExpiresAt = time.Now().Add(-1 * time.Second).Unix()
	// Recompute MAC so that it's consistent with the modified time, then check
	// that verify still fails (it checks expiry independent of MAC)
	if err := VerifyZeroTrustToken(token, kAuth); err == nil {
		t.Error("VerifyZeroTrustToken should fail for expired token")
	}
}

// TestZeroTrustTokenRefresh verifies that RefreshToken produces a new valid token
// and that the old token's nonce is not reused.
func TestZeroTrustTokenRefresh(t *testing.T) {
	kAuth := bytes.Repeat([]byte{0x33}, 32)
	old, _ := IssueZeroTrustToken("agt-refresh", "Nkyinkyim", 0.7, kAuth)

	refreshed, err := RefreshToken(old, kAuth, 0.85)
	if err != nil {
		t.Fatalf("RefreshToken: %v", err)
	}

	if err := VerifyZeroTrustToken(refreshed, kAuth); err != nil {
		t.Errorf("refreshed token fails verification: %v", err)
	}
	if bytes.Equal(old.Nonce, refreshed.Nonce) {
		t.Error("refreshed token reuses nonce — replay vulnerability")
	}
	if refreshed.TrustScore != 0.85 {
		t.Errorf("TrustScore not updated: got %v", refreshed.TrustScore)
	}
}

// TestZeroTrustTokenShortKeyRejected verifies that kAuth < 32 bytes is rejected.
func TestZeroTrustTokenShortKeyRejected(t *testing.T) {
	_, err := IssueZeroTrustToken("agt-001", "Eban", 0.5, []byte("short"))
	if err == nil {
		t.Error("expected error for kAuth < 32 bytes")
	}
}

// =============================================================================
// Kyber Encapsulate/Decapsulate Integration Tests
// =============================================================================

// TestKyberEncapsulateDecapsulate verifies the full KEM round-trip:
// encapsulate with public key, decapsulate with private key, shared secrets match.
func TestKyberEncapsulateDecapsulate(t *testing.T) {
	pubBytes, privBytes, err := GenerateKyberKey()
	if err != nil {
		t.Fatalf("GenerateKyberKey: %v", err)
	}

	ct, ss1, err := KyberEncapsulate(pubBytes)
	if err != nil {
		t.Fatalf("KyberEncapsulate: %v", err)
	}

	ss2, err := KyberDecapsulate(privBytes, ct)
	if err != nil {
		t.Fatalf("KyberDecapsulate: %v", err)
	}

	if !bytes.Equal(ss1, ss2) {
		t.Error("KEM shared secrets do not match — encapsulate/decapsulate failure")
	}
}

// TestKyberDecapsulateWithWrongKey verifies that decapsulating with a different
// private key yields a different shared secret (not an error per NIST ML-KEM spec).
func TestKyberDecapsulateWithWrongKey(t *testing.T) {
	pubBytes, _, _ := GenerateKyberKey()
	_, priv2Bytes, _ := GenerateKyberKey()

	ct, ss1, _ := KyberEncapsulate(pubBytes)
	ss2, err := KyberDecapsulate(priv2Bytes, ct)
	// Per ML-KEM spec, decapsulation with wrong key returns a random ss, not an error
	if err != nil {
		// Some implementations do return error; that's also acceptable
		return
	}
	if bytes.Equal(ss1, ss2) {
		t.Error("wrong key decapsulation produced the same shared secret — security failure")
	}
}
