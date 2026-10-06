package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nouchix/PQC-Khepra-MCP/pkg/adinkra"
)

const (
	testAgentID = "test-agent"
)

func TestPolymorphicEngine(t *testing.T) {
	engine, err := NewPolymorphicEngine("Eban", 12)
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	payload := []byte("test-payload")
	agentID := testAgentID

	// Test WrapRequest
	signed, err := engine.WrapRequest(payload, agentID)
	if err != nil {
		t.Fatalf("failed to wrap request: %v", err)
	}

	if !bytes.Equal(signed.Payload, payload) {
		t.Error("payload mismatch")
	}

	// Test VerifyRequest
	err = engine.VerifyRequest(signed)
	if err != nil {
		t.Fatalf("failed to verify request: %v", err)
	}

	// Test WrapResponse
	respPayload := []byte("test-response")
	envelope, err := engine.WrapResponse(respPayload, signed.RequestID)
	if err != nil {
		t.Fatalf("failed to wrap response: %v", err)
	}

	if envelope == nil {
		t.Fatal("expected non-nil envelope")
	}
}

func TestDEMARCGatewayAuthenticate(t *testing.T) {
	engine, _ := NewPolymorphicEngine("Eban", 12)
	gateway := NewDEMARCGateway(engine)

	agentID := testAgentID
	symbol := "Eban"
	
	// Create a private key for issuing (simulating the caller)
	_, priv, _ := adinkra.GenerateAdinkhepraPQCKeyPair(symbol)
	defer priv.DestroyPrivateKey()

	// Issue credential
	cred, err := gateway.Issue(agentID, symbol, priv)
	if err != nil {
		t.Fatalf("failed to issue credential: %v", err)
	}

	// Authenticate credential
	err = gateway.Authenticate(cred)
	if err != nil {
		t.Fatalf("failed to authenticate: %v", err)
	}

	// Test expired credential
	cred.ExpiresAt = 0
	err = gateway.Authenticate(cred)
	if err == nil {
		t.Error("expected error for expired credential")
	}
}

func TestDEMARCGatewayHTTPHandler(t *testing.T) {
	engine, _ := NewPolymorphicEngine("Eban", 12)
	gateway := NewDEMARCGateway(engine)

	agentID := testAgentID
	symbol := "Eban"
	_, priv, _ := adinkra.GenerateAdinkhepraPQCKeyPair(symbol)
	cred, _ := gateway.Issue(agentID, symbol, priv)

	handler := gateway.HTTPHandler()

	// Valid request
	body, _ := json.Marshal(cred)
	req := httptest.NewRequest("POST", "/demarc", bytes.NewReader(body))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status OK, got %d", w.Code)
	}

	// Invalid request (bad JSON)
	req = httptest.NewRequest("POST", "/demarc", bytes.NewReader([]byte("bad-json")))
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected status BadRequest, got %d", w.Code)
	}
}

// TestDEMARCGatewayRejectsForeignToken checks that a credential is only
// accepted by the gateway whose secret keyed its zero-trust token, and that a
// credential signed by one key cannot claim another key.
func TestDEMARCGatewayRejectsForeignToken(t *testing.T) {
	engineA, _ := NewPolymorphicEngine("Eban", 12)
	engineB, _ := NewPolymorphicEngine("Eban", 12)
	gatewayA := NewDEMARCGateway(engineA)
	gatewayB := NewDEMARCGateway(engineB)

	_, priv, err := adinkra.GenerateAdinkhepraPQCKeyPair("Eban")
	if err != nil {
		t.Fatal(err)
	}
	cred, err := gatewayA.Issue(testAgentID, "Eban", priv)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if err := gatewayB.Authenticate(cred); err == nil {
		t.Fatal("gateway B accepted a credential issued by gateway A")
	}

	otherPub, _, err := adinkra.GenerateAdinkhepraPQCKeyPair("Eban")
	if err != nil {
		t.Fatal(err)
	}
	swapped := *cred
	swapped.PublicKey, _ = otherPub.MarshalBinary()
	if err := gatewayA.Authenticate(&swapped); err == nil {
		t.Fatal("accepted a credential whose public key was swapped")
	}

	retargeted := *cred
	retargeted.AgentID = "other-agent"
	if err := gatewayA.Authenticate(&retargeted); err == nil {
		t.Fatal("accepted a credential retargeted to another agent")
	}
}
