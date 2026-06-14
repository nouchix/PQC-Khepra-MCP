package ir

import (
	"context"
	"crypto/rand"
	"testing"
	"time"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/dag"
	"github.com/cloudflare/circl/sign/dilithium/mode3"
)

// generateTestKeysForRemediation generates real Dilithium3 keys for testing
// TRL 10: No mocks, no stubs - real PQC cryptography
func generateTestKeysForRemediation(t *testing.T) (pubKey []byte, privKey []byte) {
	t.Helper()

	pk, sk, err := mode3.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Dilithium3 key pair: %v", err)
	}

	pubKey, err = pk.MarshalBinary()
	if err != nil {
		t.Fatalf("Failed to marshal public key: %v", err)
	}

	privKey, err = sk.MarshalBinary()
	if err != nil {
		t.Fatalf("Failed to marshal private key: %v", err)
	}

	return pubKey, privKey
}

func TestGetRemediationScripts(t *testing.T) {
	scripts := GetRemediationScripts()

	if len(scripts) == 0 {
		t.Fatal("Expected remediation scripts, got empty map")
	}

	// Verify IR.L3-3.6.1e scripts exist
	irScripts, exists := scripts[IR_L3_3_6_1e]
	if !exists {
		t.Fatal("Expected IR.L3-3.6.1e remediation scripts")
	}

	if len(irScripts) < 3 {
		t.Errorf("Expected at least 3 IR.L3-3.6.1e scripts, got %d", len(irScripts))
	}

	// Verify RA.L3-3.11.3e threat hunting scripts
	raScripts, exists := scripts[RA_L3_3_11_3e]
	if !exists {
		t.Fatal("Expected RA.L3-3.11.3e remediation scripts")
	}

	if len(raScripts) < 2 {
		t.Errorf("Expected at least 2 RA.L3-3.11.3e scripts, got %d", len(raScripts))
	}
}

func TestRemediationActionStructure(t *testing.T) {
	scripts := GetRemediationScripts()
	irScripts := scripts[IR_L3_3_6_1e]

	for _, action := range irScripts {
		if action.ID == "" {
			t.Error("Action ID should not be empty")
		}

		if action.ControlID == "" {
			t.Error("Control ID should not be empty")
		}

		if action.Title == "" {
			t.Error("Title should not be empty")
		}

		if action.ActionType == "" {
			t.Error("ActionType should not be empty")
		}

		if action.Timeout == 0 {
			t.Error("Timeout should be set")
		}
	}
}

func TestNewSOCIntegration(t *testing.T) {
	store := dag.GlobalDAG()
	mgr := NewManager(store)
	_, privKey := generateTestKeysForRemediation(t)

	soc := NewSOCIntegration(store, mgr, privKey)

	if soc == nil {
		t.Fatal("Expected non-nil SOC integration")
	}

	if !soc.enabled {
		t.Error("SOC integration should be enabled by default")
	}

	if soc.store == nil {
		t.Error("Store should be set")
	}

	if soc.manager == nil {
		t.Error("Manager should be set")
	}
}

func TestSOCIntegration_RecordTelemetryEvent(t *testing.T) {
	store := dag.GlobalDAG()
	mgr := NewManager(store)
	_, privKey := generateTestKeysForRemediation(t)

	soc := NewSOCIntegration(store, mgr, privKey)
	ctx := context.Background()

	node, err := soc.RecordTelemetryEvent(ctx, "test_event", map[string]interface{}{
		"test_key": "test_value",
		"count":    42,
	})

	if err != nil {
		t.Fatalf("RecordTelemetryEvent failed: %v", err)
	}

	if node == nil {
		t.Fatal("Expected non-nil DAG node")
	}

	if node.ID == "" {
		t.Error("Node ID should not be empty")
	}

	if node.Action != "soc_telemetry" {
		t.Errorf("Expected action 'soc_telemetry', got '%s'", node.Action)
	}

	if node.Symbol != "Dwennimmen" {
		t.Errorf("Expected symbol 'Dwennimmen', got '%s'", node.Symbol)
	}

	if len(node.Signature) == 0 {
		t.Error("Node should have a signature")
	}
}

func TestSOCIntegration_ProcessIncidentTelemetry(t *testing.T) {
	store := dag.GlobalDAG()
	mgr := NewManager(store)
	_, privKey := generateTestKeysForRemediation(t)

	soc := NewSOCIntegration(store, mgr, privKey)

	incident := &Incident{
		ID:          "inc-soc-test-001",
		Title:       "SOC Test Incident",
		Description: "Testing SOC telemetry integration",
		Severity:    SevHigh,
		Status:      StatusOpen,
		Type:        "test",
		DetectedAt:  time.Now(),
		UpdatedAt:   time.Now(),
	}

	err := soc.ProcessIncidentTelemetry(incident)
	if err != nil {
		t.Fatalf("ProcessIncidentTelemetry failed: %v", err)
	}
}

func TestSOCIntegration_ProcessIOCTelemetry(t *testing.T) {
	store := dag.GlobalDAG()
	mgr := NewManager(store)
	_, privKey := generateTestKeysForRemediation(t)

	soc := NewSOCIntegration(store, mgr, privKey)

	incident := &Incident{
		ID:    "inc-ioc-test-001",
		Title: "IOC Telemetry Test",
	}

	ioc := IOC{
		Type:  "ip",
		Value: "192.168.1.100",
		Desc:  "Test malicious IP",
	}

	err := soc.ProcessIOCTelemetry(incident, ioc)
	if err != nil {
		t.Fatalf("ProcessIOCTelemetry failed: %v", err)
	}
}

func TestSOCIntegration_ProcessStatusChangeTelemetry(t *testing.T) {
	store := dag.GlobalDAG()
	mgr := NewManager(store)
	_, privKey := generateTestKeysForRemediation(t)

	soc := NewSOCIntegration(store, mgr, privKey)

	incident := &Incident{
		ID:    "inc-status-test-001",
		Title: "Status Change Test",
	}

	err := soc.ProcessStatusChangeTelemetry(incident, StatusOpen, StatusInProgress, "SOC analyst assigned")
	if err != nil {
		t.Fatalf("ProcessStatusChangeTelemetry failed: %v", err)
	}
}

func TestSOCIntegration_ExecuteRemediation(t *testing.T) {
	store := dag.GlobalDAG()
	mgr := NewManager(store)
	_, privKey := generateTestKeysForRemediation(t)

	soc := NewSOCIntegration(store, mgr, privKey)
	ctx := context.Background()

	action := RemediationAction{
		ID:          "test-action-001",
		ControlID:   IR_L3_3_6_1e,
		Title:       "Test Remediation Action",
		Description: "Testing remediation execution",
		ActionType:  "api_call",
		APIEndpoint: "/api/v1/test",
		Timeout:     30 * time.Second,
		AutoExecute: true,
	}

	result, err := soc.ExecuteRemediation(ctx, action)
	if err != nil {
		t.Fatalf("ExecuteRemediation failed: %v", err)
	}

	if result == nil {
		t.Fatal("Expected non-nil result")
	}

	if result.ActionID != action.ID {
		t.Errorf("Expected action ID '%s', got '%s'", action.ID, result.ActionID)
	}

	if result.ControlID != action.ControlID {
		t.Errorf("Expected control ID '%s', got '%s'", action.ControlID, result.ControlID)
	}

	if result.Status == "" {
		t.Error("Status should not be empty")
	}

	if result.DAGNodeID == "" {
		t.Error("DAG Node ID should not be empty")
	}

	if result.ExecutedAt.IsZero() {
		t.Error("ExecutedAt should not be zero")
	}
}

func TestSOCIntegration_Disabled(t *testing.T) {
	store := dag.GlobalDAG()
	mgr := NewManager(store)
	_, privKey := generateTestKeysForRemediation(t)

	soc := NewSOCIntegration(store, mgr, privKey)
	soc.enabled = false

	ctx := context.Background()
	_, err := soc.RecordTelemetryEvent(ctx, "test", map[string]interface{}{})

	if err == nil {
		t.Fatal("Expected error when SOC integration is disabled")
	}
}

func TestCMMCControlConstants(t *testing.T) {
	// Verify all 24 enhanced practice constants are defined
	controls := []string{
		AC_L3_3_1_1e, AC_L3_3_1_2e, AC_L3_3_1_3e,
		AU_L3_3_3_1e, AU_L3_3_3_2e, AU_L3_3_3_3e,
		CM_L3_3_4_1e, CM_L3_3_4_2e, CM_L3_3_4_3e,
		IA_L3_3_5_1e, IA_L3_3_5_2e, IA_L3_3_5_3e,
		IR_L3_3_6_1e, IR_L3_3_6_2e, IR_L3_3_6_3e,
		RA_L3_3_11_1e, RA_L3_3_11_2e, RA_L3_3_11_3e,
		SI_L3_3_14_1e, SI_L3_3_14_2e, SI_L3_3_14_3e,
		SC_L3_3_13_1e, SC_L3_3_13_2e, SC_L3_3_13_3e,
	}

	if len(controls) != 24 {
		t.Errorf("Expected 24 enhanced practice controls, got %d", len(controls))
	}

	for _, ctrl := range controls {
		if ctrl == "" {
			t.Error("Control ID should not be empty")
		}
	}
}

func TestGenerateEventID(t *testing.T) {
	id1 := generateEventID()
	id2 := generateEventID()

	if id1 == "" {
		t.Error("Event ID should not be empty")
	}

	if id1 == id2 {
		t.Error("Event IDs should be unique")
	}

	// Should start with "evt-"
	if len(id1) < 4 || id1[:4] != "evt-" {
		t.Errorf("Event ID should start with 'evt-', got '%s'", id1)
	}
}

func TestSignWithDilithium(t *testing.T) {
	_, privKey := generateTestKeysForRemediation(t)

	data := []byte("Test data for signing")
	signature, err := signWithDilithium(data, privKey)

	if err != nil {
		t.Fatalf("signWithDilithium failed: %v", err)
	}

	if len(signature) == 0 {
		t.Error("Signature should not be empty")
	}

	// Dilithium3 signature size is 3293 bytes
	expectedSize := 3293
	if len(signature) != expectedSize {
		t.Errorf("Expected signature size %d, got %d", expectedSize, len(signature))
	}
}

func TestSignWithDilithium_InvalidKey(t *testing.T) {
	invalidKey := []byte("invalid key")
	data := []byte("Test data")

	_, err := signWithDilithium(data, invalidKey)
	if err == nil {
		t.Fatal("Expected error with invalid key")
	}
}
