package fleet

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"testing"
	"time"
)

func TestFleetRegistry_OsqueryWorkflow(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "khepra-fleet-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	reg, err := NewRegistry(tmpDir)
	if err != nil {
		t.Fatalf("failed to create registry: %v", err)
	}

	enrollReq := OsqueryEnrollRequest{
		EnrollSecret:   "khepra_sovereign_secret",
		HostIdentifier: "node-cmmc-test-01",
		Hostname:       "node-cmmc-test-01",
		IP:             "192.168.1.50",
		Platform:       "ubuntu",
		OsqueryVersion: "5.11.0",
		EnclaveID:      "enclave-satcom-01",
	}

	host, err := reg.EnrollOsqueryHost(enrollReq)
	if err != nil {
		t.Fatalf("failed to enroll osquery host: %v", err)
	}

	nodeKey := host.NodeKey
	if !strings.HasPrefix(nodeKey, "kphr_node_") {
		t.Errorf("expected node key prefix 'kphr_node_', got: %s", nodeKey)
	}

	hostRetrieved, exists := reg.GetHostByNodeKey(nodeKey)
	if !exists {
		t.Fatalf("expected host with key %s to exist in registry", nodeKey)
	}

	if hostRetrieved.Hostname != "node-cmmc-test-01" {
		t.Errorf("expected hostname node-cmmc-test-01, got %s", hostRetrieved.Hostname)
	}

	// Add distributed query
	queryID := "query_pam_config_1"
	querySQL := "SELECT * FROM file WHERE path = '/etc/pam.d/common-auth';"
	reg.AddHostQuery(nodeKey, queryID, querySQL)

	// Fetch pending queries
	pending := reg.GetPendingQueries(nodeKey)
	if sql, ok := pending[queryID]; !ok || sql != querySQL {
		t.Errorf("expected query %s with sql %s, got %+v", queryID, querySQL, pending)
	}

	// Subsequent fetch should be empty
	if len(reg.GetPendingQueries(nodeKey)) != 0 {
		t.Errorf("expected pending queries to be drained after first fetch")
	}

	// Submit results
	queries := map[string][]map[string]string{
		queryID: {
			{"path": "/etc/pam.d/common-auth", "size": "1024"},
		},
	}
	statuses := map[string]int{
		queryID: 0,
	}
	err = reg.SubmitQueryResult(nodeKey, queries, statuses)
	if err != nil {
		t.Fatalf("failed to submit query result: %v", err)
	}

	// Verify host status updated
	hostUpdated, _ := reg.GetHostByNodeKey(nodeKey)
	if hostUpdated.Status != "online" {
		t.Errorf("expected status online, got %s", hostUpdated.Status)
	}

	// Verify flagfile generation
	flagfile := reg.GenerateFlagfile("asaf.local:8443", "khepra_sovereign_secret")
	if !strings.Contains(flagfile, "--tls_hostname=asaf.local:8443") {
		t.Errorf("flagfile missing tls_hostname: %s", flagfile)
	}
	if !strings.Contains(flagfile, "--enroll_secret_value=khepra_sovereign_secret") {
		t.Errorf("flagfile missing enroll secret: %s", flagfile)
	}
}

func TestFleetRegistry_NativeAgentEnrollment(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "khepra-fleet-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	reg, err := NewRegistry(tmpDir)
	if err != nil {
		t.Fatalf("failed to create registry: %v", err)
	}

	req := AgentRegistrationRequest{
		Action:        "enroll",
		Token:         "sovereign_join_token",
		Hostname:      "satcom-ground-01",
		IP:            "10.0.10.5",
		OS:            "linux",
		Arch:          "amd64",
		KernelVersion: "6.8.0-generic",
		Enclave:       "enclave-ground-ops",
	}

	agentResp, err := reg.EnrollAgent(req)
	if err != nil {
		t.Fatalf("failed to enroll native agent: %v", err)
	}

	if agentResp.AgentID == "" {
		t.Errorf("expected non-empty agent ID")
	}

	if !agentResp.OK {
		t.Errorf("expected OK to be true")
	}

	// Test Heartbeat
	hb := AgentHeartbeat{
		Action:                "heartbeat",
		AgentID:               agentResp.AgentID,
		Timestamp:             time.Now(),
		ListeningPorts:        []int{22, 443},
		FIPSEnabled:           true,
		PAMFaillockConfigured: true,
		STIGScore:             98,
	}

	_, err = reg.UpdateHostHeartbeat(agentResp.AgentID, hb)
	if err != nil {
		t.Fatalf("failed to update heartbeat: %v", err)
	}

	hosts := reg.ListHosts("")
	if len(hosts) != 1 {
		t.Fatalf("expected 1 host in registry, got %d", len(hosts))
	}
	if hosts[0].STIGScore != 98 {
		t.Errorf("expected STIG score 98, got %d", hosts[0].STIGScore)
	}
}

func TestControlStateStore(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "khepra-control-state-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	css, err := NewControlStateStore(tmpDir)
	if err != nil {
		t.Fatalf("failed to create control state store: %v", err)
	}

	output := "auth required pam_faillock.so preauth silent deny=3 unlock_time=900"
	unchanged, _ := css.IsUnchanged("node-1", "AC-2", output)
	if unchanged {
		t.Errorf("expected fresh control state to not be unchanged")
	}

	h := sha256.Sum256([]byte(output))
	stateHash := hex.EncodeToString(h[:])

	css.Record(&ControlState{
		AssetID:     "node-1",
		ControlID:   "AC-2",
		StateHash:   stateHash,
		Status:      "pass",
		Severity:    "high",
		ProbeOutput: output,
		DAGNodeID:   "dag-node-123",
		ScannedAt:   time.Now().UTC(),
	})

	unchanged2, recordedState := css.IsUnchanged("node-1", "AC-2", output)
	if !unchanged2 {
		t.Errorf("expected unchanged to be true after recording matching output")
	}
	if recordedState.DAGNodeID != "dag-node-123" {
		t.Errorf("expected DAG node ID dag-node-123, got %s", recordedState.DAGNodeID)
	}

	// Probe output altered
	alteredOutput := "auth required pam_faillock.so preauth silent deny=5 unlock_time=900"
	unchanged3, _ := css.IsUnchanged("node-1", "AC-2", alteredOutput)
	if unchanged3 {
		t.Errorf("expected altered output to not be unchanged")
	}
}
