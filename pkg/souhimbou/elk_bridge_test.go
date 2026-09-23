package souhimbou

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/nouchix/PQC-Khepra-MCP/pkg/dag"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/flight"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/sekhem"
)

func TestELKBridge_IngressAttestation(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "elk-bridge-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// 1. Initialize DAG & Flight Recorder
	dagMem, err := dag.NewPersistentMemory(filepath.Join(tmpDir, "dag"))
	if err != nil {
		t.Fatal(err)
	}

	fr, err := flight.New(flight.RecorderConfig{
		Path: filepath.Join(tmpDir, "flight.ndjson"),
	})
	if err != nil {
		t.Fatal(err)
	}

	bridge, err := NewELKBridge(ELKBridgeConfig{
		DAG:    dagMem,
		Flight: fr,
		Mode:   sekhem.ModeHybrid,
	})
	if err != nil {
		t.Fatal(err)
	}

	// 2. Ingest Alert
	alertPayload := []byte(`{
		"id": "alert-9912",
		"rule_id": "rule-suspicious-auth",
		"rule_name": "Suspicious Lateral Movement Detected",
		"severity": "high",
		"risk_score": 85.5,
		"host": "vps-linux-hostinger",
		"@timestamp": "2026-09-22T05:30:00Z"
	}`)

	headers := make(http.Header)
	res, err := bridge.IngestAlert(context.Background(), alertPayload, headers)
	if err != nil {
		t.Fatalf("IngestAlert failed: %v", err)
	}

	if res.AlertID != "alert-9912" {
		t.Errorf("expected alert-9912, got %s", res.AlertID)
	}
	if res.DAGNodeID == "" {
		t.Errorf("expected non-empty DAGNodeID")
	}

	// Verify DAG Node was persisted
	node, exists := dagMem.Get(res.DAGNodeID)
	if !exists {
		t.Errorf("DAG node %s not found in memory", res.DAGNodeID)
	} else if node.Action != "ELK_SIEM_ALERT_ATTESTATION" {
		t.Errorf("expected action ELK_SIEM_ALERT_ATTESTATION, got %s", node.Action)
	}

	// Verify Flight Recorder recorded the frame
	frames, err := fr.Recent(10)
	if err != nil || len(frames) == 0 {
		t.Fatalf("expected at least 1 flight frame, got %d (err: %v)", len(frames), err)
	}
	if frames[len(frames)-1].ToolName != "elk_siem_ingress" {
		t.Errorf("expected tool elk_siem_ingress, got %s", frames[len(frames)-1].ToolName)
	}
}

func TestELKBridge_SovereignEgressBlock(t *testing.T) {
	bridge, err := NewELKBridge(ELKBridgeConfig{
		Mode:      sekhem.ModeSovereign,
		ELKURL:    "https://khepra-sec-f7ac1f.es.us-east-1.aws.elastic.cloud:443",
		ELKAPIKey: "fake-key",
	})
	if err != nil {
		t.Fatal(err)
	}

	err = bridge.ShipTelemetry(context.Background(), map[string]any{
		"event": "test",
	})
	if err != ErrSovereignEgressForbidden {
		t.Fatalf("expected ErrSovereignEgressForbidden, got %v", err)
	}
}

func TestELKBridge_SOCCaseIngressAndChangeRequest(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "elk-soc-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	dagMem, err := dag.NewPersistentMemory(filepath.Join(tmpDir, "dag"))
	if err != nil {
		t.Fatal(err)
	}

	fr, err := flight.New(flight.RecorderConfig{
		Path: filepath.Join(tmpDir, "flight.ndjson"),
	})
	if err != nil {
		t.Fatal(err)
	}

	bridge, err := NewELKBridge(ELKBridgeConfig{
		DAG:    dagMem,
		Flight: fr,
		Mode:   sekhem.ModeHybrid,
	})
	if err != nil {
		t.Fatal(err)
	}

	casePayload := []byte(`{
		"id": "case-774",
		"title": "Compromised API Credential Remediation",
		"description": "Elastic SOC flagged token abuse on edge host",
		"severity": "critical",
		"status": "open",
		"host": "vps-2-24-105-170",
		"commands": ["iptables -A INPUT -s 198.51.100.42 -j DROP"]
	}`)

	headers := make(http.Header)
	res, err := bridge.IngestSOCCase(context.Background(), casePayload, headers)
	if err != nil {
		t.Fatalf("IngestSOCCase failed: %v", err)
	}

	if res.CaseID != "case-774" {
		t.Errorf("expected case-774, got %s", res.CaseID)
	}
	if !res.Staged || res.ChangeRequest == nil {
		t.Fatalf("expected staged ChangeRequest, got staged=%v, cr=%v", res.Staged, res.ChangeRequest)
	}
	if res.ChangeRequest.Symbol != "Eban" {
		t.Errorf("expected Eban symbol on ChangeRequest, got %s", res.ChangeRequest.Symbol)
	}
	if res.ChangeRequest.Staging != true {
		t.Errorf("expected ChangeRequest.Staging=true, got false")
	}

	// Verify DAG attestation
	node, exists := dagMem.Get(res.DAGNodeID)
	if !exists {
		t.Errorf("DAG node %s not found", res.DAGNodeID)
	} else if node.Action != "ELK_SOC_CASE_ATTESTATION" {
		t.Errorf("expected ELK_SOC_CASE_ATTESTATION, got %s", node.Action)
	}
}

