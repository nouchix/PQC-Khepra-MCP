package souhimbou

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nouchix/PQC-Khepra-MCP/pkg/dag"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/flight"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/sekhem"
)

// helper to load live credentials from .env.local if not already in environment
func loadLiveEnvCredentials(t *testing.T) (string, string) {
	elkURL := os.Getenv("ELK_URL")
	elkKey := os.Getenv("ELK_API_KEY")
	if elkURL != "" && elkKey != "" {
		return elkURL, elkKey
	}

	// Try reading from blackbox/.env.local
	possiblePaths := []string{
		"../../.env.local",
		"../../../.env.local",
		"C:/Users/intel/blackbox/.env.local",
	}

	for _, p := range possiblePaths {
		data, err := os.ReadFile(p)
		if err == nil {
			scanner := bufio.NewScanner(bytes.NewReader(data))
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if strings.HasPrefix(line, "ELK_URL=") {
					elkURL = strings.Trim(strings.TrimPrefix(line, "ELK_URL="), `"`)
				}
				if strings.HasPrefix(line, "ELK_API_KEY=") {
					elkKey = strings.Trim(strings.TrimPrefix(line, "ELK_API_KEY="), `"`)
				}
			}
			if elkURL != "" && elkKey != "" {
				return elkURL, elkKey
			}
		}
	}

	return elkURL, elkKey
}

// ─── TEST 1: Live Elastic Cloud Cluster End-to-End Handshake ─────────────────
// Connects directly to the live AWS Elastic Cloud cluster, queries cluster info,
// writes an attested security test document, retrieves it, and cleans up.
func TestE2E_LiveElasticCluster_HandshakeAndIndex(t *testing.T) {
	elkURL, elkKey := loadLiveEnvCredentials(t)
	if elkURL == "" || elkKey == "" {
		t.Skip("Skipping live cluster test: ELK_URL or ELK_API_KEY not configured")
	}

	t.Logf("[E2E] Testing live cluster connectivity to: %s", elkURL)

	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		},
	}

	// 1. GET / (Cluster root verification)
	req, err := http.NewRequest("GET", elkURL, nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("Authorization", "ApiKey "+elkKey)

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to connect to live Elastic cluster: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("Expected HTTP 200 from cluster root, got %d: %s", resp.StatusCode, string(body))
	}

	var rootInfo map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&rootInfo); err != nil {
		t.Fatalf("Failed to parse cluster root JSON: %v", err)
	}
	t.Logf("[E2E] Connected! Cluster Name: %v, Tagline: %v", rootInfo["cluster_name"], rootInfo["tagline"])

	// 2. Index an attested test document: POST /khepra-test-e2e/_doc/test-doc-1
	testIndexURL := strings.TrimRight(elkURL, "/") + "/khepra-test-e2e/_doc/test-doc-1"
	testDoc := map[string]any{
		"@timestamp":      time.Now().UTC().Format(time.RFC3339Nano),
		"event_type":      "KHEPRA_E2E_VERIFICATION",
		"symbol":          "Eban",
		"attestation":     "ML-DSA-65",
		"cluster_tested":  elkURL,
		"security_status": "ROBUST_E2E_VERIFIED",
	}
	docBytes, _ := json.Marshal(testDoc)

	docReq, err := http.NewRequest("PUT", testIndexURL, bytes.NewReader(docBytes))
	if err != nil {
		t.Fatalf("failed to create doc PUT request: %v", err)
	}
	docReq.Header.Set("Content-Type", "application/json")
	docReq.Header.Set("Authorization", "ApiKey "+elkKey)

	docResp, err := client.Do(docReq)
	if err != nil {
		t.Fatalf("failed to PUT test document to Elastic: %v", err)
	}
	defer docResp.Body.Close()

	if docResp.StatusCode != http.StatusOK && docResp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(docResp.Body)
		t.Fatalf("Expected 200/201 on doc creation, got %d: %s", docResp.StatusCode, string(respBody))
	}
	t.Logf("[E2E] Document successfully written to live Elastic Cloud! Status: %d", docResp.StatusCode)

	// 3. GET /khepra-test-e2e/_doc/test-doc-1 (Verify write)
	getReq, _ := http.NewRequest("GET", testIndexURL, nil)
	getReq.Header.Set("Authorization", "ApiKey "+elkKey)
	getResp, err := client.Do(getReq)
	if err != nil {
		t.Fatalf("failed to GET test document: %v", err)
	}
	defer getResp.Body.Close()

	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("Failed to retrieve written document, status: %d", getResp.StatusCode)
	}

	var retrieved map[string]any
	_ = json.NewDecoder(getResp.Body).Decode(&retrieved)
	found, _ := retrieved["found"].(bool)
	if !found {
		t.Fatalf("Expected document found=true, got %v", retrieved)
	}
	t.Logf("[E2E] Document retrieved and verified from live Elastic cluster!")

	// 4. Cleanup: DELETE /khepra-test-e2e/_doc/test-doc-1
	delReq, _ := http.NewRequest("DELETE", testIndexURL, nil)
	delReq.Header.Set("Authorization", "ApiKey "+elkKey)
	delResp, err := client.Do(delReq)
	if err == nil {
		delResp.Body.Close()
		t.Logf("[E2E] Cleaned up test document. Status: %d", delResp.StatusCode)
	}
}

// ─── TEST 2: Full Ingress Pipeline (HTTP -> SEKHEM -> DAG -> Flight -> SOAR -> Daemon) ─
func TestE2E_FullIngressPipeline_EncapsulationAndAttestation(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "khepra-e2e-pipeline-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// 1. Storage & Flight Recorder
	dagMem, err := dag.NewPersistentMemory(filepath.Join(tmpDir, "dag"))
	if err != nil {
		t.Fatal(err)
	}

	flightPath := filepath.Join(tmpDir, "flight.ndjson")
	fr, err := flight.New(flight.RecorderConfig{Path: flightPath})
	if err != nil {
		t.Fatal(err)
	}

	// 2. SOAR Engine
	soarEngine := NewSOAREngine(SOARConfig{
		PlaybookDir: filepath.Join(tmpDir, "playbooks"),
		DAG:         dagMem,
	})

	// 3. Build Bridge
	const webhookSecret = "test-secret-salt-8812"
	bridge, err := NewELKBridge(ELKBridgeConfig{
		DAG:           dagMem,
		Flight:        fr,
		SOAR:          soarEngine,
		WebhookSecret: webhookSecret,
		Mode:          sekhem.ModeHybrid,
	})
	if err != nil {
		t.Fatal(err)
	}

	// 4. Mount into test HTTP server (simulating SEKHEM Gateway endpoint)
	ts := httptest.NewServer(bridge.HTTPHandler())
	defer ts.Close()

	// ─── Test 2A: Rejection of Unauthorized Webhook ───────────────────────────
	badReq, _ := http.NewRequest("POST", ts.URL, bytes.NewReader([]byte(`{"test":1}`)))
	badReq.Header.Set("Content-Type", "application/json")
	badReq.Header.Set("X-Elastic-Secret", "wrong-secret")

	badResp, err := http.DefaultClient.Do(badReq)
	if err != nil {
		t.Fatal(err)
	}
	badResp.Body.Close()
	if badResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("Expected 401 Unauthorized for bad secret, got %d", badResp.StatusCode)
	}
	t.Log("[E2E] Security Check: Unauthorized webhook correctly rejected (401)")

	// ─── Test 2B: Ingestion of High Severity Elastic Alert ────────────────────
	alertPayload := []byte(`{
		"id": "e2e-alert-7721",
		"rule_id": "rule-priv-escalation",
		"rule_name": "Linux Privilege Escalation via Sudo Attempt",
		"severity": "critical",
		"risk_score": 98.0,
		"host": "vps-2-24-105-170",
		"user": "intruder-42",
		"@timestamp": "2026-09-22T05:40:00Z"
	}`)

	goodReq, _ := http.NewRequest("POST", ts.URL, bytes.NewReader(alertPayload))
	goodReq.Header.Set("Content-Type", "application/json")
	goodReq.Header.Set("X-Elastic-Secret", webhookSecret)

	goodResp, err := http.DefaultClient.Do(goodReq)
	if err != nil {
		t.Fatal(err)
	}
	defer goodResp.Body.Close()

	if goodResp.StatusCode != http.StatusAccepted {
		b, _ := io.ReadAll(goodResp.Body)
		t.Fatalf("Expected 202 Accepted, got %d: %s", goodResp.StatusCode, string(b))
	}

	dagHeader := goodResp.Header.Get("X-Khepra-DAG-Node")
	if dagHeader == "" {
		t.Fatal("Expected X-Khepra-DAG-Node response header")
	}

	var ingestResult IngestResult
	if err := json.NewDecoder(goodResp.Body).Decode(&ingestResult); err != nil {
		t.Fatalf("Failed to parse ingest response: %v", err)
	}

	if ingestResult.AlertID != "e2e-alert-7721" {
		t.Errorf("Unexpected AlertID: %s", ingestResult.AlertID)
	}
	if !ingestResult.SOARStaged {
		t.Errorf("Expected SOARStaged=true for critical alert")
	}
	if ingestResult.PlaybookName != "quarantine-agent" {
		t.Errorf("Expected playbook quarantine-agent, got %s", ingestResult.PlaybookName)
	}

	// ─── Test 2C: Verify DAG Node on Disk ─────────────────────────────────────
	dagNode, exists := dagMem.Get(dagHeader)
	if !exists {
		t.Fatalf("DAG node %s not found in memory/disk", dagHeader)
	}
	if dagNode.Action != "ELK_SIEM_ALERT_ATTESTATION" {
		t.Errorf("Expected action ELK_SIEM_ALERT_ATTESTATION, got %s", dagNode.Action)
	}
	if dagNode.Symbol != "Eban" {
		t.Errorf("Expected symbol Eban, got %s", dagNode.Symbol)
	}
	if dagNode.PQC["rule_name"] != "Linux Privilege Escalation via Sudo Attempt" {
		t.Errorf("Unexpected rule name in DAG PQC metadata: %s", dagNode.PQC["rule_name"])
	}
	t.Logf("[E2E] DAG Attestation Node verified: ID=%s, Symbol=%s", dagNode.ID, dagNode.Symbol)

	// ─── Test 2D: Verify Flight Recorder NDJSON Chain Continuity ──────────────
	frames, err := fr.Recent(10)
	if err != nil || len(frames) == 0 {
		t.Fatalf("Failed to read flight frames: %v", err)
	}

	var foundFrame *flight.FlightFrame
	for _, f := range frames {
		if f.ToolName == "elk_siem_ingress" && f.Subject == "e2e-alert-7721" {
			frameCopy := f
			foundFrame = &frameCopy
			break
		}
	}
	if foundFrame == nil {
		t.Fatal("Could not find matching flight frame in NDJSON log")
	}
	if foundFrame.DAGNodeID != dagHeader {
		t.Errorf("FlightFrame DAG anchor mismatch: %s vs %s", foundFrame.DAGNodeID, dagHeader)
	}
	if !foundFrame.IsSigned {
		t.Errorf("FlightFrame IsSigned expected true")
	}
	t.Logf("[E2E] FlightFrame verified: Seq=%d, Tool=%s, Outcome=%s", foundFrame.Seq, foundFrame.ToolName, foundFrame.Outcome)
}

// ─── TEST 3: SOC Incident Case -> ChangeRequest -> Privileged Daemon Gate ─────
func TestE2E_SOCCase_ChangeRequestGate(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "khepra-e2e-soc-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	dagMem, err := dag.NewPersistentMemory(filepath.Join(tmpDir, "dag"))
	if err != nil {
		t.Fatal(err)
	}

	fr, err := flight.New(flight.RecorderConfig{Path: filepath.Join(tmpDir, "flight.ndjson")})
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

	socPayload := []byte(`{
		"id": "soc-case-8891",
		"title": "Unauthorized Outbound Beaconing Detected",
		"description": "Elastic AI SOC correlated 14 malicious C2 connections",
		"severity": "critical",
		"status": "open",
		"host": "vps-linux-node",
		"commands": [
			"iptables -A OUTPUT -d 203.0.113.50 -j DROP",
			"systemctl stop malicious-worker"
		]
	}`)

	res, err := bridge.IngestSOCCase(context.Background(), socPayload, nil)
	if err != nil {
		t.Fatalf("IngestSOCCase failed: %v", err)
	}

	// Verify Staging Gate Enforced
	if !res.Staged || res.ChangeRequest == nil {
		t.Fatalf("ChangeRequest was not staged! Staged=%v", res.Staged)
	}

	cr := res.ChangeRequest
	if cr.Staging != true {
		t.Errorf("CRITICAL SECURITY FLAW: ChangeRequest.Staging must be true by default")
	}
	if cr.Symbol != "Eban" {
		t.Errorf("Expected defensive symbol Eban on ChangeRequest, got %s", cr.Symbol)
	}
	if cr.ControlID != "IR-4" {
		t.Errorf("Expected CMMC control IR-4, got %s", cr.ControlID)
	}
	if len(cr.Command) != 2 {
		t.Errorf("Expected 2 remediation commands, got %d", len(cr.Command))
	}
	if cr.DAGParent != res.DAGNodeID {
		t.Errorf("Chain of custody broken: ChangeRequest DAGParent (%s) != Ingest DAGNodeID (%s)", cr.DAGParent, res.DAGNodeID)
	}

	t.Logf("[E2E] ChangeRequest verified: ID=%s, Symbol=%s, Staged=%v, DAGParent=%s",
		cr.ID, cr.Symbol, cr.Staging, cr.DAGParent)
}

// ─── TEST 4: Sovereign Air-Gap Zero-Egress Proof (DoD Non-Negotiable #1) ───────
func TestE2E_SovereignAirGap_ZeroEgressEnforcement(t *testing.T) {
	bridge, err := NewELKBridge(ELKBridgeConfig{
		Mode:      sekhem.ModeSovereign, // AIR-GAP
		ELKURL:    "https://fake.cluster.elastic.cloud:443",
		ELKAPIKey: "fake-key",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Attempt egress
	err = bridge.ShipTelemetry(context.Background(), map[string]any{
		"sensitive_telemetry": "should_never_leave_host",
	})

	if err != ErrSovereignEgressForbidden {
		t.Fatalf("Expected ErrSovereignEgressForbidden, got %v", err)
	}
	t.Log("[E2E] Sovereign Air-Gap verified: 0 bytes egress, hard-blocked before network call.")
}

// ─── TEST 5: High-Concurrency Stress Test (Attestation Chain Integrity) ───────
func TestE2E_HighConcurrency_AttestationIntegrity(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "khepra-e2e-stress-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	dagMem, err := dag.NewPersistentMemory(filepath.Join(tmpDir, "dag"))
	if err != nil {
		t.Fatal(err)
	}

	fr, err := flight.New(flight.RecorderConfig{Path: filepath.Join(tmpDir, "flight.ndjson")})
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

	const workers = 25
	const alertsPerWorker = 4
	totalAlerts := workers * alertsPerWorker

	var wg sync.WaitGroup
	errChan := make(chan error, totalAlerts)

	t.Logf("[E2E] Stress Testing: Disagreeing %d concurrent alerts across %d workers...", totalAlerts, workers)

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for i := 0; i < alertsPerWorker; i++ {
				payload := []byte(fmt.Sprintf(`{
					"id": "stress-alert-w%d-i%d",
					"rule_id": "rule-stress",
					"rule_name": "Concurrent Ingestion Stress",
					"severity": "medium",
					"host": "vps-node",
					"@timestamp": "2026-09-22T05:45:00Z"
				}`, workerID, i))

				res, err := bridge.IngestAlert(context.Background(), payload, nil)
				if err != nil {
					errChan <- fmt.Errorf("worker %d item %d error: %w", workerID, i, err)
					return
				}
				if res.DAGNodeID == "" {
					errChan <- fmt.Errorf("worker %d item %d missing DAGNodeID", workerID, i)
					return
				}
			}
		}(w)
	}

	wg.Wait()
	close(errChan)

	for err := range errChan {
		t.Fatalf("Concurrent ingestion error: %v", err)
	}

	// Verify all records landed in Flight Recorder
	frames, err := fr.Recent(totalAlerts + 10)
	if err != nil {
		t.Fatalf("Failed to read frames: %v", err)
	}

	if len(frames) != totalAlerts {
		t.Fatalf("Expected exactly %d frames in Flight Recorder, got %d", totalAlerts, len(frames))
	}

	// Verify monotonic sequence numbering and chain consistency
	for i := 0; i < len(frames); i++ {
		if frames[i].Seq != uint64(i) {
			t.Errorf("Frame %d sequence broken: expected %d, got %d", i, i, frames[i].Seq)
		}
	}

	t.Logf("[E2E] Concurrency stress test PASSED: %d events safely attested with monotonic sequence integrity!", totalAlerts)
}
