//go:build e2e
// +build e2e

// cmd/khepra-mcp/e2e_test.go — End-to-end test for the khepra-mcp binary.
//
// Tests ONLY in-memory fast-path tools (no stig.NewValidator filesystem scans).
// Tools that call stig.NewValidator(".")  — khepra_export_attestation,
// khepra_export_poam, khepra_get_compliance_score — live in
// slow_integration_test.go (run with -timeout 10m).
//
// Run:
//
//	go test -v -tags e2e -timeout 45s ./cmd/khepra-mcp/ -run TestE2E_Fast
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// ─── wire types ──────────────────────────────────────────────────────────────

type rpcMsg struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      *int            `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  any             `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

func iptr(n int) *int { return &n }

func call(msgID int, name string, args map[string]any) rpcMsg {
	return rpcMsg{
		JSONRPC: "2.0",
		ID:      iptr(msgID),
		Method:  "tools/call",
		Params:  map[string]any{"name": name, "arguments": args},
	}
}

func msh(v any) string { b, _ := json.Marshal(v); return string(b) }

// ─── server runner ────────────────────────────────────────────────────────────

// startServer launches the khepra-mcp binary and returns typed send/recv/stop fns.
// perRecv is the per-call receive timeout.
func startServer(t *testing.T, perRecv time.Duration) (
	send func(rpcMsg),
	recv func() *rpcMsg,
	stop func(),
) {
	t.Helper()

	_, thisFile, _, _ := runtime.Caller(0)
	projectRoot, _ := filepath.Abs(filepath.Join(filepath.Dir(thisFile), "..", ".."))
	binary := filepath.Join(projectRoot, "khepra-mcp.exe")
	if _, err := os.Stat(binary); err != nil {
		t.Fatalf("binary not found: %s — run: go build -o khepra-mcp.exe ./cmd/khepra-mcp/", binary)
	}

	cmd := exec.Command(binary)
	cmd.Dir = projectRoot
	cmd.Env = append(os.Environ(),
		"KHEPRA_DATA_DIR="+t.TempDir(),
		"GOTOOLCHAIN=local",
		"GOROOT=C:\\Program Files\\Go",
	)

	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("stdin: %v", err)
	}
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}

	lines := make(chan *rpcMsg, 128)
	go func() {
		sc := bufio.NewScanner(stdoutPipe)
		sc.Buffer(make([]byte, 8<<20), 8<<20) // 8 MB buffer for large PQC responses
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" {
				continue
			}
			var msg rpcMsg
			if json.Unmarshal([]byte(line), &msg) == nil {
				cp := msg
				lines <- &cp
			}
		}
		close(lines)
	}()

	send = func(msg rpcMsg) {
		io.WriteString(stdinPipe, msh(msg)+"\n")
	}

	recv = func() *rpcMsg {
		select {
		case msg, ok := <-lines:
			if !ok {
				return nil // channel closed (server exited)
			}
			return msg
		case <-time.After(perRecv):
			return nil
		}
	}

	stop = func() {
		stdinPipe.Close()
		// Give the server 3s to flush remaining responses and exit cleanly
		done := make(chan struct{})
		go func() { cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			cmd.Process.Kill()
			<-done
		}
	}

	return send, recv, stop
}

// ─── helpers ─────────────────────────────────────────────────────────────────

// exchange sends one request and waits for its response by matching the ID.
// Discards out-of-order responses from earlier slow tool calls.
func exchange(send func(rpcMsg), recv func() *rpcMsg, msg rpcMsg, timeout time.Duration) *rpcMsg {
	if msg.ID == nil {
		// Notification — no response expected
		send(msg)
		return nil
	}
	send(msg)
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		r := recv()
		if r == nil {
			return nil // recv timed out
		}
		if r.ID != nil && *r.ID == *msg.ID {
			return r
		}
		// out-of-order response — discard and keep waiting
	}
	return nil
}

// toolResult unpacks the MCP tools/call content envelope and the KHEPRA
// SecureEnvelope wrapper. Tool results live at:
//   content[].text → JSON → envelope.result → actual fields
func toolResult(r *rpcMsg) (map[string]any, error) {
	if r == nil {
		return nil, fmt.Errorf("nil response (tool may have hung)")
	}
	if r.Error != nil {
		return nil, fmt.Errorf("RPC %d: %s", r.Error.Code, r.Error.Message)
	}
	// Layer 1: MCP tools/call content envelope
	var env struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		IsError bool `json:"isError"`
	}
	if json.Unmarshal(r.Result, &env) == nil {
		if env.IsError {
			for _, c := range env.Content {
				if c.Type == "text" {
					return nil, fmt.Errorf("tool error: %s", c.Text)
				}
			}
			return nil, fmt.Errorf("tool returned isError=true")
		}
		for _, c := range env.Content {
			if c.Type == "text" && c.Text != "" {
				var inner map[string]any
				if json.Unmarshal([]byte(c.Text), &inner) == nil {
					// Layer 2: KHEPRA SecureEnvelope — actual result lives at envelope.result
					if khepraEnv, ok := inner["envelope"].(map[string]any); ok {
						if result, ok := khepraEnv["result"].(map[string]any); ok && result != nil {
							return result, nil
						}
						// If result is nil/missing, check for error payload
						if errMsg, ok := khepraEnv["error_message"]; ok && errMsg != nil {
							return nil, fmt.Errorf("tool error: %v", errMsg)
						}
					}
					// No envelope wrapper — return as-is (e.g. discover_assets)
					return inner, nil
				}
			}
		}
	}
	// Bare result — could be KHEPRA bare format or initialize/tools-list
	var bare map[string]any
	if err := json.Unmarshal(r.Result, &bare); err != nil {
		return nil, err
	}
	// Detect KHEPRA bare error format: {"is_error":true,"error_message":"..."}
	if isErr, _ := bare["is_error"].(bool); isErr {
		if errMsg, ok := bare["error_message"].(string); ok && errMsg != "" {
			return nil, fmt.Errorf("%s", errMsg)
		}
		return nil, fmt.Errorf("tool returned is_error=true")
	}
	// Detect KHEPRA bare SecureEnvelope format: {"envelope":{"result":{...}}}
	if khepraEnv, ok := bare["envelope"].(map[string]any); ok {
		if result, ok := khepraEnv["result"].(map[string]any); ok && result != nil {
			return result, nil
		}
	}
	return bare, nil
}

// ─── E2E fast test ────────────────────────────────────────────────────────────

// TestE2E_Fast exercises in-memory fast-path tools only.
// No stig.NewValidator filesystem scans — completes in < 30 seconds.
//
// Excluded from this suite (use slow_integration_test.go):
//   - khepra_export_attestation  (stig.NewValidator scan, 120s timeout)
//   - khepra_export_poam         (stig.NewValidator scan, 120s timeout)
//   - khepra_get_compliance_score (stig.NewValidator scan, 60s timeout)
//   - stig_check, cmmc_assess, ert_readiness, ert_crypto (all scan filesystem)
func TestE2E_Fast(t *testing.T) {
	const perCall = 10 * time.Second

	send, recv, stop := startServer(t, perCall)
	defer stop()

	ex := func(id int, name string, args map[string]any) *rpcMsg {
		return exchange(send, recv, call(id, name, args), perCall)
	}

	// ── 1. initialize ────────────────────────────────────────────────────────
	t.Run("initialize", func(t *testing.T) {
		r := exchange(send, recv, rpcMsg{
			JSONRPC: "2.0", ID: iptr(1), Method: "initialize",
			Params: map[string]any{
				"protocolVersion": "2024-11-05",
				"capabilities":    map[string]any{},
				"clientInfo":      map[string]any{"name": "e2e", "version": "1.0"},
			},
		}, perCall)
		res, err := toolResult(r)
		if err != nil {
			t.Fatalf("initialize: %v", err)
		}
		if got := res["protocolVersion"]; got != "2024-11-05" {
			t.Errorf("protocolVersion=%v want 2024-11-05", got)
		}
		t.Logf("OK — protocolVersion=%v", res["protocolVersion"])
	})

	// Initialized notification (no response expected)
	send(rpcMsg{JSONRPC: "2.0", Method: "notifications/initialized"})

	// ── 2. tools/list ────────────────────────────────────────────────────────
	t.Run("tools_list", func(t *testing.T) {
		r := exchange(send, recv, rpcMsg{
			JSONRPC: "2.0", ID: iptr(2), Method: "tools/list", Params: map[string]any{},
		}, perCall)
		if r == nil {
			t.Fatal("no response")
		}
		var list struct {
			Tools []struct{ Name string `json:"name"` } `json:"tools"`
		}
		if err := json.Unmarshal(r.Result, &list); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		t.Logf("registered tools: %d", len(list.Tools))
		if len(list.Tools) < 32 {
			t.Errorf("got %d tools, want >= 32", len(list.Tools))
		}
		need := []string{
			"discover_assets", "agent_record", "flight_export",
			"khepra_query_stig", "khepra_get_dag_chain",
			"nist_map", "dag_attestation", "acp_status",
			"nhi_inventory", "khepra_query_threat_intel",
			"owasp_agent_assess", "dark_crypto_contribute",
			"pqc_stig",
		}
		have := map[string]bool{}
		for _, tool := range list.Tools {
			have[tool.Name] = true
		}
		for _, name := range need {
			if !have[name] {
				t.Errorf("missing required tool: %s", name)
			}
		}
	})

	// ── 3. nist_map ──────────────────────────────────────────────────────────
	t.Run("nist_map", func(t *testing.T) {
		res, err := toolResult(ex(3, "nist_map", map[string]any{
			"query": "post-quantum cryptography", "top_k": 3,
		}))
		if err != nil {
			t.Fatalf("nist_map: %v", err)
		}
		t.Logf("OK — index_size=%v", res["index_size"])
	})

	// ── 4. khepra_query_stig ─────────────────────────────────────────────────
	t.Run("khepra_query_stig", func(t *testing.T) {
		res, err := toolResult(ex(4, "khepra_query_stig", map[string]any{
			"control_id": "CCI-000001",
		}))
		if err != nil {
			t.Fatalf("khepra_query_stig: %v", err)
		}
		t.Logf("OK — result keys: %v", keys(res))
	})

	// ── 5. agent_record ──────────────────────────────────────────────────────
	t.Run("agent_record", func(t *testing.T) {
		r5 := ex(5, "agent_record", map[string]any{
			"action":   "e2e_test_run",
			"agent_id": "khepra-e2e",
		})
		if r5 != nil {
			t.Logf("raw agent_record result (first 400 chars): %.400s", string(r5.Result))
		}
		res, err := toolResult(r5)
		if err != nil {
			t.Fatalf("agent_record: %v", err)
		}
		if recorded, _ := res["recorded"].(bool); !recorded {
			t.Errorf("recorded=false want true")
		}
		if id, _ := res["record_id"].(string); id == "" {
			t.Errorf("missing record_id")
		}
		t.Logf("OK — record_id=%v mode=%v", res["record_id"], res["mode"])
	})

	// ── 6. flight_export ─────────────────────────────────────────────────────
	t.Run("flight_export", func(t *testing.T) {
		res, err := toolResult(ex(6, "flight_export", map[string]any{}))
		if err != nil {
			t.Fatalf("flight_export: %v", err)
		}
		t.Logf("OK — chain_intact=%v total_actions=%v", res["chain_intact"], res["total_actions"])
	})

	// ── 7. dag_attestation ───────────────────────────────────────────────────
	t.Run("dag_attestation", func(t *testing.T) {
		res, err := toolResult(ex(7, "dag_attestation", map[string]any{}))
		if err != nil {
			t.Fatalf("dag_attestation: %v", err)
		}
		t.Logf("OK — node_count=%v", res["node_count"])
	})

	// ── 8. khepra_get_dag_chain ──────────────────────────────────────────────
	t.Run("khepra_get_dag_chain", func(t *testing.T) {
		r8 := ex(8, "khepra_get_dag_chain", map[string]any{})
		if r8 != nil {
			t.Logf("raw dag_chain result (first 300 chars): %.300s", string(r8.Result))
		}
		res, err := toolResult(r8)
		if err != nil {
			t.Fatalf("khepra_get_dag_chain: %v", err)
		}
		if _, ok := res["integrity"]; !ok {
			t.Errorf("missing integrity field: %v", res)
		}
		t.Logf("OK — integrity=%v node_count=%v", res["integrity"], res["node_count"])
	})

	// ── 9. nhi_inventory ──────────────────────────────────────────────────────
	t.Run("nhi_inventory", func(t *testing.T) {
		_, err := toolResult(ex(9, "nhi_inventory", map[string]any{}))
		if err != nil {
			if isLicenseError(err) {
				t.Skipf("enterprise feature (community build): %v", err)
			}
			t.Fatalf("nhi_inventory: %v", err)
		}
		t.Log("OK")
	})

	// ── 10. acp_status ────────────────────────────────────────────────────────────
	t.Run("acp_status", func(t *testing.T) {
		_, err := toolResult(ex(10, "acp_status", map[string]any{}))
		if err != nil {
			if isLicenseError(err) {
				t.Skipf("enterprise feature (community build): %v", err)
			}
			t.Fatalf("acp_status: %v", err)
		}
		t.Log("OK")
	})

	// ── 11. khepra_query_threat_intel ────────────────────────────────────────
	t.Run("khepra_query_threat_intel", func(t *testing.T) {
		_, err := toolResult(ex(11, "khepra_query_threat_intel", map[string]any{
			"query": "remote code execution",
		}))
		if err != nil {
			t.Fatalf("khepra_query_threat_intel: %v", err)
		}
		t.Log("OK")
	})

	// ── 12. owasp_agent_assess ───────────────────────────────────────────────
	t.Run("owasp_agent_assess", func(t *testing.T) {
		r12 := ex(12, "owasp_agent_assess", map[string]any{"profile": "full"})
		if r12 != nil {
			t.Logf("raw owasp result (first 400 chars): %.400s", string(r12.Result))
		} else {
			t.Logf("owasp_agent_assess: nil response (tool may not be registered)")
		}
		res, err := toolResult(r12)
		t.Logf("toolResult parsed: %v | err: %v", res, err)
		if err != nil {
			t.Fatalf("owasp_agent_assess: %v", err)
		}
		if std, _ := res["standard"].(string); std != "OWASP Agentic Top 10" {
			t.Errorf("standard=%q want %q", std, "OWASP Agentic Top 10")
		}
		if n, _ := res["total_risks"].(float64); n != 10 {
			t.Errorf("total_risks=%v want 10", n)
		}
		findings, _ := res["findings"].([]any)
		if len(findings) != 10 {
			t.Errorf("findings count=%d want 10", len(findings))
		}
		composite, _ := res["composite_score"].(float64)
		t.Logf("OK — composite_score=%.0f mitigated=%v partial=%v unmitigated=%v",
			composite, res["mitigated"], res["partial"], res["unmitigated"])
	})

	// ── 13. dark_crypto_contribute ────────────────────────────────────────────
	// Community tier — no license key needed. Uses self-attestation mode
	// (KHEPRA's own crypto inventory) since no findings are provided.
	// Works offline: returns a queued receipt if nouchix.ai is unreachable.
	t.Run("dark_crypto_contribute", func(t *testing.T) {
		res, err := toolResult(ex(13, "dark_crypto_contribute", map[string]any{}))
		if err != nil {
			t.Fatalf("dark_crypto_contribute: %v", err)
		}
		if id, _ := res["contribution_id"].(string); id == "" {
			t.Errorf("missing contribution_id")
		}
		algos, _ := res["algorithms_catalogued"].(float64)
		if algos == 0 {
			t.Errorf("algorithms_catalogued=0 want >0")
		}
		privacyGuarantees, _ := res["privacy_guarantees"].([]any)
		if len(privacyGuarantees) == 0 {
			t.Errorf("missing privacy_guarantees")
		}
		t.Logf("OK — contribution_id=%v algorithms_catalogued=%v risk=%v offline=%v",
			res["contribution_id"], res["algorithms_catalogued"],
			res["quantum_risk_level"], res["offline"])
	})

	// ── 14. pqc_stig ─────────────────────────────────────────────────────────
	// Community tier — World's First DoD PQC STIG (PQC-01-STIG-V1R1).
	// Target: pkg/mcp/tools — small dir with known PQC references (ML-DSA-65,
	// ML-KEM-768 in dark_crypto_contribute.go). Full-project scan belongs in
	// slow_integration_test.go (--timeout 10m).
	t.Run("pqc_stig", func(t *testing.T) {
		res, err := toolResult(ex(14, "pqc_stig", map[string]any{
			"scan_path": "pkg/mcp/tools",
			"profile":   "quick",
		}))
		if err != nil {
			t.Fatalf("pqc_stig: %v", err)
		}
		if std, _ := res["standard"].(string); std != "PQC-01-STIG-V1R1" {
			t.Errorf("standard=%q want %q", std, "PQC-01-STIG-V1R1")
		}
		if n, _ := res["total_controls"].(float64); n == 0 {
			t.Errorf("total_controls=0 want >0")
		}
		if _, ok := res["compliance_score"]; !ok {
			t.Errorf("missing compliance_score field")
		}
		t.Logf("OK — standard=%v score=%.0f verdict=%v cat1_fail=%v cat2_fail=%v",
			res["standard"], res["compliance_score"],
			res["verdict"], res["cat1_fail"], res["cat2_fail"])
	})
}

// keys returns the map keys as a sorted slice for logging.
func keys(m map[string]any) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	return ks
}

// isLicenseError returns true when the tool error is an enterprise license gate.
// These tools exist in the manifest but require a paid tier — treated as Skip
// rather than Fail in community/CI builds.
func isLicenseError(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "enterprise tier") ||
		strings.Contains(s, "license") ||
		strings.Contains(s, "upgrade at") ||
		strings.Contains(s, "requires enterprise")
}
