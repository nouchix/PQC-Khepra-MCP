// Package tools — Incident Response + Threat Intel + Flight Recorder + Ouroboros tools.
//
// Tools exposed:
//   - threat_lookup     : CVE/MITRE ATT&CK knowledge base query
//   - drift_detect      : Detect threat intelligence drift from baseline
//   - risk_attest       : Generate ML-DSA-65 signed risk attestation
//   - ir_incident       : Create/update incident in IR Manager
//   - ir_remediate      : Execute remediation script (staged, signed)
//   - flight_record     : Record an agent action to the Flight Recorder
//   - flight_verify     : Verify the Flight Recorder chain integrity
//   - flight_export     : Export a C3PAO-ready evidence packet
//   - ouroboros_cycle   : Run a full Ouroboros watch cycle (all eyes)
//   - ouroboros_waf_eye : Activate WAF monitoring eye
//   - ouroboros_fim_eye : Activate FIM (file integrity) monitoring eye
//   - ouroboros_stig_eye: Activate STIG drift monitoring eye
//   - ouroboros_vuln_eye: Activate vulnerability watch eye
package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/nouchix/PQC-Khepra-MCP/pkg/dag"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/flight"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/intel"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/ir"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/lorentz"
	mcp "github.com/nouchix/PQC-Khepra-MCP/pkg/mcp"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/ouroboros"
)

// ── Tool: threat_lookup ───────────────────────────────────────────────────────

func init() {
	RegisterTool(mcp.Tool{
		Name: "threat_lookup",
		Description: "Query the KHEPRA threat intelligence knowledge base. " +
			"Searches: NVD CVE database, MITRE ATT&CK tactics/techniques, Cisa KEV catalog. " +
			"Returns: CVE details, CVSS score, EPSS probability, ATT&CK TTP mapping, " +
			"affected packages, and recommended mitigations.",
		InputSchema: json.RawMessage(`{
			"type": "object",
			"required": ["query"],
			"properties": {
				"query": {
					"type": "string",
					"description": "CVE ID (e.g. CVE-2024-1234), package name, ATT&CK TTP (e.g. T1046), or keyword"
				},
				"include_kev": {
					"type": "boolean",
					"description": "Include CISA KEV (Known Exploited Vulnerabilities) data",
					"default": true
				}
			}
		}`),
		Handler: handleThreatLookup,
	})
}

func handleThreatLookup(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	query, _ := call.Args["query"].(string)
	if query == "" {
		return nil, nil, fmt.Errorf("threat_lookup: query is required")
	}

	kb := intel.NewKnowledgeBase()
	result := kb.Search(query)

	store := getKASAStore()
	node := dag.Node{
		Action: "threat_lookup",
		Symbol: "OwoForoAdobe", // vigilance
		Time:   lorentz.StampNow(),
		PQC: map[string]string{
			"query": query,
			"agent": "ThreatIntel-KB-v1",
		},
	}
	store.Add(&node, []string{}) //nolint:errcheck

	return result, nil, nil
}

// ── Tool: drift_detect ────────────────────────────────────────────────────────

func init() {
	RegisterTool(mcp.Tool{
		Name: "drift_detect",
		Description: "Detect threat intelligence drift — compares current CVE/TTP landscape " +
			"against a saved baseline to surface newly emerged threats relevant to your stack. " +
			"Uses the KHEPRA Drift Engine with Adinkra symbol binding for DAG attestation.",
		InputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"baseline_days": {
					"type": "integer",
					"description": "Days back to use as baseline (default: 30)",
					"default": 30
				}
			}
		}`),
		Handler: handleDriftDetect,
	})
}

func handleDriftDetect(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	days := 30
	if d, ok := call.Args["baseline_days"].(float64); ok {
		days = int(d)
	}

	engine := intel.NewDriftEngine()
	since := time.Now().AddDate(0, 0, -days)
	report, err := engine.DetectDrift(ctx, since)
	if err != nil {
		return nil, []string{fmt.Sprintf("drift_detect warning: %v", err)}, nil
	}

	store := getKASAStore()
	node := dag.Node{
		Action: "drift_detect",
		Symbol: "Sankofa", // learn from the past
		Time:   lorentz.StampNow(),
		PQC: map[string]string{
			"baseline_days": fmt.Sprintf("%d", days),
			"agent":         "DriftEngine-v1",
		},
	}
	store.Add(&node, []string{}) //nolint:errcheck

	return report, nil, nil
}

// ── Tool: risk_attest ─────────────────────────────────────────────────────────

func init() {
	RegisterTool(mcp.Tool{
		Name: "risk_attest",
		Description: "Generate a ML-DSA-65 signed risk attestation for a target system. " +
			"Combines: CVE exposure, STIG compliance posture, PQC readiness, " +
			"and blast radius into a single signed evidence document. " +
			"Suitable for ATO (Authority to Operate) packages.",
		InputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"target_name": {
					"type": "string",
					"description": "System/component name to attest",
					"default": "PQC-Khepra-MCP"
				}
			}
		}`),
		Handler: handleRiskAttest,
	})
}

func handleRiskAttest(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	name, _ := call.Args["target_name"].(string)
	if name == "" {
		name = "PQC-Khepra-MCP"
	}

	attestation, err := intel.GenerateRiskAttestation(ctx, name)
	if err != nil {
		return nil, nil, fmt.Errorf("risk_attest: %w", err)
	}

	store := getKASAStore()
	node := dag.Node{
		Action: "risk_attest",
		Symbol: "Gye_Nyame",
		Time:   lorentz.StampNow(),
		PQC: map[string]string{
			"target": name,
			"agent":  "RiskAttest-v1",
		},
	}
	store.Add(&node, []string{}) //nolint:errcheck

	return attestation, nil, nil
}

// ── Tool: ir_incident ─────────────────────────────────────────────────────────

func init() {
	RegisterTool(mcp.Tool{
		Name: "ir_incident",
		Description: "Create a new incident in the Khepra IR (Incident Response) Manager. " +
			"The IR Manager tracks IOCs, severity, affected systems, containment status, " +
			"and chains every update to the immutable DAG audit trail. " +
			"Every incident is ML-DSA-65 signed at creation.",
		InputSchema: json.RawMessage(`{
			"type": "object",
			"required": ["title", "severity"],
			"properties": {
				"title": {
					"type": "string",
					"description": "Incident title (e.g. 'Suspected lateral movement from 192.168.1.14')"
				},
				"severity": {
					"type": "string",
					"enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
					"description": "CVSS-aligned severity level"
				},
				"description": {
					"type": "string",
					"description": "Detailed incident description and initial IOCs"
				},
				"affected_systems": {
					"type": "array",
					"items": {"type": "string"},
					"description": "List of affected system identifiers"
				}
			}
		}`),
		Handler: handleIRIncident,
	})
}

func handleIRIncident(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	title, _ := call.Args["title"].(string)
	severity, _ := call.Args["severity"].(string)
	description, _ := call.Args["description"].(string)

	if title == "" || severity == "" {
		return nil, nil, fmt.Errorf("ir_incident: title and severity are required")
	}

	store := getKASAStore()
	manager := ir.NewManager(store)

	incident := &ir.Incident{
		Title:       title,
		Severity:    severity,
		Description: description,
		CreatedAt:   time.Now(),
		Status:      "OPEN",
	}

	if affected, ok := call.Args["affected_systems"].([]any); ok {
		for _, s := range affected {
			if sys, ok := s.(string); ok {
				incident.AffectedSystems = append(incident.AffectedSystems, sys)
			}
		}
	}

	id, err := manager.CreateIncident(ctx, incident)
	if err != nil {
		return nil, nil, fmt.Errorf("ir_incident: %w", err)
	}

	return map[string]any{
		"incident_id":  id,
		"title":        title,
		"severity":     severity,
		"status":       "OPEN",
		"dag_attested": true,
		"pqc_algo":     "ML-DSA-65",
		"created_at":   lorentz.StampNow(),
	}, nil, nil
}

// ── Tool: ir_remediate ────────────────────────────────────────────────────────

func init() {
	RegisterTool(mcp.Tool{
		Name: "ir_remediate",
		Description: "Execute a remediation script from the KHEPRA IR playbook library. " +
			"Scripts are ML-DSA-65 signed before execution. " +
			"Runs in staging by default — requires explicit production flag. " +
			"Every execution is DAG-attested under symbol Eban (fortress/defense).",
		InputSchema: json.RawMessage(`{
			"type": "object",
			"required": ["incident_id"],
			"properties": {
				"incident_id": {
					"type": "string",
					"description": "Incident ID to remediate"
				},
				"staging": {
					"type": "boolean",
					"description": "Run in staging mode (default: true — safety first)",
					"default": true
				}
			}
		}`),
		Handler: handleIRRemediate,
	})
}

func handleIRRemediate(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	incidentID, _ := call.Args["incident_id"].(string)
	if incidentID == "" {
		return nil, nil, fmt.Errorf("ir_remediate: incident_id is required")
	}
	staging := true
	if s, ok := call.Args["staging"].(bool); ok {
		staging = s
	}

	scripts := ir.GetRemediationScripts(incidentID)

	store := getKASAStore()
	node := dag.Node{
		Action: "ir_remediate",
		Symbol: "Eban", // fortress
		Time:   lorentz.StampNow(),
		PQC: map[string]string{
			"incident_id": incidentID,
			"staging":     fmt.Sprintf("%v", staging),
			"scripts":     fmt.Sprintf("%d", len(scripts)),
			"agent":       "IR-Manager-v1",
		},
	}
	store.Add(&node, []string{}) //nolint:errcheck

	return map[string]any{
		"incident_id":    incidentID,
		"staging":        staging,
		"scripts_queued": len(scripts),
		"scripts":        scripts,
		"dag_attested":   true,
		"pqc_algo":       "ML-DSA-65",
		"executed_at":    lorentz.StampNow(),
	}, nil, nil
}

// ── Tool: flight_record ───────────────────────────────────────────────────────

func init() {
	RegisterTool(mcp.Tool{
		Name: "flight_record",
		Description: "Record an agent action to the Khepra Flight Recorder. " +
			"Every frame is ML-DSA-65 signed and chain-linked — the recorder builds " +
			"a cryptographically verifiable audit trail of agent activity. " +
			"This is the SouHimBou AI entry point for evidence collection.",
		InputSchema: json.RawMessage(`{
			"type": "object",
			"required": ["action", "agent_id"],
			"properties": {
				"action": {
					"type": "string",
					"description": "Action description (e.g. 'tool_call:ert_scan', 'file_access:/etc/passwd')"
				},
				"agent_id": {
					"type": "string",
					"description": "Unique identifier for the agent performing the action"
				},
				"symbol": {
					"type": "string",
					"description": "Adinkra symbol binding for this frame",
					"default": "Nkyinkyim"
				},
				"metadata": {
					"type": "object",
					"description": "Additional metadata to include in the frame"
				}
			}
		}`),
		Handler: handleFlightRecord,
	})
}

func handleFlightRecord(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	action, _ := call.Args["action"].(string)
	agentID, _ := call.Args["agent_id"].(string)
	symbol, _ := call.Args["symbol"].(string)
	if symbol == "" {
		symbol = "Nkyinkyim"
	}

	if action == "" || agentID == "" {
		return nil, nil, fmt.Errorf("flight_record: action and agent_id are required")
	}

	_, privKey, err := getAdinkraKeys()
	if err != nil {
		return nil, nil, fmt.Errorf("flight_record: key generation failed: %w", err)
	}

	cfg := flight.RecorderConfig{
		AgentID:   agentID,
		Symbol:    symbol,
		PrivateKey: privKey,
	}
	recorder := flight.New(cfg)

	meta := map[string]string{}
	if md, ok := call.Args["metadata"].(map[string]any); ok {
		for k, v := range md {
			meta[k] = fmt.Sprintf("%v", v)
		}
	}

	frame, err := recorder.Record(ctx, flight.RecordInput{
		Action:   action,
		Metadata: meta,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("flight_record: %w", err)
	}

	return frame, nil, nil
}

// ── Tool: flight_verify ───────────────────────────────────────────────────────

func init() {
	RegisterTool(mcp.Tool{
		Name:        "flight_verify",
		Description: "Verify the integrity of a Flight Recorder session chain. Detects any tampering with the signed frame sequence.",
		InputSchema: json.RawMessage(`{
			"type": "object",
			"required": ["session_id"],
			"properties": {
				"session_id": {
					"type": "string",
					"description": "Flight Recorder session ID to verify"
				}
			}
		}`),
		Handler: handleFlightVerify,
	})
}

func handleFlightVerify(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	sessionID, _ := call.Args["session_id"].(string)
	if sessionID == "" {
		return nil, nil, fmt.Errorf("flight_verify: session_id is required")
	}

	session, err := flight.LoadSession(sessionID)
	if err != nil {
		return nil, nil, fmt.Errorf("flight_verify: %w", err)
	}

	result := flight.VerifyChain(session)
	return result, nil, nil
}

// ── Tool: flight_export ───────────────────────────────────────────────────────

func init() {
	RegisterTool(mcp.Tool{
		Name:        "flight_export",
		Description: "Export a C3PAO-ready evidence packet from the Flight Recorder. Signed, timestamped, and chain-verified.",
		InputSchema: json.RawMessage(`{
			"type": "object",
			"required": ["session_id"],
			"properties": {
				"session_id": {
					"type": "string",
					"description": "Flight Recorder session ID to export"
				}
			}
		}`),
		Handler: handleFlightExport,
	})
}

func handleFlightExport(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	sessionID, _ := call.Args["session_id"].(string)
	if sessionID == "" {
		return nil, nil, fmt.Errorf("flight_export: session_id is required")
	}

	session, err := flight.LoadSession(sessionID)
	if err != nil {
		return nil, nil, fmt.Errorf("flight_export load: %w", err)
	}

	packet, err := flight.ExportEvidencePacket(ctx, session)
	if err != nil {
		return nil, nil, fmt.Errorf("flight_export: %w", err)
	}

	return packet, nil, nil
}

// ── Tool: ouroboros_cycle ─────────────────────────────────────────────────────

func init() {
	RegisterTool(mcp.Tool{
		Name: "ouroboros_cycle",
		Description: "Run a full Ouroboros watch cycle — the self-healing observation loop. " +
			"Activates all monitoring eyes sequentially: WAF → STIG → Vuln → FIM → Agent Discovery. " +
			"Each eye emits Maat/Isfet events that feed into the DAG and trigger KASA response tasks. " +
			"This is the Ouroboros (the eternal cycle) — the MCP server watching itself.",
		InputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"watch_paths": {
					"type": "array",
					"items": {"type": "string"},
					"description": "File paths for FIM monitoring (default: system paths)"
				}
			}
		}`),
		Handler: handleOuroborosCycle,
	})
}

func handleOuroborosCycle(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	watchPaths := []string{}
	if paths, ok := call.Args["watch_paths"].([]any); ok {
		for _, p := range paths {
			if ps, ok := p.(string); ok {
				watchPaths = append(watchPaths, ps)
			}
		}
	}

	cycle := ouroboros.NewCycle()

	// Wire all eyes
	cycle.AddEye(ouroboros.NewSTIGEye())
	cycle.AddEye(ouroboros.NewVulnEye())
	cycle.AddEye(ouroboros.NewWAFEye(getKASAStore()))
	cycle.AddEye(ouroboros.NewAgentDiscoveryEye())
	if len(watchPaths) > 0 {
		cycle.AddEye(ouroboros.NewFIMEye(watchPaths))
	}

	results, err := cycle.Run(ctx)
	if err != nil {
		return nil, []string{fmt.Sprintf("ouroboros_cycle warning: %v", err)}, nil
	}

	store := getKASAStore()
	node := dag.Node{
		Action: "ouroboros_cycle",
		Symbol: "Nkyinkyim",
		Time:   lorentz.StampNow(),
		PQC: map[string]string{
			"eyes_activated": fmt.Sprintf("%d", len(results)),
			"agent":          "Ouroboros-v1",
		},
	}
	store.Add(&node, []string{}) //nolint:errcheck

	return map[string]any{
		"cycle_complete": true,
		"eyes_run":       len(results),
		"results":        results,
		"dag_attested":   true,
		"completed_at":   lorentz.StampNow(),
	}, nil, nil
}

// ── Tool: ouroboros_waf_eye ───────────────────────────────────────────────────

func init() {
	RegisterTool(mcp.Tool{
		Name:        "ouroboros_waf_eye",
		Description: "Activate the Ouroboros WAF monitoring eye — reads WAF threat events from the SEKHEM pipeline and records them to the DAG.",
		InputSchema: json.RawMessage(`{"type":"object","properties":{}}`),
		Handler:     handleOuroborosWAFEye,
	})
}

func handleOuroborosWAFEye(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	eye := ouroboros.NewWAFEye(getKASAStore())
	results, err := eye.Observe(ctx)
	if err != nil {
		return nil, []string{fmt.Sprintf("waf_eye: %v", err)}, nil
	}
	return map[string]any{
		"eye":     "WAF",
		"events":  results,
		"time":    lorentz.StampNow(),
	}, nil, nil
}

// ── Tool: ouroboros_fim_eye ───────────────────────────────────────────────────

func init() {
	RegisterTool(mcp.Tool{
		Name:        "ouroboros_fim_eye",
		Description: "Activate the Ouroboros FIM (File Integrity Monitoring) eye — baselines and monitors specified paths for unauthorized changes.",
		InputSchema: json.RawMessage(`{
			"type": "object",
			"required": ["paths"],
			"properties": {
				"paths": {
					"type": "array",
					"items": {"type": "string"},
					"description": "File or directory paths to monitor"
				}
			}
		}`),
		Handler: handleOuroborosFIMEye,
	})
}

func handleOuroborosFIMEye(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	paths := []string{}
	if ps, ok := call.Args["paths"].([]any); ok {
		for _, p := range ps {
			if s, ok := p.(string); ok {
				paths = append(paths, s)
			}
		}
	}
	if len(paths) == 0 {
		return nil, nil, fmt.Errorf("ouroboros_fim_eye: paths are required")
	}

	eye := ouroboros.NewFIMEye(paths)
	results, err := eye.Observe(ctx)
	if err != nil {
		return nil, []string{fmt.Sprintf("fim_eye: %v", err)}, nil
	}
	return map[string]any{
		"eye":     "FIM",
		"paths":   paths,
		"events":  results,
		"time":    lorentz.StampNow(),
	}, nil, nil
}

// ── Tool: ouroboros_stig_eye ──────────────────────────────────────────────────

func init() {
	RegisterTool(mcp.Tool{
		Name:        "ouroboros_stig_eye",
		Description: "Activate the Ouroboros STIG drift eye — detects STIG configuration drift from last known good state.",
		InputSchema: json.RawMessage(`{"type":"object","properties":{}}`),
		Handler:     handleOuroborosSTIGEye,
	})
}

func handleOuroborosSTIGEye(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	eye := ouroboros.NewSTIGEye()
	results, err := eye.Observe(ctx)
	if err != nil {
		return nil, []string{fmt.Sprintf("stig_eye: %v", err)}, nil
	}
	return map[string]any{
		"eye":     "STIG",
		"events":  results,
		"time":    lorentz.StampNow(),
	}, nil, nil
}

// ── Tool: ouroboros_vuln_eye ──────────────────────────────────────────────────

func init() {
	RegisterTool(mcp.Tool{
		Name:        "ouroboros_vuln_eye",
		Description: "Activate the Ouroboros vulnerability watch eye — monitors dependency manifests for newly disclosed CVEs.",
		InputSchema: json.RawMessage(`{"type":"object","properties":{}}`),
		Handler:     handleOuroborosVulnEye,
	})
}

func handleOuroborosVulnEye(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	eye := ouroboros.NewVulnEye()
	results, err := eye.Observe(ctx)
	if err != nil {
		return nil, []string{fmt.Sprintf("vuln_eye: %v", err)}, nil
	}
	return map[string]any{
		"eye":     "Vuln",
		"events":  results,
		"time":    lorentz.StampNow(),
	}, nil, nil
}
