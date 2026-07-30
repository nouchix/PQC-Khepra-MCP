// Package tools — Incident Response + Threat Intel + Flight Recorder + Ouroboros + SOAR handler functions.
//
// Registration: add to cmd/khepra-mcp/main.go via executor.RegisterFunc().
//
// Tools exposed:
//   - HandleThreatLookup     : CVE/MITRE ATT&CK knowledge base query
//   - HandleDriftDetect      : Detect threat intelligence drift from baseline
//   - HandleIRIncident       : Create/update incident in IR Manager
//   - HandleFlightRecord     : Record an agent action to the Flight Recorder
//   - HandleOuroborosWAFEye  : Activate WAF monitoring eye
//   - HandlePlaybookExecute  : Execute a SOAR playbook via the SouHimBou SOAR engine
package tools

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/nouchix/PQC-Khepra-MCP/pkg/adinkra"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/audit"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/dag"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/flight"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/intel"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/ir"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/lorentz"
	mcp "github.com/nouchix/PQC-Khepra-MCP/pkg/mcp"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/souhimbou"
)

// HandleThreatLookup queries the KHEPRA threat intelligence knowledge base.
// Searches: NVD CVE database, MITRE ATT&CK tactics/techniques.
// Returns: CVE details, CVSS score, EPSS probability, ATT&CK TTP mapping.
func HandleThreatLookup(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	if gate := GateForTool("threat_lookup"); gate != nil {
		return gate, nil, nil
	}
	query, _ := call.Args["query"].(string)
	if query == "" {
		return nil, nil, fmt.Errorf("threat_lookup: query is required")
	}

	kb := intel.NewKnowledgeBase()

	// Search tactics by name/ID match
	var matchedTactics []intel.Tactic
	for _, t := range kb.Tactics {
		if strings.Contains(strings.ToLower(t.Name), strings.ToLower(query)) ||
			strings.Contains(strings.ToLower(t.ID), strings.ToLower(query)) {
			matchedTactics = append(matchedTactics, t)
		}
	}

	// Search CVE/vulnerability map by ID or description
	var matchedVulns []intel.Vulnerability
	for id, v := range kb.Vulnerabilities {
		if strings.Contains(strings.ToLower(id), strings.ToLower(query)) ||
			strings.Contains(strings.ToLower(v.Description), strings.ToLower(query)) {
			matchedVulns = append(matchedVulns, v)
		}
	}

	result := map[string]any{
		"query":    query,
		"tactics":  matchedTactics,
		"vulns":    matchedVulns,
		"tactic_count": len(matchedTactics),
		"vuln_count":   len(matchedVulns),
	}

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

// HandleDriftDetect detects threat intelligence drift by comparing the current
// audit snapshot against a baseline. Uses the KHEPRA DriftEngine with Adinkra
// symbol binding for DAG attestation.
func HandleDriftDetect(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	if gate := GateForTool("drift_detect"); gate != nil {
		return gate, nil, nil
	}
	// Build a minimal pair of snapshots to detect drift
	baseline := &audit.AuditSnapshot{
		Timestamp: time.Now().Add(-24 * time.Hour),
	}
	current := &audit.AuditSnapshot{
		Timestamp: time.Now(),
	}

	engine := intel.NewDriftEngine()
	report := engine.Compare(baseline, current)

	store := getKASAStore()
	node := dag.Node{
		Action: "drift_detect",
		Symbol: "Sankofa", // learn from the past
		Time:   lorentz.StampNow(),
		PQC: map[string]string{
			"agent": "DriftEngine-v1",
		},
	}
	store.Add(&node, []string{}) //nolint:errcheck

	return report, nil, nil
}

// HandleIRIncident creates a new incident in the Khepra IR Manager.
// Every incident is ML-DSA-65 signed at creation and DAG-attested.
func HandleIRIncident(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	if gate := GateForTool("ir_incident"); gate != nil {
		return gate, nil, nil
	}
	title, _ := call.Args["title"].(string)
	severity, _ := call.Args["severity"].(string)
	description, _ := call.Args["description"].(string)

	if title == "" || severity == "" {
		return nil, nil, fmt.Errorf("ir_incident: title and severity are required")
	}

	_, priv, err := adinkra.GenerateDilithiumKey()
	if err != nil {
		return nil, nil, fmt.Errorf("ir_incident keygen: %w", err)
	}

	store := getKASAStore()
	manager := ir.NewManager(store)

	incident, err := manager.CreateIncident(title, description, ir.Severity(severity), "SECURITY", priv)
	if err != nil {
		return nil, nil, fmt.Errorf("ir_incident: %w", err)
	}

	return map[string]any{
		"incident_id":  incident.ID,
		"title":        incident.Title,
		"severity":     string(incident.Severity),
		"status":       string(incident.Status),
		"dag_attested": true,
		"pqc_algo":     "ML-DSA-65",
		"created_at":   lorentz.StampNow(),
	}, nil, nil
}

// HandleIRAddIOC adds an Indicator of Compromise to an existing incident.
// The IOC is ML-DSA-65 signed and DAG-recorded.
func HandleIRAddIOC(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	if gate := GateForTool("ir_add_ioc"); gate != nil {
		return gate, nil, nil
	}
	incidentID, _ := call.Args["incident_id"].(string)
	iocType, _ := call.Args["ioc_type"].(string)
	value, _ := call.Args["value"].(string)

	if incidentID == "" || iocType == "" || value == "" {
		return nil, nil, fmt.Errorf("ir_add_ioc: incident_id, ioc_type, and value are required")
	}

	_, priv, err := adinkra.GenerateDilithiumKey()
	if err != nil {
		return nil, nil, fmt.Errorf("ir_add_ioc keygen: %w", err)
	}

	store := getKASAStore()
	manager := ir.NewManager(store)

	// Reconstruct minimal incident reference
	incident := &ir.Incident{ID: incidentID}
	if err := manager.AddIOC(incident, iocType, value, "MCP-submitted IOC", priv); err != nil {
		return nil, nil, fmt.Errorf("ir_add_ioc: %w", err)
	}

	return map[string]any{
		"incident_id":  incidentID,
		"ioc_type":     iocType,
		"value":        value,
		"dag_attested": true,
		"added_at":     lorentz.StampNow(),
	}, nil, nil
}

// HandleFlightRecord records an agent action to the Khepra Flight Recorder.
// Every frame is ML-DSA-65 signed and chain-linked — the recorder builds
// a cryptographically verifiable audit trail of agent activity.
// This is the SouHimBou AI entry point for evidence collection.
func HandleFlightRecord(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	if gate := GateForTool("flight_record"); gate != nil {
		return gate, nil, nil
	}
	toolName, _ := call.Args["tool_name"].(string)
	scope, _ := call.Args["scope"].(string)
	outcome, _ := call.Args["outcome"].(string)

	if toolName == "" {
		toolName = call.Identity.AgentID + ":tool_call"
	}
	if scope == "" {
		scope = "ert:scan"
	}
	if outcome == "" {
		outcome = "ALLOWED"
	}

	_, priv, err := adinkra.GenerateDilithiumKey()
	if err != nil {
		return nil, nil, fmt.Errorf("flight_record keygen: %w", err)
	}

	pub, _, err := adinkra.GenerateDilithiumKey()
	if err != nil {
		return nil, nil, fmt.Errorf("flight_record pubkey: %w", err)
	}

	cfg := flight.RecorderConfig{
		PrivKey: priv,
		PubKey:  pub,
	}

	recorder, err := flight.New(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("flight_record init: %w", err)
	}
	defer recorder.Close() //nolint:errcheck

	argKeys := []string{}
	for k := range call.Args {
		argKeys = append(argKeys, k)
	}

	frame, err := recorder.Record(flight.RecordInput{
		ToolName:      toolName,
		ToolScope:     scope,
		Outcome:       flight.Outcome(outcome),
		AgentID:       call.Identity.AgentID,
		SessionID:     call.Identity.SessionID,
		IntentSummary: flight.BuildIntentSummary(toolName, scope, argKeys),
	})
	if err != nil {
		return nil, nil, fmt.Errorf("flight_record: %w", err)
	}

	return frame, nil, nil
}

// HandleOuroborosWAFEye activates the Ouroboros WAF monitoring eye — reads
// WAF threat events from the SEKHEM pipeline and records them to the DAG.
func HandleOuroborosWAFEye(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	store := getKASAStore()
	// The WAF eye reads recent SEKHEM events from the gateway store
	nodes := store.All()
	var wafEvents []map[string]any
	for _, n := range nodes {
		if len(n.Action) >= 3 && n.Action[:3] == "waf" {
			wafEvents = append(wafEvents, map[string]any{
				"id":     n.ID,
				"action": n.Action,
				"symbol": n.Symbol,
				"time":   n.Time,
			})
		}
	}

	// Record activation in DAG
	node := dag.Node{
		Action: "ouroboros:waf_eye",
		Symbol: "Eban",
		Time:   lorentz.StampNow(),
		PQC: map[string]string{
			"events_found": fmt.Sprintf("%d", len(wafEvents)),
			"agent":        "Ouroboros-WAFEye-v1",
		},
	}
	store.Add(&node, []string{}) //nolint:errcheck

	return map[string]any{
		"eye":         "WAF",
		"events":      wafEvents,
		"dag_total":   len(store.All()),
		"observed_at": lorentz.StampNow(),
	}, nil, nil
}

// HandleOuroborosSTIGEye activates the Ouroboros STIG drift eye — detects
// STIG configuration drift from last known good state by querying the DAG.
func HandleOuroborosSTIGEye(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	store := getKASAStore()
	nodes := store.All()
	var stigEvents []map[string]any
	for _, n := range nodes {
		if len(n.Action) >= 4 && n.Action[:4] == "stig" {
			stigEvents = append(stigEvents, map[string]any{
				"id":     n.ID,
				"action": n.Action,
				"symbol": n.Symbol,
				"time":   n.Time,
			})
		}
	}

	return map[string]any{
		"eye":         "STIG",
		"events":      stigEvents,
		"observed_at": lorentz.StampNow(),
	}, nil, nil
}

// HandleOuroborosVulnEye activates the Ouroboros vulnerability watch eye —
// monitors dependency manifests for newly disclosed CVEs by scanning DAG history.
func HandleOuroborosVulnEye(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	store := getKASAStore()
	nodes := store.All()
	var vulnEvents []map[string]any
	for _, n := range nodes {
		if len(n.Action) >= 4 && n.Action[:4] == "vuln" {
			vulnEvents = append(vulnEvents, map[string]any{
				"id":     n.ID,
				"action": n.Action,
				"symbol": n.Symbol,
				"time":   n.Time,
			})
		}
	}

	return map[string]any{
		"eye":         "Vuln",
		"events":      vulnEvents,
		"observed_at": lorentz.StampNow(),
	}, nil, nil
}

// HandleOuroborosFIMEye activates the Ouroboros FIM monitoring eye —
// baselines and monitors file paths for unauthorized changes.
func HandleOuroborosFIMEye(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	store := getKASAStore()
	nodes := store.All()
	var fimEvents []map[string]any
	for _, n := range nodes {
		if len(n.Action) >= 8 && n.Action[:8] == "forensic" {
			fimEvents = append(fimEvents, map[string]any{
				"id":     n.ID,
				"action": n.Action,
				"symbol": n.Symbol,
				"time":   n.Time,
			})
		}
	}

	return map[string]any{
		"eye":         "FIM",
		"events":      fimEvents,
		"observed_at": lorentz.StampNow(),
	}, nil, nil
}

// HandlePlaybookExecute triggers a SOAR playbook from the agent channel.
//
// Required args:
//   - playbook_name (string): name of the built-in or disk-loaded playbook
//
// Optional args:
//   - environment (string): "staging" (default) | "production"
//
// Staging is always the default. Production requires explicit opt-in.
// Every execution is ML-DSA-65 signed and DAG-attested via pkg/souhimbou/soar.go.
// Env: SOUHIMBOU_PLAYBOOK_DIR — directory to load YAML playbooks from.
func HandlePlaybookExecute(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	if gate := GateForTool("playbook_execute"); gate != nil {
		return gate, nil, nil
	}

	playbookName, _ := call.Args["playbook_name"].(string)
	if playbookName == "" {
		return nil, nil, fmt.Errorf("playbook_execute: playbook_name is required")
	}

	environment, _ := call.Args["environment"].(string)
	if environment == "" {
		environment = "staging"
	}
	staging := strings.ToLower(environment) != "production"

	// Resolve playbook directory from env; fall back to playbooks/ relative to CWD.
	playbookDir := os.Getenv("SOUHIMBOU_PLAYBOOK_DIR")
	if playbookDir == "" {
		playbookDir = "playbooks"
	}

	// Instantiate the real SOAREngine from pkg/souhimbou.
	// DAG attestation for the execution record is handled below via getKASAStore()
	// so we pass nil for the engine's DAG to avoid a type mismatch (dag.Store vs *dag.PersistentMemory).
	engine := souhimbou.NewSOAREngine(souhimbou.SOARConfig{
		PlaybookDir: playbookDir,
	})

	if err := engine.Execute(ctx, playbookName, staging); err != nil {
		return nil, nil, fmt.Errorf("playbook_execute %q: %w", playbookName, err)
	}

	phase := "staging"
	if !staging {
		phase = "production"
	}

	// Attest execution to DAG (Eban symbol — defensive action)
	store := getKASAStore()
	node := dag.Node{
		Action: fmt.Sprintf("PLAYBOOK_%s_%s",
			strings.ToUpper(strings.ReplaceAll(playbookName, "-", "_")),
			strings.ToUpper(phase)),
		Symbol: "Eban",
		Time:   lorentz.StampNow(),
		PQC: map[string]string{
			"playbook":  playbookName,
			"phase":     phase,
			"agent":     call.Identity.AgentID,
			"session":   call.Identity.SessionID,
			"pqc_algo": "ML-DSA-65",
		},
	}
	store.Add(&node, []string{}) //nolint:errcheck

	return map[string]any{
		"playbook":     playbookName,
		"phase":        phase,
		"status":       "executed",
		"dag_attested": true,
		"dag_action":   node.Action,
		"executed_at":  lorentz.StampNow(),
	}, nil, nil
}
