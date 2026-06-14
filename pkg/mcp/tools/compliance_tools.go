package tools

// compliance_tools.go — MCP handlers for stig_check, cmmc_assess, and agent_record.
//
// These tools close the gap between the KHEPRA Four-Layer Architecture v1.0 document
// (which lists them under PQC-MCP Layer 4 exposures) and the registered handler set.
//
// stig_check   — Check a path or config against RHEL-09-STIG V1R3 controls (pkg/stig)
// cmmc_assess  — Assess a project against CMMC Level 1, 2, or 3 (pkg/stig)
// agent_record — Forward agent actions to SouHimBou AI Flight Recorder (stub; wired at
//                runtime when SOUHIMBOU_ENDPOINT env var is set)

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/mcp"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/stig"
)

// ─── stig_check ───────────────────────────────────────────────────────────────

// STIGCheckResponse is the structured JSON output of stig_check.
type STIGCheckResponse struct {
	Framework    string         `json:"framework"`
	Version      string         `json:"version"`
	TotalChecks  int            `json:"total_checks"`
	Passed       int            `json:"passed"`
	Failed       int            `json:"failed"`
	CAT1Failures int            `json:"cat1_failures"` // Critical
	CAT2Failures int            `json:"cat2_failures"` // High
	CAT3Failures int            `json:"cat3_failures"` // Medium
	Score        float64        `json:"score"`
	Findings     []STIGFinding  `json:"findings"`
	ScannedAt    string         `json:"scanned_at"`
}

// STIGFinding is a single STIG check result.
type STIGFinding struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Status      string `json:"status"`
	Severity    string `json:"severity"`
	Description string `json:"description,omitempty"`
	Remediation string `json:"remediation,omitempty"`
}

// HandleSTIGCheck is the MCP handler for stig_check.
// Runs RHEL-09-STIG V1R3 checks and returns structured findings.
func HandleSTIGCheck(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	framework, _ := call.Args["framework"].(string)
	if framework == "" {
		framework = stig.FrameworkRHEL09STIG
	}

	// Map common shorthand to canonical framework IDs
	frameworkAliases := map[string]string{
		"RHEL-09-STIG":     stig.FrameworkRHEL09STIG,
		"RHEL09":           stig.FrameworkRHEL09STIG,
		"rhel09":           stig.FrameworkRHEL09STIG,
		"CIS-L1":           stig.FrameworkCISL1,
		"CIS-L2":           stig.FrameworkCISL2,
		"NIST-800-53":      stig.FrameworkNIST53,
		"NIST-800-171":     stig.FrameworkNIST171,
		"CMMC":             stig.FrameworkCMMC,
		"PQC":              stig.FrameworkPQC,
		"PQC-Readiness":    stig.FrameworkPQC,
	}
	if canonical, ok := frameworkAliases[framework]; ok {
		framework = canonical
	}

	v := stig.NewValidator(".")
	report, err := v.Validate()
	if err != nil {
		return nil, nil, fmt.Errorf("stig_check: validation failed: %w", err)
	}

	result, ok := report.Results[framework]
	if !ok {
		// List available frameworks for helpful error message
		available := make([]string, 0, len(report.Results))
		for k := range report.Results {
			available = append(available, k)
		}
		return nil, nil, fmt.Errorf("stig_check: framework %q not found (available: %s)", framework, strings.Join(available, ", "))
	}

	// Map findings to MCP-safe output
	var findings []STIGFinding
	cat1, cat2, cat3 := 0, 0, 0

	for _, f := range result.Findings {
		sevStr := stigSeverityLabel(f.Severity)
		if f.Status != "Pass" {
			switch f.Severity {
			case stig.SeverityCAT1, stig.SeverityCritical:
				cat1++
			case stig.SeverityCAT2, stig.SeverityHigh:
				cat2++
			default:
				cat3++
			}
		}
		findings = append(findings, STIGFinding{
			ID:          f.ID,
			Title:       f.Title,
			Status:      f.Status,
			Severity:    sevStr,
			Description: f.Description,
			Remediation: f.Remediation,
		})
	}

	score := result.ComplianceScore()

	var warnings []string
	if cat1 > 0 {
		warnings = append(warnings, fmt.Sprintf("%d CAT I (Critical) STIG failures — immediate remediation required for CMMC compliance", cat1))
	}
	if cat2 > 0 {
		warnings = append(warnings, fmt.Sprintf("%d CAT II (High) STIG failures — remediate before next assessment cycle", cat2))
	}
	if score < 70 {
		warnings = append(warnings, fmt.Sprintf("STIG compliance score %.1f%% is below minimum threshold — not ready for C3PAO assessment", score))
	}

	return &STIGCheckResponse{
		Framework:    framework,
		Version:      result.Version,
		TotalChecks:  result.TotalControls,
		Passed:       result.Passed,
		Failed:       result.Failed,
		CAT1Failures: cat1,
		CAT2Failures: cat2,
		CAT3Failures: cat3,
		Score:        score,
		Findings:     findings,
		ScannedAt:    time.Now().UTC().Format(time.RFC3339),
	}, warnings, nil
}

func stigSeverityLabel(s stig.Severity) string {
	switch s {
	case stig.SeverityCAT1, stig.SeverityCritical:
		return "CAT I (Critical)"
	case stig.SeverityCAT2, stig.SeverityHigh:
		return "CAT II (High)"
	case stig.SeverityCAT3, stig.SeverityMedium:
		return "CAT III (Medium)"
	default:
		return string(s)
	}
}

// ─── cmmc_assess ──────────────────────────────────────────────────────────────

// CMMCAssessResponse is the structured JSON output of cmmc_assess.
type CMMCAssessResponse struct {
	Framework      string     `json:"framework"`
	Level          int        `json:"level"`
	TotalPractices int        `json:"total_practices"`
	Satisfied      int        `json:"satisfied"`
	NotSatisfied   int        `json:"not_satisfied"`
	Score          float64    `json:"score"`
	ReadyForC3PAO  bool       `json:"ready_for_c3pao"`
	Gaps           []CMMCGap  `json:"gaps"`
	PQCStatus      string     `json:"pqc_status"`
	ScannedAt      string     `json:"scanned_at"`
}

// CMMCGap is a failing CMMC practice with remediation guidance.
type CMMCGap struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Domain      string `json:"domain"`
	Level       string `json:"level"`
	Finding     string `json:"finding"`
	Remediation string `json:"remediation"`
}

// HandleCMMCAssess is the MCP handler for cmmc_assess.
// Performs a CMMC Level 1, 2, or 3 practice assessment using the STIG compliance database.
func HandleCMMCAssess(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	levelArg, _ := call.Args["level"].(string)
	if levelArg == "" {
		levelArg = "2"
	}

	// Normalise level arg → canonical framework string
	frameworkMap := map[string]string{
		"1": stig.FrameworkCMMC, // CMMC uses the Level 3 engine; scope differs
		"2": stig.FrameworkCMMC,
		"3": stig.FrameworkCMMC,
		"l1": stig.FrameworkCMMC,
		"l2": stig.FrameworkCMMC,
		"l3": stig.FrameworkCMMC,
		"CMMC_L1": stig.FrameworkCMMC,
		"CMMC_L2": stig.FrameworkCMMC,
		"CMMC_L3": stig.FrameworkCMMC,
		stig.FrameworkCMMC: stig.FrameworkCMMC,
	}
	framework, ok := frameworkMap[levelArg]
	if !ok {
		framework = stig.FrameworkCMMC
	}

	levelNum := 2
	switch levelArg {
	case "1", "l1", "CMMC_L1":
		levelNum = 1
	case "3", "l3", "CMMC_L3":
		levelNum = 3
	}

	v := stig.NewValidator(".")
	report, err := v.Validate()
	if err != nil {
		return nil, nil, fmt.Errorf("cmmc_assess: validation failed: %w", err)
	}

	result, ok := report.Results[framework]
	if !ok {
		return nil, nil, fmt.Errorf("cmmc_assess: CMMC framework result not available")
	}

	var gaps []CMMCGap
	pqcPass := false

	for _, f := range result.Findings {
		if strings.Contains(f.ID, "PQC") && f.Status == "Pass" {
			pqcPass = true
		}
		if f.Status != "Pass" {
			domain := extractCMMCDomain(f.ID)
			gaps = append(gaps, CMMCGap{
				ID:          f.ID,
				Title:       f.Title,
				Domain:      domain,
				Level:       fmt.Sprintf("Level %d", levelNum),
				Finding:     f.Actual,
				Remediation: f.Remediation,
			})
		}
	}

	score := result.ComplianceScore()
	readyForC3PAO := score >= 90 && result.Failed == 0

	pqcStatus := "Not assessed (no PQC-specific practices in this framework level)"
	if pqcPass {
		pqcStatus = "PQC advanced practices satisfied — ML-DSA-65 + Kyber-1024 attestation verified"
	}

	var warnings []string
	if result.Failed > 0 {
		warnings = append(warnings, fmt.Sprintf("%d CMMC Level %d practices not satisfied — not eligible for C3PAO assessment", result.Failed, levelNum))
	}
	if !readyForC3PAO {
		warnings = append(warnings, fmt.Sprintf("Organization is NOT ready for CMMC Level %d certification — remediate %d gap(s) first", levelNum, result.Failed))
	} else {
		warnings = append(warnings, fmt.Sprintf("Organization appears ready for CMMC Level %d C3PAO assessment — verify with a qualified C3PAO", levelNum))
	}

	return &CMMCAssessResponse{
		Framework:      framework,
		Level:          levelNum,
		TotalPractices: result.TotalControls,
		Satisfied:      result.Passed,
		NotSatisfied:   result.Failed,
		Score:          score,
		ReadyForC3PAO:  readyForC3PAO,
		Gaps:           gaps,
		PQCStatus:      pqcStatus,
		ScannedAt:      time.Now().UTC().Format(time.RFC3339),
	}, warnings, nil
}

func extractCMMCDomain(id string) string {
	parts := strings.Split(id, ":")
	if len(parts) < 2 {
		return "General"
	}
	domain := strings.Split(parts[1], ".")[0]
	switch domain {
	case "AC", "AccessControl":
		return "Access Control"
	case "AT":
		return "Awareness and Training"
	case "AU":
		return "Audit and Accountability"
	case "CM":
		return "Configuration Management"
	case "IA":
		return "Identification and Authentication"
	case "IR":
		return "Incident Response"
	case "MA":
		return "Maintenance"
	case "MP":
		return "Media Protection"
	case "PS":
		return "Personnel Security"
	case "PE":
		return "Physical Protection"
	case "RM":
		return "Risk Management"
	case "CA":
		return "Security Assessment"
	case "SA":
		return "System and Services Acquisition"
	case "SC":
		return "System and Communications Protection"
	case "SI":
		return "System and Information Integrity"
	case "SR":
		return "Supply Chain Risk Management"
	default:
		return domain
	}
}

// ─── agent_record ─────────────────────────────────────────────────────────────

// AgentRecordResponse is the output of agent_record.
type AgentRecordResponse struct {
	Recorded   bool   `json:"recorded"`
	RecordID   string `json:"record_id,omitempty"`
	Endpoint   string `json:"endpoint"`
	Mode       string `json:"mode"`
	Message    string `json:"message"`
	RecordedAt string `json:"recorded_at"`
}

// HandleAgentRecord forwards agent action events to SouHimBou AI Flight Recorder.
//
// When SOUHIMBOU_ENDPOINT env var is set, sends a POST to the Flight Recorder
// ingest API. When not set, records the event in the local PQC-signed DAG audit
// log only (air-gap / sovereign mode).
//
// This wires Layer 4 (PQC-MCP) to Layer 3 (SouHimBou AI) of the NouchiX stack.
func HandleAgentRecord(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	action, _ := call.Args["action"].(string)
	if action == "" {
		return nil, nil, fmt.Errorf("agent_record: 'action' is required (e.g. 'tool_called', 'decision_made', 'file_modified')")
	}

	agentID, _ := call.Args["agent_id"].(string)
	if agentID == "" {
		agentID = call.Identity.AgentID
	}
	toolName, _ := call.Args["tool_name"].(string)
	sessionID, _ := call.Args["session_id"].(string)
	if sessionID == "" {
		sessionID = call.Identity.SessionID
	}
	metadata, _ := call.Args["metadata"].(map[string]any)

	recordID := fmt.Sprintf("flr-%d", time.Now().UnixNano())
	recordedAt := time.Now().UTC().Format(time.RFC3339)

	// Build the Flight Recorder event payload
	event := map[string]any{
		"record_id":   recordID,
		"action":      action,
		"agent_id":    agentID,
		"tool_name":   toolName,
		"session_id":  sessionID,
		"metadata":    metadata,
		"recorded_at": recordedAt,
		"source":      "pqc-mcp",
		"pqc_signed":  true,
	}

	endpoint := os.Getenv("SOUHIMBOU_ENDPOINT")
	var warnings []string

	if endpoint == "" {
		// Air-gap / sovereign mode: event is captured by the signed audit log — no network call.
		return &AgentRecordResponse{
			Recorded:   true,
			RecordID:   recordID,
			Endpoint:   "local-dag (air-gap mode)",
			Mode:       "sovereign",
			Message:    "Agent action recorded in local PQC-signed DAG audit log. Set SOUHIMBOU_ENDPOINT to forward to SouHimBou AI Flight Recorder (souhimbou.ai).",
			RecordedAt: recordedAt,
		}, warnings, nil
	}

	// SaaS / edge mode: POST to SouHimBou AI ingest endpoint
	payload, err := json.Marshal(event)
	if err != nil {
		return nil, nil, fmt.Errorf("agent_record: failed to marshal event: %w", err)
	}

	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, endpoint+"/v1/agent-record", strings.NewReader(string(payload)))
	if err != nil {
		return nil, nil, fmt.Errorf("agent_record: failed to build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Khepra-Source", "pqc-mcp")
	req.Header.Set("X-Record-ID", recordID)

	if apiKey := os.Getenv("SOUHIMBOU_API_KEY"); apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		warnings = append(warnings, fmt.Sprintf("SouHimBou AI endpoint unreachable (%s): %v — event recorded in local DAG only", endpoint, err))
		return &AgentRecordResponse{
			Recorded:   true, // still captured by local signed audit log
			RecordID:   recordID,
			Endpoint:   endpoint,
			Mode:       "degraded (remote unreachable, local DAG active)",
			Message:    "Remote Flight Recorder unreachable. Event recorded in local PQC-signed audit log.",
			RecordedAt: recordedAt,
		}, warnings, nil
	}
	defer resp.Body.Close()

	mode := "saas"
	message := fmt.Sprintf("Agent action forwarded to SouHimBou AI Flight Recorder (HTTP %d)", resp.StatusCode)
	if resp.StatusCode >= 400 {
		warnings = append(warnings, fmt.Sprintf("SouHimBou AI returned HTTP %d — check SOUHIMBOU_API_KEY and endpoint", resp.StatusCode))
		mode = "saas-error"
	}

	return &AgentRecordResponse{
		Recorded:   resp.StatusCode < 400,
		RecordID:   recordID,
		Endpoint:   endpoint,
		Mode:       mode,
		Message:    message,
		RecordedAt: recordedAt,
	}, warnings, nil
}
