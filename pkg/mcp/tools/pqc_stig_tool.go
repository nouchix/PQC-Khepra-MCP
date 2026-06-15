// Package tools — pqc_stig_tool.go: MCP handler for the World's First DoD PQC STIG.
//
// Tool: pqc_stig
// Tier: Pharaoh (Enterprise) — TierEnterprise gate
//
// Runs PQC-01-STIG-V1R1 controls exclusively — fast because it does NOT invoke
// the RHEL/CIS/NIST/CMMC frameworks. Only the 12 PQC-specific controls execute.
//
// Control Coverage (CNSA 2.0 / FIPS 203/204/205):
//
//	CAT I — Critical (Algorithm Approval + Key Strength):
//	  PQC-010010  NIST-approved PQC algorithm enforcement (ML-KEM/ML-DSA/SLH-DSA only)
//	  PQC-010020  ML-DSA key strength (Level 3 / ML-DSA-65 minimum for CUI)
//	  PQC-010030  ML-KEM key strength (Level 3 / ML-KEM-768 minimum for CUI)
//	  PQC-010040  Deprecated PQC algorithm prohibition (Rainbow, SIKE, NTRU-fail, etc.)
//
//	CAT II — High (Hybrid Crypto + Key Protection):
//	  PQC-020010  Hybrid classical+PQC during CNSA 2.0 transition period
//	  PQC-020020  PQC private key protection at rest (HSM preferred)
//	  PQC-020030  Constant-time PQC implementation (side-channel resistance)
//	  PQC-020040  PQC certificate chain presence
//
//	CAT III — Medium (Audit + Documentation + Coverage):
//	  PQC-030010  PQC algorithm usage logging for quantum readiness audits
//	  PQC-030020  Key rotation procedure documentation for PQC keys
//	  PQC-030030  PQC coverage for both signing AND encryption
//
// DISA has no PQC STIG as of mid-2026. This baseline fills the gap for DoD
// contractors, C3PAOs, and FedRAMP system owners requiring quantum evidence today.
// Authority: NouchiX / AdinKhepra ASAF — pending DISA collaboration.
package tools

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/nouchix/PQC-Khepra-MCP/pkg/mcp"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/stig"
	"github.com/go-pdf/fpdf"
)

// HandlePQCSTIG is the MCP handler for the pqc_stig tool.
// Runs ONLY PQC-01-STIG-V1R1 controls — all other STIG frameworks are disabled
// to ensure fast execution (< 5s) without vendor tree scanning.
func HandlePQCSTIG(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	scanPath, _ := call.Args["scan_path"].(string)
	if scanPath == "" {
		scanPath = "."
	}
	profile, _ := call.Args["profile"].(string)
	if profile == "" {
		profile = "full"
	}
	profile = strings.ToLower(profile)
	outputPath, _ := call.Args["output_path"].(string)

	// ── Run PQC STIG — fast path, no system calls, no cross-ref DB ───────────
	v := stig.NewValidator(scanPath)

	// ValidatePQCOnly: skips uname/WSL hang, 36K-row DB load, blast radius scan.
	// Runs ONLY the 12 PQC-01-STIG-V1R1 controls. Returns in < 1 second.
	report, err := v.ValidatePQCOnly()
	if err != nil {
		return nil, nil, fmt.Errorf("pqc_stig: validation failed: %w", err)
	}

	result, ok := report.Results[stig.FrameworkPQCStig]
	if !ok {
		return nil, nil, fmt.Errorf("pqc_stig: PQC-01-STIG-V1R1 results not found — validator may not have run")
	}

	// ── Parse findings by category and status ────────────────────────────────
	var findings []PQCSTIGFinding
	cat1Pass, cat1Fail := 0, 0
	cat2Pass, cat2Fail := 0, 0
	cat3Pass, cat3Fail := 0, 0
	notApplicable, manualReview := 0, 0

	for _, f := range result.Findings {
		pf := PQCSTIGFinding{
			ID:          f.ID,
			Title:       f.Title,
			Status:      f.Status,
			Severity:    pqcStigCategoryLabel(f.Severity),
			Category:    pqcControlCategory(f.ID),
			Description: f.Description,
			Actual:      f.Actual,
			Expected:    f.Expected,
			Remediation: f.Remediation,
			References:  f.References,
			CheckedAt:   f.CheckedAt,
			FIPSBasis:   pqcFIPSBasis(f.ID),
			CNSAControl: pqcCNSAControl(f.ID),
		}
		findings = append(findings, pf)

		switch f.Status {
		case "Pass":
			switch f.Severity {
			case stig.SeverityCAT1, stig.SeverityCritical:
				cat1Pass++
			case stig.SeverityCAT2, stig.SeverityHigh:
				cat2Pass++
			default:
				cat3Pass++
			}
		case "Not Applicable":
			notApplicable++
		case "Manual Review Required":
			manualReview++
		default: // Fail and everything else
			switch f.Severity {
			case stig.SeverityCAT1, stig.SeverityCritical:
				cat1Fail++
			case stig.SeverityCAT2, stig.SeverityHigh:
				cat2Fail++
			default:
				cat3Fail++
			}
		}
	}

	// Sort findings by ID for deterministic output
	sort.Slice(findings, func(i, j int) bool {
		return findings[i].ID < findings[j].ID
	})

	// ── Compliance score and readiness verdict ────────────────────────────────
	score := result.ComplianceScore()
	verdict, readinessLevel := pqcReadinessVerdict(score, cat1Fail, cat2Fail)

	// ── Build warnings ────────────────────────────────────────────────────────
	var warnings []string
	if cat1Fail > 0 {
		warnings = append(warnings, fmt.Sprintf(
			"CAT I: %d critical PQC control failure(s) — system is NOT CNSA 2.0 compliant. "+
				"Immediate remediation required. C3PAO will issue Plan of Action & Milestones (POAM).",
			cat1Fail))
	}
	if cat2Fail > 0 {
		warnings = append(warnings, fmt.Sprintf(
			"CAT II: %d high-severity PQC control failure(s) — remediate before next assessment cycle.",
			cat2Fail))
	}
	if manualReview > 0 {
		warnings = append(warnings, fmt.Sprintf(
			"%d control(s) require manual review — automated checks insufficient for policy/documentation verification.",
			manualReview))
	}

	// ── Apply profile filter ──────────────────────────────────────────────────
	var displayFindings []PQCSTIGFinding
	switch profile {
	case "quick":
		// Quick: CAT I and CAT II failures + all manual review items
		// (CAT III omitted to keep quick output concise for daily checks)
		for _, f := range findings {
			if f.Status == "Pass" || f.Status == "Not Applicable" {
				continue
			}
			if f.Category == "CAT I" || f.Category == "CAT II" || f.Status == "Manual Review Required" {
				displayFindings = append(displayFindings, f)
			}
		}
	case "executive":
		// Executive: summary only, no per-finding detail
		displayFindings = nil // Response will contain summary stats only
	default: // "full"
		displayFindings = findings
	}

	// ── CNSA 2.0 migration timeline assessment ────────────────────────────────
	timeline := pqcMigrationTimeline(cat1Fail, cat2Fail)

	response := &PQCSTIGResponse{
		// Identity
		Standard:   "PQC-01-STIG-V1R1",
		Authority:  "NouchiX / AdinKhepra ASAF — pending DISA collaboration",
		FIPSBasis:  []string{"NIST FIPS 203 (ML-KEM/Kyber)", "NIST FIPS 204 (ML-DSA/Dilithium)", "NIST FIPS 205 (SLH-DSA/SPHINCS+)"},
		CNSABasis:  "NSA CNSA 2.0 (Commercial National Security Algorithm Suite 2.0)",
		AssessedAt: time.Now().UTC(),
		Target:     scanPath,
		Profile:    profile,

		// Scores
		ComplianceScore: score,
		ReadinessLevel:  readinessLevel,
		Verdict:         verdict,

		// Finding counts
		TotalControls: len(findings),
		CAT1Pass:      cat1Pass,
		CAT1Fail:      cat1Fail,
		CAT2Pass:      cat2Pass,
		CAT2Fail:      cat2Fail,
		CAT3Pass:      cat3Pass,
		CAT3Fail:      cat3Fail,
		NotApplicable: notApplicable,
		ManualReview:  manualReview,

		// Findings (profile-filtered)
		Findings: displayFindings,

		// Migration intelligence
		MigrationTimeline: timeline,
		ImmediateActions:  pqcImmediateActions(findings),

		// Evidence
		EvidenceNote: "This assessment constitutes PQC-01-STIG-V1R1 compliance evidence. " +
			"For C3PAO-grade evidence, use khepra_export_attestation (Sovereign tier) to generate " +
			"a PQC-signed evidence packet with ML-DSA-65 signature and DAG-anchored audit trail.",
	}

	// ── Optional PDF export ───────────────────────────────────────────────────
	if outputPath != "" {
		pdfPath, pdfErr := exportPQCPDF(response, outputPath)
		if pdfErr != nil {
			warnings = append(warnings, fmt.Sprintf("PDF export failed (%v) — JSON response still available", pdfErr))
		} else {
			response.PDFPath = pdfPath
		}
	}

	return response, warnings, nil
}

// ─── Response Types ────────────────────────────────────────────────────────────

// PQCSTIGResponse is the structured output from pqc_stig.
type PQCSTIGResponse struct {
	// Standard identification
	Standard   string    `json:"standard"`
	Authority  string    `json:"authority"`
	FIPSBasis  []string  `json:"fips_basis"`
	CNSABasis  string    `json:"cnsa_basis"`
	AssessedAt time.Time `json:"assessed_at"`
	Target     string    `json:"target"`
	Profile    string    `json:"profile"`

	// Compliance scoring
	ComplianceScore float64 `json:"compliance_score"`
	ReadinessLevel  string  `json:"readiness_level"`
	Verdict         string  `json:"verdict"`

	// Finding counts
	TotalControls int `json:"total_controls"`
	CAT1Pass      int `json:"cat1_pass"`
	CAT1Fail      int `json:"cat1_fail"`
	CAT2Pass      int `json:"cat2_pass"`
	CAT2Fail      int `json:"cat2_fail"`
	CAT3Pass      int `json:"cat3_pass"`
	CAT3Fail      int `json:"cat3_fail"`
	NotApplicable int `json:"not_applicable"`
	ManualReview  int `json:"manual_review"`

	// Findings (may be nil in executive profile)
	Findings []PQCSTIGFinding `json:"findings,omitempty"`

	// Migration intelligence
	MigrationTimeline string   `json:"migration_timeline"`
	ImmediateActions  []string `json:"immediate_actions,omitempty"`

	// Evidence note
	EvidenceNote string `json:"evidence_note"`

	// PDF output path (populated when output_path arg was provided)
	PDFPath string `json:"pdf_path,omitempty"`
}

// PQCSTIGFinding is a single PQC STIG control result.
type PQCSTIGFinding struct {
	ID          string    `json:"id"`
	Title       string    `json:"title"`
	Status      string    `json:"status"`
	Severity    string    `json:"severity"`
	Category    string    `json:"category"`
	Description string    `json:"description,omitempty"`
	Actual      string    `json:"actual,omitempty"`
	Expected    string    `json:"expected,omitempty"`
	Remediation string    `json:"remediation,omitempty"`
	References  []string  `json:"references,omitempty"`
	CheckedAt   time.Time `json:"checked_at"`
	FIPSBasis   string    `json:"fips_basis,omitempty"`
	CNSAControl string    `json:"cnsa_control,omitempty"`
}

// ─── Helper Functions ──────────────────────────────────────────────────────────

// pqcStigCategoryLabel maps stig severity constants to PQC STIG category strings.
func pqcStigCategoryLabel(s stig.Severity) string {
	switch s {
	case stig.SeverityCAT1, stig.SeverityCritical:
		return "CAT I (Critical)"
	case stig.SeverityCAT2, stig.SeverityHigh:
		return "CAT II (High)"
	case stig.SeverityCAT3, stig.SeverityMedium:
		return "CAT III (Medium)"
	default:
		return "CAT III (Medium)"
	}
}

// pqcControlCategory returns just the category prefix.
func pqcControlCategory(id string) string {
	switch {
	case strings.HasPrefix(id, "PQC-01"):
		return "CAT I"
	case strings.HasPrefix(id, "PQC-02"):
		return "CAT II"
	default:
		return "CAT III"
	}
}

// pqcFIPSBasis returns the relevant FIPS standard for each PQC control.
func pqcFIPSBasis(id string) string {
	switch id {
	case "PQC-010010":
		return "NIST FIPS 203, 204, 205"
	case "PQC-010020":
		return "NIST FIPS 204 (ML-DSA/Dilithium)"
	case "PQC-010030":
		return "NIST FIPS 203 (ML-KEM/Kyber)"
	case "PQC-010040":
		return "NIST IR 8413 (PQC Algorithm Status)"
	case "PQC-020010":
		return "NIST SP 800-208 (Hybrid Key Exchange)"
	case "PQC-020020":
		return "NIST FIPS 140-3 (Cryptographic Module Security)"
	case "PQC-020030":
		return "NIST SP 800-90B (Side-Channel Resistance)"
	case "PQC-020040":
		return "NIST FIPS 203, 204 (PQC Certificate Extensions)"
	case "PQC-030010":
		return "NIST SP 800-92 (Audit Log Management)"
	case "PQC-030020":
		return "NIST SP 800-57 Part 1 (Key Management)"
	case "PQC-030030":
		return "NIST FIPS 203, 204 (Comprehensive PQC Coverage)"
	}
	return ""
}

// pqcCNSAControl maps PQC STIG controls to CNSA 2.0 requirements.
func pqcCNSAControl(id string) string {
	switch id {
	case "PQC-010010":
		return "CNSA 2.0 §3 — Approved Algorithms (ML-KEM, ML-DSA, SLH-DSA)"
	case "PQC-010020":
		return "CNSA 2.0 §4.1 — ML-DSA Key Size Requirements"
	case "PQC-010030":
		return "CNSA 2.0 §4.2 — ML-KEM Key Size Requirements"
	case "PQC-010040":
		return "CNSA 2.0 §3 — Prohibited Algorithms"
	case "PQC-020010":
		return "CNSA 2.0 §5 — Hybrid Classical+PQC Transition"
	case "PQC-020020":
		return "CNSA 2.0 §6 — Key Protection Requirements"
	case "PQC-020030":
		return "CNSA 2.0 §7 — Implementation Security"
	case "PQC-020040":
		return "CNSA 2.0 §8 — Certificate and PKI Requirements"
	case "PQC-030010":
		return "CNSA 2.0 §9 — Audit and Accountability"
	case "PQC-030020":
		return "CNSA 2.0 §6.3 — Key Lifecycle Management"
	case "PQC-030030":
		return "CNSA 2.0 §3 — Full-Stack PQC Coverage"
	}
	return ""
}

// pqcReadinessVerdict converts score and failure counts to a readiness verdict.
func pqcReadinessVerdict(score float64, cat1Fail, cat2Fail int) (verdict, level string) {
	switch {
	case cat1Fail > 0:
		return fmt.Sprintf("NOT CNSA 2.0 COMPLIANT — %d CAT I failure(s) block quantum readiness certification", cat1Fail),
			"CRITICAL"
	case cat2Fail > 0 && score < 70:
		return fmt.Sprintf("CONDITIONAL — %d CAT II failure(s) require remediation before C3PAO assessment", cat2Fail),
			"HIGH"
	case cat2Fail > 0:
		return fmt.Sprintf("SUBSTANTIALLY COMPLIANT — %d CAT II finding(s) require remediation", cat2Fail),
			"MEDIUM"
	case score >= 90:
		return "QUANTUM READY — All critical controls pass. PQC-01-STIG-V1R1 compliant.",
			"READY"
	case score >= 75:
		return "MOSTLY COMPLIANT — Minor CAT III findings only. Acceptable for initial C3PAO review.",
			"GOOD"
	default:
		return "PARTIAL COMPLIANCE — Review CAT III findings and manual review items.",
			"MEDIUM"
	}
}

// pqcMigrationTimeline generates CNSA 2.0 migration timeline guidance.
func pqcMigrationTimeline(cat1Fail, cat2Fail int) string {
	switch {
	case cat1Fail > 0:
		return "IMMEDIATE ACTION REQUIRED: NSM-10 mandates PQC migration for NSS by 2030. " +
			"CAT I failures indicate pre-standardization or deprecated PQC algorithms — " +
			"these must be replaced with FIPS 203/204/205 algorithms NOW. " +
			"Timeline: 0-6 months for critical system migration."
	case cat2Fail > 0:
		return "NEAR-TERM: CNSA 2.0 transition period runs through 2030. " +
			"CAT II findings indicate hybrid crypto gaps or key protection deficiencies. " +
			"Timeline: 6-18 months for hybrid implementation completion."
	default:
		return "ON TRACK: System is substantially aligned with CNSA 2.0 requirements. " +
			"Continue monitoring NIST FIPS 203/204/205 implementation guidance. " +
			"Timeline: Maintain current posture through 2030 NSS deadline."
	}
}

// pqcImmediateActions returns the top remediation actions from failed CAT I/II findings.
func pqcImmediateActions(findings []PQCSTIGFinding) []string {
	var actions []string
	for _, f := range findings {
		if f.Status == "Pass" || f.Status == "Not Applicable" {
			continue
		}
		if f.Category != "CAT I" && f.Category != "CAT II" {
			continue
		}
		if f.Remediation != "" && f.Remediation != "N/A" {
			actions = append(actions, fmt.Sprintf("[%s] %s", f.ID, f.Remediation))
		}
		if len(actions) >= 5 { // Top 5 immediate actions
			break
		}
	}
	return actions
}

// ─── PDF Export ────────────────────────────────────────────────────────────────

// exportPQCPDF generates a DoD-style PQC Executive Intelligence Brief PDF.
// Returns the absolute output file path on success.
func exportPQCPDF(r *PQCSTIGResponse, outputPath string) (string, error) {
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return "", fmt.Errorf("create output directory: %w", err)
	}
	pdfPath := outputPath
	if !strings.HasSuffix(pdfPath, ".pdf") {
		pdfPath += ".pdf"
	}
	doc := fpdf.New("P", "mm", "A4", "")
	doc.SetMargins(15, 15, 15)
	doc.SetAutoPageBreak(true, 15)

	// Title Page
	doc.AddPage()
	doc.SetFont("Helvetica", "B", 22)
	doc.Ln(30)
	doc.CellFormat(0, 14, "PQC EXECUTIVE INTELLIGENCE BRIEF", "", 1, "C", false, 0, "")
	doc.SetFont("Helvetica", "", 14)
	doc.CellFormat(0, 9, "Post-Quantum Cryptography STIG Assessment", "", 1, "C", false, 0, "")
	doc.CellFormat(0, 9, r.Standard, "", 1, "C", false, 0, "")
	doc.Ln(12)
	doc.SetFillColor(210, 210, 210)
	doc.SetFont("Helvetica", "B", 11)
	doc.CellFormat(0, 9, "CLASSIFICATION: UNCLASSIFIED", "1", 1, "C", true, 0, "")
	doc.Ln(8)
	doc.SetFont("Helvetica", "", 10)
	doc.CellFormat(0, 7, "Assessment Date:  "+r.AssessedAt.Format("2006-01-02 15:04:05 UTC"), "", 1, "C", false, 0, "")
	doc.CellFormat(0, 7, "Target:           "+r.Target, "", 1, "C", false, 0, "")
	doc.CellFormat(0, 7, "Profile:          "+r.Profile, "", 1, "C", false, 0, "")
	doc.CellFormat(0, 7, "Authority:        "+r.Authority, "", 1, "C", false, 0, "")
	doc.Ln(20)
	doc.SetFont("Helvetica", "I", 9)
	doc.CellFormat(0, 6, "Generated by Khepra MCP — AdinKhepra Iron Bank Security Scanner", "", 1, "C", false, 0, "")
	doc.CellFormat(0, 6, "souhimbou.ai", "", 1, "C", false, 0, "")

	// Executive Summary Page
	doc.AddPage()
	doc.SetFont("Helvetica", "B", 16)
	doc.CellFormat(0, 10, "EXECUTIVE SUMMARY", "B", 1, "L", false, 0, "")
	doc.Ln(5)
	doc.SetFillColor(240, 240, 240)
	doc.SetFont("Helvetica", "B", 13)
	switch r.ReadinessLevel {
	case "READY", "GOOD":
		doc.SetTextColor(0, 150, 0)
	case "MEDIUM":
		doc.SetTextColor(180, 120, 0)
	default:
		doc.SetTextColor(200, 0, 0)
	}
	doc.CellFormat(90, 14, fmt.Sprintf("Compliance Score: %.1f%%", r.ComplianceScore), "1", 0, "C", true, 0, "")
	doc.SetTextColor(0, 0, 0)
	doc.CellFormat(90, 14, "Readiness: "+r.ReadinessLevel, "1", 1, "C", true, 0, "")
	doc.Ln(4)
	doc.SetFont("Helvetica", "", 10)
	doc.MultiCell(0, 6, "Verdict: "+r.Verdict, "", "L", false)
	doc.Ln(5)
	doc.SetFont("Helvetica", "B", 11)
	doc.CellFormat(0, 8, "Findings Summary:", "", 1, "L", false, 0, "")
	doc.SetFont("Helvetica", "", 10)
	type kv struct{ l, v string }
	for _, row := range []kv{
		{"CAT I Critical  Pass", fmt.Sprintf("%d", r.CAT1Pass)},
		{"CAT I Critical  Fail", fmt.Sprintf("%d", r.CAT1Fail)},
		{"CAT II High     Pass", fmt.Sprintf("%d", r.CAT2Pass)},
		{"CAT II High     Fail", fmt.Sprintf("%d", r.CAT2Fail)},
		{"CAT III Medium  Pass", fmt.Sprintf("%d", r.CAT3Pass)},
		{"CAT III Medium  Fail", fmt.Sprintf("%d", r.CAT3Fail)},
		{"Not Applicable", fmt.Sprintf("%d", r.NotApplicable)},
		{"Manual Review Required", fmt.Sprintf("%d", r.ManualReview)},
		{"Total Controls", fmt.Sprintf("%d", r.TotalControls)},
	} {
		doc.CellFormat(120, 6, row.l, "", 0, "L", false, 0, "")
		doc.CellFormat(60, 6, row.v, "", 1, "R", false, 0, "")
	}
	doc.Ln(5)
	doc.SetFont("Helvetica", "B", 11)
	doc.CellFormat(0, 8, "CNSA 2.0 Migration Timeline:", "", 1, "L", false, 0, "")
	doc.SetFont("Helvetica", "", 10)
	doc.MultiCell(0, 6, r.MigrationTimeline, "", "L", false)

	// Findings Detail Page
	if len(r.Findings) > 0 {
		doc.AddPage()
		doc.SetFont("Helvetica", "B", 16)
		doc.CellFormat(0, 10, "CONTROL FINDINGS DETAIL", "B", 1, "L", false, 0, "")
		doc.Ln(5)
		for _, f := range r.Findings {
			if f.Status == "Pass" || f.Status == "Not Applicable" {
				continue
			}
			switch f.Category {
			case "CAT I":
				doc.SetTextColor(200, 0, 0)
			case "CAT II":
				doc.SetTextColor(180, 80, 0)
			default:
				doc.SetTextColor(130, 100, 0)
			}
			doc.SetFont("Helvetica", "B", 11)
			doc.CellFormat(0, 7, "["+f.ID+"] "+f.Category+" — "+f.Status, "", 1, "L", false, 0, "")
			doc.SetTextColor(0, 0, 0)
			doc.SetFont("Helvetica", "", 10)
			doc.MultiCell(0, 5, f.Title, "", "L", false)
			if f.Remediation != "" && f.Remediation != "N/A" {
				doc.SetFont("Helvetica", "I", 9)
				doc.MultiCell(0, 5, "Remediation: "+f.Remediation, "", "L", false)
				doc.SetFont("Helvetica", "", 10)
			}
			if len(f.References) > 0 {
				doc.SetFont("Courier", "", 8)
				doc.CellFormat(0, 5, "Refs: "+strings.Join(f.References, " | "), "", 1, "L", false, 0, "")
				doc.SetFont("Helvetica", "", 10)
			}
			doc.Ln(3)
		}
	}

	// Immediate Actions Page
	if len(r.ImmediateActions) > 0 {
		doc.AddPage()
		doc.SetFont("Helvetica", "B", 16)
		doc.SetTextColor(200, 0, 0)
		doc.CellFormat(0, 10, "IMMEDIATE ACTIONS REQUIRED", "B", 1, "L", false, 0, "")
		doc.SetTextColor(0, 0, 0)
		doc.Ln(5)
		doc.SetFont("Helvetica", "", 10)
		for i, action := range r.ImmediateActions {
			doc.MultiCell(0, 6, fmt.Sprintf("%d. %s", i+1, action), "", "L", false)
			doc.Ln(2)
		}
	}

	doc.SetFont("Courier", "", 8)
	doc.SetTextColor(80, 80, 80)
	doc.Ln(8)
	doc.CellFormat(0, 5, "CLASSIFICATION: UNCLASSIFIED  |  "+r.Standard+"  |  souhimbou.ai", "", 1, "C", false, 0, "")
	doc.SetTextColor(0, 0, 0)

	if err := doc.OutputFileAndClose(pdfPath); err != nil {
		txtPath := pdfPath + ".txt"
		if txtErr := exportPQCText(r, txtPath); txtErr != nil {
			return "", fmt.Errorf("pdf failed (%v); text fallback also failed: %w", err, txtErr)
		}
		return txtPath, nil
	}
	return pdfPath, nil
}

// exportPQCText writes a plain-text PQC brief as fallback when fpdf is unavailable.
func exportPQCText(r *PQCSTIGResponse, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	// Explicit close with error capture to prevent silent data loss (Go WARNING).
	defer func() {
		if cerr := f.Close(); cerr != nil {
			log.Printf("[WARN] file close error: %v", cerr)
		}
	}()
	w := func(format string, args ...any) { fmt.Fprintf(f, format, args...) }
	w("═══════════════════════════════════════════════════════════════════\n")
	w("           PQC EXECUTIVE INTELLIGENCE BRIEF — %s\n", r.Standard)
	w("═══════════════════════════════════════════════════════════════════\n\n")
	w("CLASSIFICATION: UNCLASSIFIED\n")
	w("DATE:    %s\nTARGET:  %s\nPROFILE: %s\n\n",
		r.AssessedAt.Format("2006-01-02 15:04:05 UTC"), r.Target, r.Profile)
	w("─── EXECUTIVE SUMMARY ──────────────────────────────────────────────\n")
	w("Compliance Score: %.1f%%   Readiness: %s\n", r.ComplianceScore, r.ReadinessLevel)
	w("Verdict: %s\n\n", r.Verdict)
	w("CAT I Critical:  %d pass / %d fail\n", r.CAT1Pass, r.CAT1Fail)
	w("CAT II High:     %d pass / %d fail\n", r.CAT2Pass, r.CAT2Fail)
	w("CAT III Medium:  %d pass / %d fail\n", r.CAT3Pass, r.CAT3Fail)
	w("Not Applicable:  %d   Manual Review: %d\n\n", r.NotApplicable, r.ManualReview)
	w("Migration Timeline:\n%s\n\n", r.MigrationTimeline)
	if len(r.ImmediateActions) > 0 {
		w("─── IMMEDIATE ACTIONS ──────────────────────────────────────────────\n")
		for i, a := range r.ImmediateActions {
			w("%d. %s\n", i+1, a)
		}
		w("\n")
	}
	w("═══════════════════════════════════════════════════════════════════\n")
	w("END OF BRIEF  |  CLASSIFICATION: UNCLASSIFIED  |  souhimbou.ai\n")
	return nil
}
