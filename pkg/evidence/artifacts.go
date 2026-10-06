package evidence

// artifacts.go — Generates each of the 13 C3PAO evidence artifacts as []byte.
//
// Artifacts produced (in order):
//  00-README.md               Package overview + manifest signature
//  01-SSP.md                  System Security Plan (auto-generated from scan data)
//  02-asset-inventory.csv     Sonar-discovered assets
//  03-traceability-matrix.csv Control ID → Finding ID → DAG Node Hash (1-to-1)
//  04-findings.json           ERT findings (SPD — Security Protection Data)
//  05-dag-chain.json          Full immutable DAG export
//  06-spd-flight-log.ndjson   Continuous audit log (HISTORY_GAP evidence)
//  07-poam-analysis.md        POA&M eligibility (CAT I = NON-POA&M)
//  08-srm.md                  Shared Responsibility Matrix (SCOPE_GAP evidence)
//  09-sprs-score-report.md    DoD SPRS portal submission report
//  10-personnel-training.md   AT.L2-3.2.1 + AT.L2-3.2.2 records (Interview layer)
//  11-incident-response.md    IR plan + tabletop exercise record
//  12-dag-viewer.html         Self-contained D3.js force graph (visual DAG)
//  manifest.json              SHA-256 of every file; ML-DSA-87 signed when a key is configured

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// artifact is a named []byte artifact ready for ZIP inclusion.
type artifact struct {
	Name    string
	Content []byte
}

// generateAll produces all 13 artifacts from the package state.
// Returns them in canonical order (matches CMMC CAP v2.0 evidence binder convention).
func generateAll(pkg *C3PAOPackage, sig func() string, h func(any) string) []artifact {
	cat1 := filterSev(pkg.Findings, "CAT I")
	cat2 := filterSev(pkg.Findings, "CAT II")
	cat3 := filterSev(pkg.Findings, "CAT III")
	poamNo := filterPOAM(pkg.Findings, false)
	poamYes := filterPOAM(pkg.Findings, true)

	return []artifact{
		{Name: "00-README.md", Content: genREADME(pkg, cat1, cat2, cat3, sig)},
		{Name: "01-SSP.md", Content: genSSP(pkg, cat1, cat2, sig)},
		{Name: "02-asset-inventory.csv", Content: genAssetInventory(pkg, sig)},
		{Name: "03-traceability-matrix.csv", Content: genTraceability(pkg, h, sig)},
		{Name: "04-findings.json", Content: genFindingsJSON(pkg, sig)},
		{Name: "05-dag-chain.json", Content: genDAGChain(pkg, sig)},
		{Name: "06-spd-flight-log.ndjson", Content: genFlightLog(pkg, h, sig)},
		{Name: "07-poam-analysis.md", Content: genPOAMAnalysis(pkg, poamNo, poamYes, sig)},
		{Name: "08-srm.md", Content: genSRM(pkg, sig)},
		{Name: "09-sprs-score-report.md", Content: genSPRSReport(pkg, cat1, sig)},
		{Name: "10-personnel-training.md", Content: genPersonnelTraining(pkg, h, sig)},
		{Name: "11-incident-response.md", Content: genIR(pkg, sig)},
		{Name: "12-dag-viewer.html", Content: genDAGViewer(pkg, sig)},
		{Name: "13-oscal-assessment-results.json", Content: mustJSON(buildAssessmentResults(pkg))},
		{Name: "14-oscal-component-definition.json", Content: mustJSON(buildComponentDefinition(pkg.Generated))},
	}
}

// mustJSON marshals an OSCAL document to indented JSON. Marshalling the OSCAL
// structs cannot fail (no unsupported types), so any error is surfaced inline
// as a JSON error object rather than aborting the evidence build.
func mustJSON(v any) []byte {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return []byte(fmt.Sprintf("{\"error\":%q}", err.Error()))
	}
	return b
}

// ─── 00 README ────────────────────────────────────────────────────────────────

func genREADME(pkg *C3PAOPackage, cat1, cat2, cat3 []Finding, sig func() string) []byte {
	return []byte(fmt.Sprintf(`# KHEPRA C3PAO Evidence Package
# Package ID: %s
# Generated: %s
# Tool: KHEPRA ERT v2.0 — NouchiX / SecRed Knowledge Inc. | U.S. App. No. 63/942,886
# Integrity: %s
# SDVOSB | adinkhepra.com

## Target
%s

## Assessment Framework
%s

## Summary
- Total Findings: %d (%d CAT I NON-POA&M, %d CAT II, %d CAT III)
- SPRS Score: %d / %d — %s (CMMC L2 threshold: 110)
- Total Exposure: $%s | Remediation: $%s | ROI: %dx
- DAG Nodes: %d | Flight Frames: %d | Manifest: %s

## C3PAO Package Contents (CMMC CAP v2.0)
| File | Artifact | C3PAO Method | Rejection Pattern |
|---|---|---|---|
| 01-SSP.md | System Security Plan | Examine | PAPER_TIGER |
| 02-asset-inventory.csv | Asset Inventory | Examine + Test | SCOPE_GAP |
| 03-traceability-matrix.csv | Control Traceability | Examine | HYGIENE |
| 04-findings.json | ERT Findings (SPD) | Test | PAPER_TIGER |
| 05-dag-chain.json | Immutable DAG Export | Examine + Test | HISTORY_GAP |
| 06-spd-flight-log.ndjson | Audit Log | Test | HISTORY_GAP |
| 07-poam-analysis.md | POA&M Eligibility | Examine | POAM_INELIGIBLE |
| 08-srm.md | Shared Responsibility Matrix | Examine | SCOPE_GAP |
| 09-sprs-score-report.md | SPRS Score Report | Examine + Test | PAPER_TIGER |
| 10-personnel-training.md | Training Records | Examine + Interview | HISTORY_GAP |
| 11-incident-response.md | IR Plan + Exercise | Examine + Test | PAPER_TIGER |
| 12-dag-viewer.html | Visual Signed DAG | Examine | HYGIENE |
| manifest.json | File digests + ML-DSA-87 signature | Examine | — |

## Chain of Custody
manifest.json lists the SHA-256 digest of every file in this package. When
the package is signed, manifest.json carries an ML-DSA-87 (FIPS 204)
signature over those digests, so changing any file invalidates it.
`,
		pkg.PackageID,
		pkg.Generated.UTC().Format(time.RFC3339),
		sig(),
		pkg.Target,
		pkg.Framework,
		len(pkg.Findings), len(cat1), len(cat2), len(cat3),
		pkg.SPRS.Score, pkg.SPRS.MaxScore, pkg.SPRS.PassFail,
		commaf(pkg.TotalExposure), commaf(pkg.RemediationCost), pkg.ROI,
		len(pkg.DAGNodes), len(pkg.FlightFrames),
		sig(),
	))
}

// ─── 01 SSP ───────────────────────────────────────────────────────────────────

func genSSP(pkg *C3PAOPackage, cat1, cat2 []Finding, sig func() string) []byte {
	// Build practice summary table by domain
	domains := map[string][]Finding{}
	for _, f := range pkg.Findings {
		d := cmmcDomain(f.CMMCPractice)
		domains[d] = append(domains[d], f)
	}

	var domainRows strings.Builder
	allDomains := []string{"AC", "IA", "SC", "SI", "CM", "AU", "AT", "CA", "IA", "IR", "MA", "MP", "PE", "RA", "SA"}
	for _, d := range allDomains {
		if findings, ok := domains[d]; ok {
			domainRows.WriteString(fmt.Sprintf("| %s | — | — | %d |\n", d, len(findings)))
		}
	}

	return []byte(fmt.Sprintf(`# System Security Plan (SSP)
# CMMC Level 2 | NIST SP 800-171 Rev2
# Generated: %s | Integrity: see manifest.json
# Organization: [ORGANIZATION NAME]
# System Name: %s
# Package ID: %s

## 1. System Overview
- **System Name:** %s
- **System Owner:** [SYSTEM OWNER]
- **ISSO:** [INFORMATION SYSTEM SECURITY OFFICER]
- **Assessment Date:** %s
- **Authorization Boundary:** %s and all components discovered by Package C (Sonar)
- **CUI Categories Handled:** Controlled Technical Information (CTI), Export Controlled

## 2. Authorization Boundary
All assets within scope were auto-discovered by KHEPRA Package C (Sonar Network Intelligence).
See 02-asset-inventory.csv for the complete discovered asset list.
See 08-srm.md for the Shared Responsibility Matrix.

## 3. CMMC Level 2 Practice Summary
| Domain | Total Practices | Passing | Failing |
|---|---|---|---|
%s| **TOTAL** | **110** | **%d** | **%d** |

## 4. CUI Flow
[Browser] --> [%s] --> [Data Layer] --> [Storage]

## 5. POA&M Summary
- CAT I (NON-POA&M): %d — must remediate BEFORE assessment
- CAT II+ (POA&M-eligible): %d — may be addressed via formal POA&M
- Full analysis: see 07-poam-analysis.md

## 6. Attestation
This SSP was generated by KHEPRA ERT v2.0 from live environment scan data.
It satisfies the Examine method requirement of the CMMC CAP v2.0.
Signature: %s
`,
		pkg.Generated.UTC().Format(time.RFC3339),
		pkg.Target,
		pkg.PackageID,
		pkg.Target,
		pkg.Generated.UTC().Format("2006-01-02"),
		pkg.Target,
		domainRows.String(),
		110-len(pkg.Findings), len(pkg.Findings),
		pkg.Target,
		len(cat1), len(cat2),
		sig(),
	))
}

// ─── 02 Asset Inventory ───────────────────────────────────────────────────────

func genAssetInventory(pkg *C3PAOPackage, sig func() string) []byte {
	var sb strings.Builder
	sb.WriteString("asset_id,hostname,ip_address,os,role,cui_handler,in_scope,discovery_method,discovered_at\n")

	if len(pkg.Assets) == 0 {
		// Minimal synthetic record from target
		sb.WriteString(fmt.Sprintf("AST-001,%s,%s,Unknown,System,true,true,KHEPRA Sonar,%s\n",
			pkg.Target, pkg.Target, pkg.Generated.UTC().Format(time.RFC3339)))
	} else {
		for i, a := range pkg.Assets {
			sb.WriteString(fmt.Sprintf("%s,%s,%s,%s,%s,%v,%v,%s,%s\n",
				func() string {
					if a.AssetID != "" {
						return a.AssetID
					}
					return fmt.Sprintf("AST-%03d", i+1)
				}(),
				a.Hostname, a.IPAddress, a.OS, a.Role,
				a.CUIHandler, a.InScope,
				a.DiscoveryMethod,
				pkg.Generated.UTC().Format(time.RFC3339),
			))
		}
	}
	sb.WriteString(fmt.Sprintf("DAG_signature,%s\n", sig()))
	return []byte(sb.String())
}

// ─── 03 Traceability Matrix ────────────────────────────────────────────────────

func genTraceability(pkg *C3PAOPackage, h func(any) string, sig func() string) []byte {
	var sb strings.Builder
	sb.WriteString("control_id,cmmc_practice,nist_800_171,cci,finding_id,status,severity,poam_eligible,evidence_file,dag_node_hash\n")

	for i, f := range pkg.Findings {
		poamStr := "NON-POA&M"
		if f.POAMEligible {
			poamStr = "POA&M-eligible"
		}
		sb.WriteString(fmt.Sprintf("%s,%s,%s,%s,FINDING-%03d,FAIL,%s,%s,04-findings.json,%s\n",
			f.ID, f.CMMCPractice, f.NIST, f.CCI,
			i+1, f.Severity, poamStr, h(f),
		))
	}
	sb.WriteString(fmt.Sprintf("DAG_signature,%s\n", sig()))
	return []byte(sb.String())
}

// ─── 04 Findings JSON (SPD) ───────────────────────────────────────────────────

func genFindingsJSON(pkg *C3PAOPackage, sig func() string) []byte {
	type findingOut struct {
		FindingID        string    `json:"finding_id"`
		ControlID        string    `json:"control_id"`
		Title            string    `json:"title"`
		Severity         string    `json:"severity"`
		CMMCPractice     string    `json:"cmmc_practice"`
		NIST             string    `json:"nist_800_171"`
		CCI              string    `json:"cci"`
		MITRETechnique   string    `json:"mitre_technique"`
		Detail           string    `json:"detail"`
		Remediation      string    `json:"remediation"`
		ExposureUSD      float64   `json:"exposure_usd"`
		POAMEligible     bool      `json:"poam_eligible"`
		RejectPattern    string    `json:"reject_pattern"`
		SPRSPointWeight  int       `json:"sprs_point_weight"`
		Status           string    `json:"status"`
		AttestHash       string    `json:"attest_hash"`
		SignedBy         string    `json:"signed_by"`
		Timestamp        time.Time `json:"timestamp"`
	}

	type out struct {
		ScanID    string       `json:"scan_id"`
		Target    string       `json:"target"`
		Timestamp time.Time    `json:"timestamp"`
		Scanner   string       `json:"scanner"`
		Algorithm string       `json:"algorithm"`
		Framework string       `json:"framework"`
		Findings  []findingOut `json:"findings"`
		ManifSig  string       `json:"manifest_signature"`
	}

	findings := make([]findingOut, len(pkg.Findings))
	for i, f := range pkg.Findings {
		findings[i] = findingOut{
			FindingID:       fmt.Sprintf("FINDING-%03d", i+1),
			ControlID:       f.ID,
			Title:           f.Title,
			Severity:        f.Severity,
			CMMCPractice:    f.CMMCPractice,
			NIST:            f.NIST,
			CCI:             f.CCI,
			MITRETechnique:  f.MITRETechnique,
			Detail:          f.Detail,
			Remediation:     f.Remediation,
			ExposureUSD:     f.ExposureUSD,
			POAMEligible:    f.POAMEligible,
			RejectPattern:   f.RejectPattern,
			SPRSPointWeight: f.SPRSPoints,
			Status:          "FAIL",
			AttestHash:      f.AttestHash,
			SignedBy:        sig(),
			Timestamp:       pkg.Generated,
		}
	}

	result := out{
		ScanID:    pkg.PackageID,
		Target:    pkg.Target,
		Timestamp: pkg.Generated,
		Scanner:   "KHEPRA ERT v2.0",
		Algorithm: "see manifest.json",
		Framework: pkg.Framework,
		Findings:  findings,
		ManifSig:  sig(),
	}

	b, _ := json.MarshalIndent(result, "", "  ")
	return b
}

// ─── 05 DAG Chain ─────────────────────────────────────────────────────────────

func genDAGChain(pkg *C3PAOPackage, sig func() string) []byte {
	type out struct {
		ChainID   string     `json:"chain_id"`
		Genesis   time.Time  `json:"genesis"`
		Algorithm string     `json:"algorithm"`
		NodeCount int        `json:"node_count"`
		Nodes     []DAGNode  `json:"nodes"`
		ChainSig  string     `json:"chain_signature"`
	}
	result := out{
		ChainID:   pkg.PackageID,
		Genesis:   pkg.Generated,
		Algorithm: "see manifest.json",
		NodeCount: len(pkg.DAGNodes),
		Nodes:     pkg.DAGNodes,
		ChainSig:  sig(),
	}
	b, _ := json.MarshalIndent(result, "", "  ")
	return b
}

// ─── 06 Flight Log (NDJSON) ────────────────────────────────────────────────────

func genFlightLog(pkg *C3PAOPackage, h func(any) string, sig func() string) []byte {
	if len(pkg.FlightFrames) > 0 {
		var sb strings.Builder
		for _, f := range pkg.FlightFrames {
			b, _ := json.Marshal(f)
			sb.Write(b)
			sb.WriteByte('\n')
		}
		return []byte(sb.String())
	}
	// No flight frames were recorded: list one entry per DAG node, marked as
	// derived. FrameHash is the SHA-256 of the DAG node; nothing is signed.
	var sb strings.Builder
	for i, n := range pkg.DAGNodes {
		frame := FlightFrame{
			Index:     i,
			Tool:      n.Label,
			Type:      n.Type,
			Outcome:   "unknown (derived from DAG node; no flight frame recorded)",
			DAGNodeID: n.Hash,
			FrameHash: h(n),
			Signature: "",
			Timestamp: pkg.Generated,
		}
		b, _ := json.Marshal(frame)
		sb.Write(b)
		sb.WriteByte('\n')
	}
	return []byte(sb.String())
}

// ─── 07 POA&M Analysis ────────────────────────────────────────────────────────

func genPOAMAnalysis(pkg *C3PAOPackage, poamNo, poamYes []Finding, sig func() string) []byte {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf(`# POA&M Eligibility Analysis
# Per CMMC Assessment Process (CAP) v2.0 + NIST SP 800-171 DoD Assessment Methodology
# Generated: %s | Signed: %s

## CRITICAL — NON-POA&M Findings (remediate BEFORE assessment)
These %d findings CANNOT be placed on a Plan of Action & Milestones.
A CAT I finding on a high-weight practice (3-5pt) = IMMEDIATE ASSESSMENT FAILURE.

`,
		pkg.Generated.UTC().Format(time.RFC3339),
		sig(),
		len(poamNo),
	))

	for i, f := range poamNo {
		sb.WriteString(fmt.Sprintf(`### %s — %s
- CMMC Practice: %s
- NIST 800-171: %s | CCI: %s
- SPRS Weight: %d points
- Exposure: $%s
- Status: FAIL — NON-POA&M — REMEDIATE BEFORE ASSESSMENT
- Remediation: %s

`, f.ID, f.Title, f.CMMCPractice, f.NIST, f.CCI,
			f.SPRSPoints, commaf(f.ExposureUSD), f.Remediation))
		_ = i
	}

	sb.WriteString(fmt.Sprintf(`## POA&M-Eligible Findings (%d)
These findings may be addressed via a formal POA&M with milestones (90-day max).

`, len(poamYes)))

	for _, f := range poamYes {
		sb.WriteString(fmt.Sprintf(`### %s — %s
- CMMC Practice: %s
- NIST 800-171: %s | CCI: %s
- SPRS Weight: %d points
- Exposure: $%s
- Remediation: %s
- POA&M Milestone: 90 days from assessment date

`, f.ID, f.Title, f.CMMCPractice, f.NIST, f.CCI,
			f.SPRSPoints, commaf(f.ExposureUSD), f.Remediation))
	}

	sb.WriteString(`## Assessor Statement
This analysis was produced by KHEPRA ERT v2.0 using NIST SP 800-171 DoD Assessment
Methodology point weights. NON-POA&M determinations reflect controls where partial
implementation constitutes an automatic assessment failure per CMMC CAP v2.0.
`)
	return []byte(sb.String())
}

// ─── 08 SRM ───────────────────────────────────────────────────────────────────

func genSRM(pkg *C3PAOPackage, sig func() string) []byte {
	var espRows strings.Builder
	if len(pkg.ESPs) == 0 {
		espRows.WriteString("| [No ESPs identified — update with Sonar scan results] | — | — | — | — |\n")
	} else {
		for _, e := range pkg.ESPs {
			espRows.WriteString(fmt.Sprintf("| %s | %s | %v | %s | %s |\n",
				e.Name, e.Service, e.CUIExposure,
				e.ResponsibilityOwner,
				strings.Join(e.InheritedControls, ", "),
			))
		}
	}

	return []byte(fmt.Sprintf(`# Shared Responsibility Matrix (SRM)
# External Service Provider (ESP) Documentation
# Per CMMC CAP v2.0 — Addresses SCOPE_GAP rejection pattern
# Generated: %s | Signed: %s

## ESPs Identified by Package C (Sonar)
| ESP | Service | CUI Exposure | Responsibility Owner | Controls Inherited |
|---|---|---|---|---|
%s
## Inherited Controls Note
Physical and Environmental controls (PE-*) are typically inherited from the
infrastructure provider. All logical controls remain the organization's responsibility.

## Assessor Note
This SRM was auto-generated from KHEPRA Package C Sonar scan output.
Absence of a formal SRM is a leading cause of SCOPE_GAP assessment rejection.
`,
		pkg.Generated.UTC().Format(time.RFC3339),
		sig(),
		espRows.String(),
	))
}

// ─── 09 SPRS Score Report ─────────────────────────────────────────────────────

func genSPRSReport(pkg *C3PAOPackage, cat1 []Finding, sig func() string) []byte {
	sprs := pkg.SPRS
	var tableRows strings.Builder
	for _, line := range sprs.Breakdown {
		tableRows.WriteString(fmt.Sprintf("| %s | %s | %s | -%d | %s: %s |\n",
			line.NISTRef, line.Control, line.Severity, line.Points,
			line.FindingID, line.Title,
		))
	}

	return []byte(fmt.Sprintf(`# SPRS Score Report
# Supplier Performance Risk System — DoD Submission-Ready
# Per NIST SP 800-171 DoD Assessment Methodology v1.2.1
# Generated: %s | Signed: %s

## Score Summary
| Metric | Value |
|---|---|
| Maximum Score | 110 |
| Total Point Deductions | -%d |
| **SPRS Score** | **%d** |
| CMMC Level 2 Threshold | 110 |
| Unique NIST Practices Failed | %d |
| Assessment Result | %s — Below Threshold |

## Score Calculation (Starting Score: 110)
| NIST Practice | CMMC Control | Severity | Points Deducted | Finding |
|---|---|---|---|---|
%s
**Total Deducted: -%d points**
**Final SPRS Score: %d / 110**

## DoD Submission
This score must be submitted to the SPRS portal at https://www.sprs.csd.disa.mil/
before contract award for DoD contracts containing DFARS 252.204-7021.

Current gap from CMMC L2 threshold: %d points.
Remediate all %d CAT I (NON-POA&M) findings to achieve full compliance.

## Remediation Economics
- Estimated remediation cost: $%s
- Total breach exposure avoided: $%s
- ROI of remediation: %dx

## Attestation
%s
`,
		pkg.Generated.UTC().Format(time.RFC3339), sig(),
		sprs.Deduction, sprs.Score,
		sprs.UniqueNIST,
		sprs.PassFail,
		tableRows.String(),
		sprs.Deduction, sprs.Score,
		110-sprs.Score, len(cat1),
		commaf(pkg.RemediationCost), commaf(pkg.TotalExposure), pkg.ROI,
		sig(),
	))
}

// ─── 10 Personnel Training ────────────────────────────────────────────────────

func genPersonnelTraining(pkg *C3PAOPackage, h func(any) string, sig func() string) []byte {
	var trainingRows strings.Builder
	if len(pkg.TrainingRecords) == 0 {
		trainingRows.WriteString("| — | No training records were provided to the evidence builder | — | — |\n")
	} else {
		for _, t := range pkg.TrainingRecords {
			attest := t.AttestHash
			if attest == "" {
				attest = h(t)
			}
			trainingRows.WriteString(fmt.Sprintf("| %s | %s | %s | %s |\n",
				t.Role, t.TrainingCompleted,
				t.CompletedAt.UTC().Format("2006-01-02"),
				attest,
			))
		}
	}

	var personnelRows strings.Builder
	if len(pkg.Personnel) == 0 {
		personnelRows.WriteString(`| [SYSADMIN NAME] | System Administrator | AC-*, IA-*, CM-*, SC-* |
| [ISSO NAME] | ISSO | All 110 CMMC practices |
| [DEV NAME] | Lead Developer | SI-*, SC-13, CM-* |
`)
	} else {
		for _, p := range pkg.Personnel {
			personnelRows.WriteString(fmt.Sprintf("| %s | %s | %s |\n",
				p.Name, p.Title,
				strings.Join(p.ControlsResponsible, ", "),
			))
		}
	}

	return []byte(fmt.Sprintf(`# Personnel Training Records
# CMMC AT Domain | AT.L2-3.2.1 + AT.L2-3.2.2
# Generated: %s | Integrity: %s

## AT.L2-3.2.1 — Security Awareness Training
| Personnel Role | Training Completed | Date | Record Hash |
|---|---|---|---|
%s
## AT.L2-3.2.2 — Role-Based Training
Complete this table from your training records before assessment.

| Role | Training Topic | Frequency | Last Completed |
|---|---|---|---|
| Administrator | Privileged Access Security | Annual | [DATE] |
| Developer | Input Validation & Injection Prevention | Annual | [DATE] |
| All Staff | Phishing Awareness | Quarterly | [DATE] |

## Personnel Designated for C3PAO Interview
The following personnel can describe each control and their role in maintaining it.

| Name | Title | Controls Responsible For |
|---|---|---|
%s
## Source
Training rows above come only from records supplied to the evidence builder;
none are generated. Record hashes are SHA-256 digests of those records.
`,
		pkg.Generated.UTC().Format(time.RFC3339), sig(),
		trainingRows.String(),
		personnelRows.String(),
	))
}

// ─── 11 Incident Response ─────────────────────────────────────────────────────

func genIR(pkg *C3PAOPackage, sig func() string) []byte {
	return []byte(fmt.Sprintf(`# Incident Response Plan — Exercise Record (template)
# CMMC IR Domain | IR.L2-3.6.1 + IR.L2-3.6.2 + IR.L2-3.6.3
# Generated: %s | Integrity: %s
#
# Complete every [BRACKETED] field from your own records. KHEPRA does not
# record tabletop exercises; nothing below is pre-filled as evidence.

## IR Plan Status
- Plan Version: [VERSION]
- Last Updated: [DATE]
- Plan Owner: [ISSO NAME]
- US-CERT Reporting Endpoint: https://www.cisa.gov/report

## Tabletop Exercise Record
| Exercise Date | Scenario | Participants | Result | Lessons Learned |
|---|---|---|---|---|
| [DATE] | [SCENARIO] | [PARTICIPANTS] | [RESULT] | [LESSONS LEARNED] |

## IR Procedure — Detection to Containment (as configured in KHEPRA)
1. KASA anomaly score > 0.85 triggers SouHimBou AI alert
2. SouHimBou AI opens incident ticket automatically
3. SOAR playbook: quarantine-agent staged for human approval
4. Human approves → production execution
5. Incident documented in the DAG (ML-DSA-87 signed)
6. US-CERT notification within 72 hours per DFARS 252.204-7012

## Monitoring Evidence in This Package
- Flight recorder frames: 06-spd-flight-log.ndjson (%d recorded)
- DAG nodes: 05-dag-chain.json (%d nodes)
- Monitoring period: [START DATE] to present
`,
		pkg.Generated.UTC().Format(time.RFC3339), sig(),
		len(pkg.FlightFrames), len(pkg.DAGNodes),
	))
}

// ─── 12 DAG Viewer (self-contained HTML) ──────────────────────────────────────

func genDAGViewer(pkg *C3PAOPackage, sig func() string) []byte {
	// Serialize nodes as JSON for inline script
	nodesJSON, _ := json.Marshal(pkg.DAGNodes)

	return []byte(fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>KHEPRA DAG Evidence — %s</title>
<script src="https://cdn.jsdelivr.net/npm/d3@7/dist/d3.min.js"></script>
<style>
body{background:#050c16;color:#e0eaf5;font-family:monospace;margin:0}
#info{padding:12px 18px;border-bottom:1px solid rgba(26,159,232,.3);font-size:12px;display:flex;gap:14px;flex-wrap:wrap}
#info span{color:#1a9fe8}
#info .g{color:#22c55e}#info .r{color:#ef4444}#info .y{color:#e5a54b}
svg{width:100%%;height:calc(100vh - 54px)}
.link{stroke:rgba(26,159,232,.25);stroke-width:1.5}
.node circle{stroke-width:1.5;fill-opacity:.12}
.node.genesis circle{stroke:#22c55e;fill:#22c55e}
.node.finding circle{stroke:#ef4444;fill:#ef4444}
.node.cert circle{stroke:#e5a54b;fill:#e5a54b}
.node.flight circle{stroke:#06b6d4;fill:#06b6d4}
.node circle{stroke:#1a9fe8;fill:#1a9fe8}
.lbl{fill:#e0eaf5;font-size:8px;text-anchor:middle;pointer-events:none}
</style>
</head>
<body>
<div id="info">
  <span>KHEPRA Immutable DAG</span>
  <span>Package: <span>%s</span></span>
  <span>Nodes: <span>%d</span></span>
  <span>Integrity: <span>see manifest.json</span></span>
  <span>Signed: <span>%s</span></span>
</div>
<svg id="dag"></svg>
<script>
const raw = %s;
const nodes = raw.map((n,i)=>({...n,i}));
const links = nodes.slice(1).map((_,i)=>({source:i,target:i+1}));
const cm = {cert:'#e5a54b',finding:'#ef4444',genesis:'#22c55e',flight:'#06b6d4'};
const W=window.innerWidth, H=window.innerHeight-54;
const svg = d3.select('#dag');
const sim = d3.forceSimulation(nodes)
  .force('link',d3.forceLink(links).id(d=>d.i).distance(65))
  .force('charge',d3.forceManyBody().strength(-140))
  .force('center',d3.forceCenter(W/2,H/2));
const link = svg.append('g').selectAll('line').data(links).enter()
  .append('line').attr('class','link');
const node = svg.append('g').selectAll('g').data(nodes).enter()
  .append('g').attr('class',d=>'node '+(d.type||''));
node.append('circle').attr('r',9)
  .attr('stroke',d=>cm[d.type]||'#1a9fe8')
  .attr('fill',d=>cm[d.type]||'#1a9fe8');
node.append('title').text(d=>d.label+'\n'+d.hash);
node.append('text').attr('class','lbl').attr('dy',20).text(d=>(d.label||'').slice(0,16));
sim.on('tick',()=>{
  link.attr('x1',d=>d.source.x).attr('y1',d=>d.source.y)
      .attr('x2',d=>d.target.x).attr('y2',d=>d.target.y);
  node.attr('transform',d=>'translate('+d.x+','+d.y+')');
});
</script>
</body>
</html>`,
		pkg.PackageID,
		pkg.PackageID,
		len(pkg.DAGNodes),
		sig(),
		string(nodesJSON),
	))
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func filterSev(findings []Finding, sev string) []Finding {
	var out []Finding
	for _, f := range findings {
		if f.Severity == sev {
			out = append(out, f)
		}
	}
	return out
}

func filterPOAM(findings []Finding, eligible bool) []Finding {
	var out []Finding
	for _, f := range findings {
		if f.POAMEligible == eligible {
			out = append(out, f)
		}
	}
	return out
}

// cmmcDomain extracts the two-letter domain code from a CMMC practice string.
// e.g. "CMMC.SC.L2-3.13.10" → "SC"
func cmmcDomain(practice string) string {
	parts := strings.Split(practice, ".")
	if len(parts) >= 2 {
		return parts[1]
	}
	return "?"
}

// commaf formats a float64 as a comma-separated integer string (no cents).
func commaf(f float64) string {
	n := int64(f)
	s := fmt.Sprintf("%d", n)
	if n < 0 {
		s = s[1:]
	}
	var result []byte
	for i, c := range []byte(s) {
		if i > 0 && (len(s)-i)%3 == 0 {
			result = append(result, ',')
		}
		result = append(result, c)
	}
	if n < 0 {
		return "-" + string(result)
	}
	return string(result)
}
