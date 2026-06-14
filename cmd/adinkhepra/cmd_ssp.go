package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/compliance"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/dag"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/stig"
)

func sspCmd(args []string) {
	if len(args) < 1 {
		printSSPUsage()
		return
	}
	switch args[0] {
	case "generate":
		sspGenerateCmd(args[1:])
	case "update":
		sspUpdateCmd(args[1:])
	case "export":
		sspExportCmd(args[1:])
	case "diff":
		sspDiffCmd(args[1:])
	case "status":
		sspStatusCmd(args[1:])
	default:
		printSSPUsage()
	}
}

func printSSPUsage() {
	fmt.Println(`adinkhepra ssp - System Security Plan (NIST SP 800-18 / CMMC Level 2)

Usage:
  adinkhepra ssp generate  [--scan results.json] [--skeleton ssp_skeleton.json] --output ssp_v1.json
  adinkhepra ssp update    --ssp ssp.json --control AC.L2-3.1.1 --status IMPLEMENTED [--narrative "..."]
  adinkhepra ssp export    --ssp ssp.json [--format pdf|json|emass] --output ssp_export.pdf
  adinkhepra ssp diff      --prev ssp_v1.json --curr ssp_v2.json
  adinkhepra ssp status    --ssp ssp.json

Commands:
  generate    Auto-generate SSP from scan results and discovery skeleton
  update      Update a specific control implementation narrative
  export      Export SSP as PDF, JSON, or eMASS-compatible XML
  diff        Compare two SSP versions (shows delta for quarterly refresh)
  status      Show SSP completion status and control coverage

Examples:
  # Generate SSP from fresh scan
  adinkhepra ssp generate --output ssp_v1.json

  # Generate from existing scan results + Phase 0 discovery data
  adinkhepra ssp generate --scan scan_results.json --skeleton ssp_skeleton.json --output ssp_v1.json

  # Update a control manually
  adinkhepra ssp update --ssp ssp_v1.json --control AC.L2-3.1.1 --status IMPLEMENTED \\
    --narrative "Access control enforced via AD Group Policy; MFA required for all privileged users."

  # Export for C3PAO review
  adinkhepra ssp export --ssp ssp_v1.json --format pdf --output ssp_for_c3pao.pdf`)
}

// NIST SP 800-18 required sections
type SSPDocument struct {
	// Section 1 — System Identification
	SystemName           string `json:"system_name"`
	SystemAbbreviation   string `json:"system_abbreviation"`
	ResponsibleOrg       string `json:"responsible_organization"`
	InformationOwner     string `json:"information_owner"`
	SystemOwner          string `json:"system_owner"`
	ISSO                 string `json:"isso"` // Information System Security Officer
	AuthorizingOfficial  string `json:"authorizing_official"`

	// Section 2 — System Categorization
	SystemType           string `json:"system_type"`  // Major, Minor, National Security
	CUICategories        []string `json:"cui_categories"`
	ImpactLevel          string `json:"impact_level"` // Low, Moderate, High

	// Section 3 — System Overview
	SystemDescription    string `json:"system_description"`
	SystemEnvironment    string `json:"system_environment"`
	SystemInterconnections []Interconnection `json:"system_interconnections"`

	// Section 4 — System Boundary
	BoundaryDescription  string   `json:"boundary_description"`
	ComponentsInBoundary []string `json:"components_in_boundary"`

	// Section 5 — Information Types / CUI
	CUIDataFlows []CUIDataFlow `json:"cui_data_flows"`

	// Section 6 — Applicable Laws
	ApplicableLaws []string `json:"applicable_laws"`

	// Section 7 — User Roles & Responsibilities
	UserRoles []UserRole `json:"user_roles"`

	// Section 8 — Security Control Implementation (CMMC practices)
	Controls     map[string]compliance.ControlImplementation `json:"controls"`
	ControlStats SSPControlStats                             `json:"control_stats"`

	// Section 9 — Attachments
	POAMReference    string `json:"poam_reference"`
	ScanReferences   []string `json:"scan_references"`

	// Metadata
	Version          string    `json:"version"`
	GeneratedAt      time.Time `json:"generated_at"`
	LastUpdatedAt    time.Time `json:"last_updated_at"`
	DAGChainDepth    int       `json:"dag_chain_depth"`
	PQCSignature     string    `json:"pqc_signature,omitempty"`
}

type Interconnection struct {
	SystemName   string `json:"system_name"`
	Organization string `json:"organization"`
	Protocol     string `json:"protocol"` // TLS 1.3, SSH, IPsec
	PurposeData  string `json:"purpose_and_data"`
	AgreementRef string `json:"agreement_reference"` // MOU/ISA reference
}

type CUIDataFlow struct {
	DataType    string `json:"data_type"`    // CUI category
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Protocol    string `json:"protocol"`
	Encrypted   bool   `json:"encrypted"`
}

type UserRole struct {
	RoleName       string   `json:"role_name"`
	Privileges     []string `json:"privileges"`
	ResponsibilityDesc string `json:"responsibility_description"`
	RequiresTraining   bool `json:"requires_security_training"`
}

type SSPControlStats struct {
	TotalControls     int     `json:"total_controls"`
	Implemented       int     `json:"implemented"`
	Planned           int     `json:"planned"`
	FailedScan        int     `json:"failed_scan"`
	NotApplicable     int     `json:"not_applicable"`
	CompletionPercent float64 `json:"completion_percent"`
}

// generateSSPFromReport populates an SSPDocument from a ComprehensiveReport.
// This is the core Phase 0 → SSP auto-population logic.
func generateSSPFromReport(report *stig.ComprehensiveReport, skeleton *SSPDocument) *SSPDocument {
	doc := &SSPDocument{
		Version:        "1.0",
		GeneratedAt:    time.Now(),
		LastUpdatedAt:  time.Now(),
		Controls:       make(map[string]compliance.ControlImplementation),
		ApplicableLaws: []string{
			"DFARS 252.204-7012 (Safeguarding Covered Defense Information)",
			"DFARS 252.204-7021 (CMMC Requirements)",
			"32 CFR Part 2002 (CUI Program)",
			"NIST SP 800-171 Rev 2",
			"CMMC 2.0 Level 2",
		},
	}

	// Seed from skeleton (Phase 0 discovery output) if provided
	if skeleton != nil {
		doc.SystemName = skeleton.SystemName
		doc.SystemAbbreviation = skeleton.SystemAbbreviation
		doc.ResponsibleOrg = skeleton.ResponsibleOrg
		doc.SystemDescription = skeleton.SystemDescription
		doc.SystemEnvironment = skeleton.SystemEnvironment
		doc.SystemInterconnections = skeleton.SystemInterconnections
		doc.BoundaryDescription = skeleton.BoundaryDescription
		doc.ComponentsInBoundary = skeleton.ComponentsInBoundary
		doc.CUIDataFlows = skeleton.CUIDataFlows
		doc.UserRoles = skeleton.UserRoles
		doc.ISSO = skeleton.ISSO
	}

	// Default values if not seeded
	if doc.SystemName == "" {
		doc.SystemName = report.Hostname
	}
	if doc.ImpactLevel == "" {
		doc.ImpactLevel = "Moderate" // Default for CMMC Level 2
	}
	if doc.CUICategories == nil {
		doc.CUICategories = []string{"Controlled Technical Information (CTI)"}
	}

	// Populate controls from scan results
	implemented, planned, failed, na := 0, 0, 0, 0
	for framework, result := range report.Results {
		for _, finding := range result.Findings {
			status := "PLANNED"
			narrative := fmt.Sprintf(
				"[Auto-generated from %s scan on %s] %s",
				framework, report.ScanDate.Format("2006-01-02"), finding.Description,
			)

			switch finding.Status {
			case "Pass":
				status = "IMPLEMENTED"
				narrative = fmt.Sprintf(
					"[AUTO-VERIFIED %s] Scan confirmed compliant. Evidence: %s. Expected: %s.",
					framework, finding.Actual, finding.Expected,
				)
				implemented++
			case "Fail":
				status = "FAILED_SCAN"
				narrative = fmt.Sprintf(
					"[FAILED %s] %s. Actual: %s. Remediation: %s.",
					framework, finding.Description, finding.Actual, finding.Remediation,
				)
				failed++
			case "Not Applicable":
				status = "N/A"
				na++
			default:
				planned++
			}

			doc.Controls[finding.ID] = compliance.ControlImplementation{
				ControlID:      finding.ID,
				Status:         status,
				Narrative:      narrative,
				LastAudited:    finding.CheckedAt,
				LastScanResult: finding.Actual,
			}
		}
	}

	total := implemented + planned + failed + na
	completionPct := 0.0
	if total > 0 {
		completionPct = float64(implemented) / float64(total) * 100.0
	}

	doc.ControlStats = SSPControlStats{
		TotalControls:     total,
		Implemented:       implemented,
		Planned:           planned,
		FailedScan:        failed,
		NotApplicable:     na,
		CompletionPercent: completionPct,
	}

	return doc
}

func sspGenerateCmd(args []string) {
	fs := flag.NewFlagSet("ssp generate", flag.ExitOnError)
	scanFile := fs.String("scan", "", "Scan results JSON (from adinkhepra compliance scan)")
	skeletonFile := fs.String("skeleton", "", "Phase 0 discovery skeleton JSON")
	output := fs.String("output", "ssp_v1.json", "Output SSP file")
	company := fs.String("company", "", "Company/System name")
	isso := fs.String("isso", "ISSM", "Information System Security Officer name")
	fs.Parse(args)

	fmt.Println("╔══════════════════════════════════════════════════════════════╗")
	fmt.Println("║          KHEPRA PROTOCOL // SSP GENERATOR                   ║")
	fmt.Println("║    System Security Plan — NIST SP 800-18 / CMMC Level 2     ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════╝")
	fmt.Println()

	var report *stig.ComprehensiveReport

	if *scanFile != "" {
		data, err := os.ReadFile(*scanFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading scan file: %v\n", err)
			os.Exit(1)
		}
		report = &stig.ComprehensiveReport{}
		if err := json.Unmarshal(data, report); err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing scan results: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("[*] Loaded scan results from: %s\n", *scanFile)
	} else {
		fmt.Println("[*] Running live assessment to populate SSP...")
		v := stig.NewValidator(".")
		var err error
		report, err = v.Validate()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Scan error: %v\n", err)
			os.Exit(1)
		}
	}

	var skeleton *SSPDocument
	if *skeletonFile != "" {
		data, err := os.ReadFile(*skeletonFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading skeleton: %v\n", err)
			os.Exit(1)
		}
		skeleton = &SSPDocument{}
		json.Unmarshal(data, skeleton)
		fmt.Printf("[*] Seeded from Phase 0 discovery skeleton: %s\n", *skeletonFile)
	}

	doc := generateSSPFromReport(report, skeleton)
	if *company != "" {
		doc.SystemName = *company
	}
	doc.ISSO = *isso

	// Wire to DAG for tamper-evident logging
	dagStore := dag.NewMemory()
	_ = dagStore // DAG integration wired in Sprint B (POAM lifecycle)

	// Serialize
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "SSP serialization error: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(*output, data, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Write error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\n✓ SSP generated: %s\n", *output)
	fmt.Printf("  Controls documented:   %d\n", doc.ControlStats.TotalControls)
	fmt.Printf("  IMPLEMENTED:           %d\n", doc.ControlStats.Implemented)
	fmt.Printf("  FAILED / Needs POAM:   %d\n", doc.ControlStats.FailedScan)
	fmt.Printf("  Completion:            %.1f%%\n", doc.ControlStats.CompletionPercent)
	fmt.Println()
	fmt.Println("  Next steps:")
	fmt.Println("    adinkhepra ssp export --ssp", *output, "--format pdf --output ssp_for_c3pao.pdf")
	fmt.Println("    adinkhepra poam generate --scan scan_results.json --output poam_v1.pdf")
}

func sspUpdateCmd(args []string) {
	fs := flag.NewFlagSet("ssp update", flag.ExitOnError)
	sspFile := fs.String("ssp", "", "SSP JSON file")
	controlID := fs.String("control", "", "Control ID (e.g., AC.L2-3.1.1)")
	status := fs.String("status", "IMPLEMENTED", "Status: IMPLEMENTED|PLANNED|N/A|PARTIAL")
	narrative := fs.String("narrative", "", "Implementation narrative")
	fs.Parse(args)

	if *sspFile == "" || *controlID == "" {
		fmt.Fprintln(os.Stderr, "Error: --ssp and --control required")
		os.Exit(1)
	}

	data, err := os.ReadFile(*sspFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	var doc SSPDocument
	json.Unmarshal(data, &doc)

	doc.Controls[*controlID] = compliance.ControlImplementation{
		ControlID:   *controlID,
		Status:      *status,
		Narrative:   *narrative,
		LastAudited: time.Now(),
	}
	doc.LastUpdatedAt = time.Now()

	newData, _ := json.MarshalIndent(doc, "", "  ")
	os.WriteFile(*sspFile, newData, 0644)
	fmt.Printf("✓ Updated control %s → %s\n", *controlID, *status)
}

func sspExportCmd(args []string) {
	fs := flag.NewFlagSet("ssp export", flag.ExitOnError)
	sspFile := fs.String("ssp", "", "SSP JSON file")
	format := fs.String("format", "pdf", "Export format: pdf, markdown, json")
	output := fs.String("output", "ssp_export.pdf", "Output file")
	fs.Parse(args)

	data, err := os.ReadFile(*sspFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	var doc SSPDocument
	json.Unmarshal(data, &doc)

	switch strings.ToLower(*format) {
	case "json":
		newData, _ := json.MarshalIndent(doc, "", "  ")
		os.WriteFile(*output, newData, 0644)
	case "markdown", "md":
		exportSSPMarkdown(&doc, *output)
	default: // pdf
		outPath := *output
		if !strings.HasSuffix(outPath, ".pdf") {
			outPath += ".pdf"
		}
		exportData := &stig.SSPExportData{
			SystemName:          doc.SystemName,
			SystemAbbreviation:  doc.SystemAbbreviation,
			ResponsibleOrg:      doc.ResponsibleOrg,
			SystemOwner:         doc.SystemOwner,
			ISSO:                doc.ISSO,
			AuthorizingOfficial: doc.AuthorizingOfficial,
			ImpactLevel:         doc.ImpactLevel,
			CUICategories:       doc.CUICategories,
			SystemDescription:   doc.SystemDescription,
			SystemEnvironment:   doc.SystemEnvironment,
			BoundaryDescription: doc.BoundaryDescription,
			ApplicableLaws:      doc.ApplicableLaws,
			Version:             doc.Version,
			GeneratedAt:         doc.GeneratedAt,
			LastUpdatedAt:       doc.LastUpdatedAt,
			DAGChainDepth:       doc.DAGChainDepth,
			PQCSignature:        doc.PQCSignature,
			TotalControls:       doc.ControlStats.TotalControls,
			Implemented:         doc.ControlStats.Implemented,
			FailedScan:          doc.ControlStats.FailedScan,
			Planned:             doc.ControlStats.Planned,
			CompletionPercent:   doc.ControlStats.CompletionPercent,
			Controls:            make(map[string]string),
		}
		for id, ctrl := range doc.Controls {
			exportData.Controls[id] = ctrl.Status
		}
		if err := stig.ExportSSPToPDF(exportData, outPath); err != nil {
			fmt.Fprintf(os.Stderr, "PDF export error: %v\n", err)
			os.Exit(1)
		}
		*output = outPath
	}
	fmt.Printf("✓ SSP exported: %s\n", *output)
}

func exportSSPMarkdown(doc *SSPDocument, outputPath string) {
	if strings.HasSuffix(outputPath, ".pdf") {
		outputPath = strings.TrimSuffix(outputPath, ".pdf") + "_ssp.md"
		fmt.Printf("[*] Note: Full PDF render in G-8 sprint — emitting Markdown: %s\n", outputPath)
	}

	var sb strings.Builder
	sb.WriteString("# SYSTEM SECURITY PLAN (SSP)\n")
	sb.WriteString("## NIST SP 800-18 / CMMC Level 2\n\n")
	sb.WriteString(fmt.Sprintf("**System Name:** %s  \n", doc.SystemName))
	sb.WriteString(fmt.Sprintf("**ISSO:** %s  \n", doc.ISSO))
	sb.WriteString(fmt.Sprintf("**Generated:** %s  \n", doc.GeneratedAt.Format("January 2, 2006")))
	sb.WriteString(fmt.Sprintf("**Impact Level:** %s  \n\n", doc.ImpactLevel))

	sb.WriteString("---\n\n## 1. System Identification\n\n")
	sb.WriteString(fmt.Sprintf("- **Organization:** %s\n", doc.ResponsibleOrg))
	sb.WriteString(fmt.Sprintf("- **System Owner:** %s\n", doc.SystemOwner))
	sb.WriteString(fmt.Sprintf("- **ISSO:** %s\n", doc.ISSO))
	sb.WriteString(fmt.Sprintf("- **AO:** %s\n\n", doc.AuthorizingOfficial))

	sb.WriteString("## 2. System Categorization\n\n")
	sb.WriteString(fmt.Sprintf("- **Impact Level:** %s\n", doc.ImpactLevel))
	sb.WriteString(fmt.Sprintf("- **CUI Categories:** %s\n\n", strings.Join(doc.CUICategories, ", ")))

	sb.WriteString("## 3. System Overview\n\n")
	sb.WriteString(doc.SystemDescription)
	sb.WriteString("\n\n")

	sb.WriteString("## 4. System Boundary\n\n")
	sb.WriteString(doc.BoundaryDescription)
	sb.WriteString("\n\n")

	sb.WriteString("## 5. Applicable Laws & Regulations\n\n")
	for _, law := range doc.ApplicableLaws {
		sb.WriteString(fmt.Sprintf("- %s\n", law))
	}

	sb.WriteString("\n## 6. Security Control Implementation\n\n")
	sb.WriteString(fmt.Sprintf("**Coverage:** %.1f%% (%d / %d controls documented)  \n\n",
		doc.ControlStats.CompletionPercent,
		doc.ControlStats.Implemented,
		doc.ControlStats.TotalControls,
	))

	sb.WriteString("| Control ID | Status | Last Audited |\n")
	sb.WriteString("|---|---|---|\n")
	for id, ctrl := range doc.Controls {
		sb.WriteString(fmt.Sprintf("| %s | %s | %s |\n",
			id, ctrl.Status, ctrl.LastAudited.Format("2006-01-02")))
	}

	os.WriteFile(outputPath, []byte(sb.String()), 0644)
}

func sspDiffCmd(args []string) {
	fs := flag.NewFlagSet("ssp diff", flag.ExitOnError)
	prevFile := fs.String("prev", "", "Previous SSP JSON")
	currFile := fs.String("curr", "", "Current SSP JSON")
	fs.Parse(args)

	prevData, _ := os.ReadFile(*prevFile)
	currData, _ := os.ReadFile(*currFile)

	var prev, curr SSPDocument
	json.Unmarshal(prevData, &prev)
	json.Unmarshal(currData, &curr)

	fmt.Println("SSP DELTA REPORT")
	fmt.Println("════════════════")
	changed := 0
	for id, currCtrl := range curr.Controls {
		prevCtrl, exists := prev.Controls[id]
		if !exists {
			fmt.Printf("[NEW]     %s → %s\n", id, currCtrl.Status)
			changed++
		} else if prevCtrl.Status != currCtrl.Status {
			fmt.Printf("[CHANGED] %s: %s → %s\n", id, prevCtrl.Status, currCtrl.Status)
			changed++
		}
	}
	if changed == 0 {
		fmt.Println("No changes detected between SSP versions.")
	} else {
		fmt.Printf("\n%d control(s) changed.\n", changed)
	}
}

func sspStatusCmd(args []string) {
	fs := flag.NewFlagSet("ssp status", flag.ExitOnError)
	sspFile := fs.String("ssp", "", "SSP JSON file")
	fs.Parse(args)

	data, err := os.ReadFile(*sspFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	var doc SSPDocument
	json.Unmarshal(data, &doc)

	fmt.Printf("\nSSP STATUS — %s\n", doc.SystemName)
	fmt.Println("─────────────────────────────────")
	fmt.Printf("Version:       %s\n", doc.Version)
	fmt.Printf("Last updated:  %s\n", doc.LastUpdatedAt.Format("2006-01-02 15:04"))
	fmt.Printf("ISSO:          %s\n", doc.ISSO)
	fmt.Printf("Impact level:  %s\n", doc.ImpactLevel)
	fmt.Println()
	fmt.Printf("Controls implemented:  %d / %d (%.1f%%)\n",
		doc.ControlStats.Implemented, doc.ControlStats.TotalControls, doc.ControlStats.CompletionPercent)
	fmt.Printf("Controls failing scan: %d\n", doc.ControlStats.FailedScan)
	fmt.Printf("Planned (pending):     %d\n", doc.ControlStats.Planned)
}
