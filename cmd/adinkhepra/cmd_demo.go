package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/stig"
)

// Demo mode — generates a complete self-serve CMMC assessment in 60 seconds
// using pre-scripted synthetic data embedded at build time.
// No real system is scanned. Safe to run on air-gapped demo laptops.

func demoCmd(args []string) {
	fs := flag.NewFlagSet("demo", flag.ExitOnError)
	company := fs.String("company", "ABC Defense Corp", "Client company name for the demo")
	framework := fs.String("framework", "CMMC_L2", "Compliance framework: CMMC_L2, NIST_800171, STIG")
	output := fs.String("output", "demo_output", "Output directory for demo artifacts")
	fs.Parse(args)

	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════════════════════════╗")
	fmt.Println("║         KHEPRA PROTOCOL // SELF-SERVE DEMO MODE                     ║")
	fmt.Println("║     Synthetic CMMC Assessment — No Real System Required              ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════════════╝")
	fmt.Println()
	fmt.Printf("  Company:     %s\n", *company)
	fmt.Printf("  Framework:   %s\n", *framework)
	fmt.Printf("  Started:     %s\n\n", time.Now().Format("2006-01-02 15:04:05"))

	// Create output directory
	os.MkdirAll(*output, 0755)

	// ── Phase 0: Discovery simulation ──────────────────────────────────────
	fmt.Println("[ Phase 0 ] Environment Discovery...")
	time.Sleep(800 * time.Millisecond)
	fmt.Println("  ✓ Discovered 47 endpoints")
	fmt.Println("  ✓ Identified 12 quantum-vulnerable cryptographic assets")
	fmt.Println("  ✓ Mapped 3 CUI data flows")
	fmt.Println("  ✓ Found 2 external interconnections")
	time.Sleep(300 * time.Millisecond)

	// ── Phase 1: Compliance scan ────────────────────────────────────────────
	fmt.Println("\n[ Phase 1 ] CMMC Level 2 Assessment (110 practices)...")
	time.Sleep(1200 * time.Millisecond)
	report := buildDemoReport(*company)
	fmt.Printf("  ✓ %d practices assessed\n", report.ExecutiveSummary.CAT1Findings+report.ExecutiveSummary.CAT2Findings+report.ExecutiveSummary.CAT3Findings+47)
	fmt.Printf("  ✓ 47 IMPLEMENTED (%.0f%%)\n", report.ExecutiveSummary.CMMCCompliance)
	fmt.Printf("  ✗ %d failing (POAM required)\n",
		report.ExecutiveSummary.CAT1Findings+report.ExecutiveSummary.CAT2Findings+report.ExecutiveSummary.CAT3Findings)
	time.Sleep(300 * time.Millisecond)

	// ── Phase 2: Godfather Report ───────────────────────────────────────────
	fmt.Println("\n[ Phase 2 ] Synthesizing Godfather Report (dollar-denominated risk)...")
	time.Sleep(1000 * time.Millisecond)
	totalExposure := 0.0
	for _, item := range report.POAMItems {
		totalExposure += item.DollarImpact
	}
	fmt.Printf("  ✓ Financial exposure calculated: $%.0fM\n", totalExposure/1_000_000)
	fmt.Printf("  ✓ CAT I findings: %d ($150K each)\n", report.ExecutiveSummary.CAT1Findings)
	fmt.Printf("  ✓ CAT II findings: %d ($50K each)\n", report.ExecutiveSummary.CAT2Findings)
	time.Sleep(300 * time.Millisecond)

	// ── Phase 3: POAM ───────────────────────────────────────────────────────
	fmt.Printf("\n[ Phase 3 ] POAM Register (%d open items, dollar-weighted)...\n", len(report.POAMItems))
	time.Sleep(600 * time.Millisecond)
	fmt.Println("  ✓ POAM generated and priority-sorted")
	fmt.Printf("  ✓ Top priority: %s ($%.0f, due %s)\n",
		report.POAMItems[0].ControlID,
		report.POAMItems[0].DollarImpact,
		report.POAMItems[0].ScheduledCompletion.Format("2006-01-02"),
	)
	time.Sleep(300 * time.Millisecond)

	// ── Phase 4: Blast Radius ───────────────────────────────────────────────
	fmt.Println("\n[ Phase 4 ] Quantum-Readiness Blast Radius (NTI Scoring)...")
	time.Sleep(800 * time.Millisecond)
	fmt.Println("  ✓ Overall NTI Score: 8.7 / 10.0 (HIGH)")
	fmt.Println("  ✓ 12 crypto assets enumerated — 12 VULNERABLE (RSA/ECDSA)")
	fmt.Println("  ✓ Migration effort: 24 days / $60,000")
	fmt.Println("  ✓ Q-Day Horizon: 2030–2035 (NSA CNSA 2.0)")
	time.Sleep(300 * time.Millisecond)

	// ── Phase 5: SSP ───────────────────────────────────────────────────────
	fmt.Println("\n[ Phase 5 ] System Security Plan (NIST SP 800-18)...")
	time.Sleep(600 * time.Millisecond)
	ssp := generateSSPFromReport(report, nil)
	ssp.SystemName = *company
	fmt.Printf("  ✓ SSP generated: %d controls documented (%.0f%% coverage)\n",
		ssp.ControlStats.TotalControls, ssp.ControlStats.CompletionPercent)
	fmt.Printf("  ✓ %d controls IMPLEMENTED, %d needing remediation\n",
		ssp.ControlStats.Implemented, ssp.ControlStats.FailedScan)
	time.Sleep(300 * time.Millisecond)

	// ── Phase 6: Export artifacts ───────────────────────────────────────────
	fmt.Println("\n[ Phase 6 ] Exporting demo artifacts...")

	// Export scan results JSON
	scanPath := *output + "/demo_scan_results.json"
	scanData, _ := json.MarshalIndent(report, "", "  ")
	os.WriteFile(scanPath, scanData, 0644)
	fmt.Printf("  ✓ Scan results: %s\n", scanPath)

	// Export POAM CSV
	poamPath := *output + "/demo_poam.csv"
	exportDemoPOAMCSV(report, poamPath)
	fmt.Printf("  ✓ POAM (CSV):   %s\n", poamPath)

	// Export Blast Radius Markdown
	brPath := *output + "/demo_blast_radius.md"
	exportDemoBlastRadius(*company, brPath)
	fmt.Printf("  ✓ Blast Radius: %s\n", brPath)

	// Export SSP Markdown
	sspPath := *output + "/demo_ssp.md"
	exportSSPMarkdown(ssp, sspPath)
	fmt.Printf("  ✓ SSP:          %s\n", sspPath)

	// ── Summary ─────────────────────────────────────────────────────────────
	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════════════════════════╗")
	fmt.Println("║  DEMO COMPLETE — What KHEPRA Found:                                  ║")
	fmt.Println("║                                                                       ║")
	fmt.Printf("║  Client: %-60s║\n", *company)
	fmt.Printf("║  CMMC Score: %.0f%% compliant (47/110 practices passing)              ║\n",
		report.ExecutiveSummary.CMMCCompliance)
	fmt.Printf("║  Financial Risk: $%.1fM total exposure (IBM breach cost model)       ║\n", totalExposure/1_000_000)
	fmt.Println("║  NTI Score: 8.7/10 — HIGH quantum vulnerability                       ║")
	fmt.Printf("║  POAM: %d open items (priority-sorted, dollar-weighted)               ║\n", len(report.POAMItems))
	fmt.Println("║                                                                       ║")
	fmt.Println("║  To schedule a live demo: https://nouchix.com                         ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════════════╝")
}

// buildDemoReport constructs a synthetic ComprehensiveReport for demo purposes.
// All data is pre-scripted — no real system is scanned.
func buildDemoReport(company string) *stig.ComprehensiveReport {
	now := time.Now()

	findings := []stig.Finding{
		// CAT I (Critical) — 3 findings
		{ID: "AC.L2-3.1.1", Title: "Authorized Access Control", Severity: stig.SeverityCAT1, Status: "Fail", Description: "Multi-factor authentication not enforced for privileged accounts", Remediation: "Enable MFA via Azure AD Conditional Access or equivalent", CheckedAt: now},
		{ID: "AC.L2-3.1.2", Title: "Transaction Privilege Separation", Severity: stig.SeverityCAT1, Status: "Fail", Description: "No separation of duties for privileged operations", Remediation: "Implement Role-Based Access Control with least-privilege principles", CheckedAt: now},
		{ID: "IA.L2-3.5.3", Title: "Multifactor Authentication", Severity: stig.SeverityCAT1, Status: "Fail", Description: "MFA not required for all CUI system access", Remediation: "Deploy MFA tokens (PIV/FIDO2) for all user accounts accessing CUI", CheckedAt: now},

		// CAT II (High) — 5 findings
		{ID: "AU.L2-3.3.1", Title: "System Auditing", Severity: stig.SeverityHigh, Status: "Fail", Description: "Audit logging incomplete — failed login attempts not recorded", Remediation: "Configure centralized SIEM with complete audit trail (90-day retention)", CheckedAt: now},
		{ID: "CM.L2-3.4.1", Title: "Baseline Configuration", Severity: stig.SeverityHigh, Status: "Fail", Description: "No documented baseline configuration for CUI systems", Remediation: "Implement STIG baseline for all endpoints (RHEL 9, Windows Server 2022)", CheckedAt: now},
		{ID: "IR.L2-3.6.1", Title: "Incident Handling", Severity: stig.SeverityHigh, Status: "Fail", Description: "Incident response plan not tested in last 12 months", Remediation: "Conduct tabletop exercise and update IR plan", CheckedAt: now},
		{ID: "SC.L2-3.13.8", Title: "Data in Transit", Severity: stig.SeverityHigh, Status: "Fail", Description: "TLS 1.2 in use on 3 internal services (upgrade to TLS 1.3 required)", Remediation: "Upgrade all services to TLS 1.3 minimum; disable TLS 1.0/1.1/1.2", CheckedAt: now},
		{ID: "SI.L2-3.14.1", Title: "Flaw Remediation", Severity: stig.SeverityHigh, Status: "Fail", Description: "47 CVEs unpatched (12 Critical, 35 High) — patch cycle exceeds 30 days", Remediation: "Implement automated patching with 15-day SLA for Critical/High CVEs", CheckedAt: now},

		// Passing controls (47 of 110)
		{ID: "AC.L1-3.1.20", Title: "External Connections", Severity: stig.SeverityMedium, Status: "Pass", Description: "External connections verified and documented", CheckedAt: now},
		{ID: "MP.L1-3.8.3", Title: "Media Disposal", Severity: stig.SeverityMedium, Status: "Pass", Description: "Media sanitization procedures documented and enforced", CheckedAt: now},
		{ID: "SC.L1-3.13.1", Title: "Boundary Protection", Severity: stig.SeverityMedium, Status: "Pass", Description: "Firewall boundary controls in place", CheckedAt: now},
	}

	results := map[string]*stig.ValidationResult{
		stig.FrameworkCMMC: {
			Framework: stig.FrameworkCMMC,
			Version:   "Level 2",
			Findings:  findings,
			Passed:    47,
			Failed:    8,
			TotalControls: 110,
			StartTime: now.Add(-2 * time.Minute),
			EndTime:   now,
		},
	}

	// Build POAM from findings
	poamItems := []stig.POAMItem{}
	counter := 1
	for _, f := range findings {
		if f.Status != "Fail" {
			continue
		}
		dollarImpact := 50000.0
		severityWeight := 2.0
		days := 14
		if f.Severity == stig.SeverityCAT1 || f.Severity == stig.SeverityCritical {
			dollarImpact = 150000.0
			severityWeight = 3.0
			days = 7
		}
		poamItems = append(poamItems, stig.POAMItem{
			ID:                  fmt.Sprintf("POAM-%d-%03d", now.Year(), counter),
			ControlID:           f.ID,
			Weakness:            f.Description,
			Severity:            f.Severity,
			Status:              "Open",
			PointOfContact:      "ISSM",
			EstimatedCost:       dollarImpact,
			DollarImpact:        dollarImpact,
			SeverityWeight:      severityWeight,
			PriorityScore:       dollarImpact / float64(days) * severityWeight,
			EstimatedDays:       days,
			ScheduledCompletion: now.Add(time.Duration(days) * 24 * time.Hour),
			MilestoneActions:    []string{f.Remediation},
		})
		counter++
	}

	// Sort by priority score
	for i := 0; i < len(poamItems); i++ {
		for j := i + 1; j < len(poamItems); j++ {
			if poamItems[j].PriorityScore > poamItems[i].PriorityScore {
				poamItems[i], poamItems[j] = poamItems[j], poamItems[i]
			}
		}
	}

	return &stig.ComprehensiveReport{
		Hostname:  company,
		OSVersion: "Demo Environment (Synthetic)",
		ScanDate:  now,
		Results:   results,
		POAMItems: poamItems,
		ExecutiveSummary: stig.ExecutiveSummary{
			OverallCompliance:  42.7,
			ComplianceGrade:    "Poor (D)",
			CMMCCompliance:     42.7,
			STIGCompliance:     38.2,
			NIST800171Compliance: 44.1,
			CAT1Findings:       3,
			CAT2Findings:       5,
			CAT3Findings:       2,
			OverallRisk:        "Critical",
			PQCReadinessGrade:  "Critical (F)",
			PQCMigrationRequired: true,
			TopRisks: []string{
				"3 CAT I findings requiring immediate remediation",
				"Post-quantum cryptography migration required (NTI: 8.7/10)",
				"47 CVEs unpatched — breach risk $1.4M+",
			},
			ExecutiveRecommendations: []string{
				"Address 3 CAT I findings within 7 days (MFA, privilege separation, IA)",
				"Implement POAM for all 8 open items",
				"Initiate PQC migration roadmap — Q-Day horizon 2030-2035",
			},
		},
	}
}

func exportDemoPOAMCSV(report *stig.ComprehensiveReport, outputPath string) {
	var sb strings.Builder
	sb.WriteString("POAM ID,Control ID,Severity,Dollar Impact,Priority Score,Est. Days,Due Date,Status,Weakness\n")
	for _, item := range report.POAMItems {
		sb.WriteString(fmt.Sprintf("%s,%s,%s,$%.0f,%.0f,%d,%s,%s,\"%s\"\n",
			item.ID, item.ControlID, item.Severity,
			item.DollarImpact, item.PriorityScore, item.EstimatedDays,
			item.ScheduledCompletion.Format("2006-01-02"),
			item.Status, item.Weakness,
		))
	}
	os.WriteFile(outputPath, []byte(sb.String()), 0644)
}

func exportDemoBlastRadius(company, outputPath string) {
	var sb strings.Builder
	sb.WriteString("# QUANTUM-READINESS BLAST RADIUS REPORT\n")
	sb.WriteString(fmt.Sprintf("## %s — Demo Assessment\n\n", company))
	sb.WriteString("**Overall NTI Score: 8.7 / 10.0 — HIGH**  \n")
	sb.WriteString("**Q-Day Horizon: 2030–2035 (NSA CNSA 2.0)**  \n\n")
	sb.WriteString("| Asset | Type | Algorithm | NTI Score | Status | Phase |\n")
	sb.WriteString("|---|---|---|---|---|---|\n")
	assets := [][]string{
		{"PQC-TLS-001", "TLS_CERT", "RSA-2048", "9.5", "VULNERABLE", "PHASE_1"},
		{"PQC-SSH-001", "SSH_KEY", "Ed25519", "7.1", "VULNERABLE", "PHASE_2"},
		{"PQC-CERT-001", "X509_CERT", "RSA-2048", "8.1", "VULNERABLE", "PHASE_1"},
		{"PQC-VPN-001", "VPN_TUNNEL", "DH-2048", "8.6", "VULNERABLE", "PHASE_1"},
		{"PQC-SIGN-001", "CODE_SIGN", "ECDSA-P256", "8.1", "VULNERABLE", "PHASE_1"},
	}
	for _, a := range assets {
		sb.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s | %s |\n",
			a[0], a[1], a[2], a[3], a[4], a[5]))
	}
	sb.WriteString("\n## Migration Roadmap\n\n")
	sb.WriteString("**Target:** ML-DSA-65 (NIST FIPS 204) + ML-KEM-1024 (NIST FIPS 203)  \n")
	sb.WriteString("**Estimated effort:** 24 days / $60,000  \n\n")
	sb.WriteString("### Phase 1 (< 6 months): TLS + VPN + X.509\n")
	sb.WriteString("### Phase 2 (6–12 months): SSH + Code Signing\n")
	os.WriteFile(outputPath, []byte(sb.String()), 0644)
}
