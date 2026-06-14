package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/dag"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/ert"
)

// ertCmd runs integrated ERT analysis with full ecosystem integration
func ertCmd(args []string) {
	if len(args) < 1 {
		fmt.Println("Usage: adinkhepra ert <subcommand>")
		fmt.Println()
		fmt.Println("Subcommands:")
		fmt.Println("  full [dir]        - Run complete integrated ERT analysis (all 4 packages)")
		fmt.Println("  readiness [dir]   - Package A: Strategic Weapons System")
		fmt.Println("  architect [dir]   - Package B: Operational Weapons System")
		fmt.Println("  crypto [dir]      - Package C: Tactical Weapons System")
		fmt.Println("  godfather [dir]   - Package D: The Godfather Report")
		fmt.Println()
		fmt.Println("The 'full' subcommand integrates with:")
		fmt.Println("  - CVE Database (real vulnerability data)")
		fmt.Println("  - STIG Validation (compliance gaps)")
		fmt.Println("  - Sonar Scanner (network intelligence)")
		fmt.Println("  - Immutable DAG (audit trail)")
		fmt.Println()
		return
	}

	subcommand := args[0]
	targetDir := "."
	if len(args) > 1 {
		targetDir = args[1]
	}

	switch subcommand {
	case "full":
		ertFullCmd(targetDir)
	case "readiness":
		ertReadinessCmd(args[1:]) // Use existing command
	case "architect":
		ertArchitectCmd(args[1:]) // Use existing command
	case "crypto":
		ertCryptoCmd(args[1:]) // Use existing command
	case "godfather":
		ertGodfatherCmd(args[1:]) // Use existing command
	default:
		fmt.Printf("Unknown subcommand: %s\n", subcommand)
		fmt.Println("Run 'adinkhepra ert' for usage information")
	}
}

// ertFullCmd runs complete integrated ERT analysis
func ertFullCmd(targetDir string) {
	fmt.Println("\033[97m") // White/Bold text
	fmt.Println("================================================================")
	fmt.Println(" KHEPRA PROTOCOL // EXECUTIVE ROUNDTABLE (ERT)")
	fmt.Println(" INTEGRATED INTELLIGENCE ANALYSIS")
	fmt.Println("================================================================")
	fmt.Print("\033[0m")
	fmt.Println()

	fmt.Printf("Target Directory: %s\n", targetDir)
	fmt.Println()

	// Initialize DAG memory
	fmt.Println("[*] Initializing Immutable DAG...")
	dagMem := dag.NewMemory()

	// Create genesis node
	genesis := &dag.Node{
		Action: "ERT_ANALYSIS_START",
		Symbol: "GENESIS",
		Time:   "2026-01-12T00:00:00Z",
	}
	if err := dagMem.Add(genesis, []string{}); err != nil {
		fmt.Printf("Warning: Genesis node creation failed: %v\n", err)
	}

	// Initialize ERT engine
	fmt.Println("[*] Initializing ERT Intelligence Engine...")
	engine, err := ert.NewEngine(targetDir, "production", dagMem)
	if err != nil {
		fmt.Printf("❌ FATAL: ERT engine initialization failed: %v\n", err)
		os.Exit(1)
	}

	// Load data sources
	fmt.Println("[*] Loading CVE Database...")
	stats := engine.GetCVEDatabase().Stats()
	fmt.Printf("    -> Total CVEs: %d\n", stats["total_cves"])
	fmt.Printf("    -> Known Exploited: %d\n", stats["known_exploited"])
	fmt.Printf("    -> Critical: %d\n", stats["critical"])
	fmt.Println()

	// Run full analysis
	fmt.Println("[*] Running Full Executive Roundtable Analysis...")
	fmt.Println("    This integrates:")
	fmt.Println("    - Package A: Strategic Readiness (STIG + Compliance)")
	fmt.Println("    - Package B: Architecture (CVE + Supply Chain)")
	fmt.Println("    - Package C: Crypto Analysis (PQC + IP Lineage)")
	fmt.Println("    - Package D: Godfather Synthesis (Business Impact)")
	fmt.Println()

	intel, err := engine.RunFullAnalysis()
	if err != nil {
		fmt.Printf("❌ FATAL: ERT analysis failed: %v\n", err)
		os.Exit(1)
	}

	// Display results
	fmt.Println("\n\033[1m═══════════════════════════════════════════════════════════════")
	fmt.Println(" PACKAGE A: STRATEGIC READINESS")
	fmt.Println("═══════════════════════════════════════════════════════════════\033[0m")
	fmt.Printf("\nStrategic Alignment Score: %d/100\n", intel.Readiness.AlignmentScore)
	fmt.Printf("STIG Compliance Score:     %d/100\n", intel.Readiness.STIGScore)
	fmt.Printf("Strategy Documents Found:  %d\n", len(intel.Readiness.StrategyDocs))
	fmt.Printf("Compliance Gaps:           %d\n", len(intel.Readiness.ComplianceGaps))
	fmt.Printf("Regulatory Conflicts:      %d\n", len(intel.Readiness.RegulatoryConflicts))

	if len(intel.Readiness.ComplianceGaps) > 0 {
		fmt.Println("\nCritical Compliance Gaps:")
		for i, gap := range intel.Readiness.ComplianceGaps {
			if i >= 5 {
				fmt.Printf("... and %d more\n", len(intel.Readiness.ComplianceGaps)-5)
				break
			}
			fmt.Printf("  [%s] %s: %s\n", gap.Severity, gap.Framework, gap.Description)
		}
	}

	fmt.Println("\n\033[1m═══════════════════════════════════════════════════════════════")
	fmt.Println(" PACKAGE B: ARCHITECTURE & SUPPLY CHAIN")
	fmt.Println("═══════════════════════════════════════════════════════════════\033[0m")
	fmt.Printf("\nModules Analyzed:          %d\n", intel.Architecture.ModuleCount)
	fmt.Printf("Total Files:               %d\n", intel.Architecture.FileCount)
	fmt.Printf("Dependencies:              %d\n", len(intel.Architecture.DependencyGraph))
	fmt.Printf("Vulnerable Dependencies:   %d\n", len(intel.Architecture.VulnerableDeps))
	fmt.Printf("Shadow IT Detected:        %d\n", len(intel.Architecture.ShadowIT))
	fmt.Printf("Friction Points:           %d\n", len(intel.Architecture.FrictionPoints))

	if len(intel.Architecture.VulnerableDeps) > 0 {
		fmt.Println("\nVulnerable Dependencies:")
		for i, dep := range intel.Architecture.VulnerableDeps {
			if i >= 5 {
				fmt.Printf("... and %d more\n", len(intel.Architecture.VulnerableDeps)-5)
				break
			}
			exploitFlag := ""
			if dep.Exploitable {
				exploitFlag = " [EXPLOITED IN WILD]"
			}
			fmt.Printf("  [%s] %s (%d CVEs)%s\n", dep.Severity, dep.Package, len(dep.CVEs), exploitFlag)
		}
	}

	fmt.Println("\n\033[1m═══════════════════════════════════════════════════════════════")
	fmt.Println(" PACKAGE C: CRYPTOGRAPHY & IP LINEAGE")
	fmt.Println("═══════════════════════════════════════════════════════════════\033[0m")
	fmt.Printf("\nPQC Readiness:             %s\n", intel.Crypto.PQCReadiness)
	fmt.Printf("Source Files Hashed:       %d\n", len(intel.Crypto.SourceHashes))
	fmt.Println("\nCryptographic Primitives:")
	fmt.Printf("  RSA:                     %d uses\n", intel.Crypto.CryptoUsage.RSA)
	fmt.Printf("  ECDSA:                   %d uses\n", intel.Crypto.CryptoUsage.ECDSA)
	fmt.Printf("  AES:                     %d uses\n", intel.Crypto.CryptoUsage.AES)
	fmt.Printf("  Kyber (PQC):             %d uses\n", intel.Crypto.CryptoUsage.Kyber)
	fmt.Printf("  Dilithium (PQC):         %d uses\n", intel.Crypto.CryptoUsage.Dilithium)

	fmt.Println("\nIntellectual Property Lineage:")
	fmt.Printf("  Proprietary:             %.1f%%\n", intel.Crypto.IPLineage.Proprietary)
	fmt.Printf("  Open Source (MIT/Apache):%.1f%%\n", intel.Crypto.IPLineage.OSS)
	fmt.Printf("  GPL/Viral:               %.1f%%\n", intel.Crypto.IPLineage.GPL)
	if intel.Crypto.IPLineage.Clean {
		printGreen("  IP Status:               CLEAN ✓")
	} else {
		printRed("  IP Status:               CONTAMINATED ✗")
	}

	fmt.Println("\n\n\033[1m═══════════════════════════════════════════════════════════════")
	fmt.Println(" PACKAGE D: THE GODFATHER REPORT")
	fmt.Println("═══════════════════════════════════════════════════════════════\033[0m")

	// Risk level with color
	fmt.Print("\nExecutive Risk Level:      ")
	switch intel.Godfather.RiskLevel {
	case "CRITICAL":
		printRed(intel.Godfather.RiskLevel)
	case "HIGH":
		printYellow(intel.Godfather.RiskLevel)
	case "MODERATE":
		printYellow(intel.Godfather.RiskLevel)
	default:
		printGreen(intel.Godfather.RiskLevel)
	}

	fmt.Println("\n\nCausal Chain Analysis:")
	for _, link := range intel.Godfather.CausalChain {
		var prefix string
		switch link.Type {
		case "GOAL":
			prefix = "\033[92m[GOAL]\033[0m"
		case "BLOCKER":
			prefix = "\033[91m[BLOCKER]\033[0m"
		case "CONSEQUENCE":
			prefix = "\033[93m[CONSEQUENCE]\033[0m"
		case "ENABLER":
			prefix = "\033[92m[ENABLER]\033[0m"
		default:
			prefix = fmt.Sprintf("[%s]", link.Type)
		}
		fmt.Printf("%d. %s %s\n", link.Step, prefix, link.Description)
	}

	fmt.Println("\n\033[1mRECOMMENDED INTERVENTIONS:\033[0m")
	for _, rec := range intel.Godfather.Recommendations {
		var color string
		switch rec.Priority {
		case "URGENT":
			color = "\033[91m" // Red
		case "STRATEGIC":
			color = "\033[93m" // Yellow
		default:
			color = "\033[92m" // Green
		}

		fmt.Printf("%s[%s]\033[0m %s\n", color, rec.Priority, rec.Action)
		fmt.Printf("         Impact: %s\n", rec.Impact)
		if rec.ROI != "" {
			fmt.Printf("         ROI: %s\n", rec.ROI)
		}
	}

	fmt.Println("\n\033[1mBUSINESS IMPACT:\033[0m")
	fmt.Printf("Revenue at Risk:           %s\n", intel.Godfather.BusinessImpact.RevenueAtRisk)
	fmt.Printf("Compliance Cost:           %s\n", intel.Godfather.BusinessImpact.ComplianceCost)
	fmt.Printf("Mitigation Cost:           %s\n", intel.Godfather.BusinessImpact.MitigationCost)
	fmt.Printf("Time to Compliance:        %s\n", intel.Godfather.BusinessImpact.TimeToCompliance)

	if len(intel.Godfather.BusinessImpact.KeyRisks) > 0 {
		fmt.Println("\nKey Business Risks:")
		for i, risk := range intel.Godfather.BusinessImpact.KeyRisks {
			fmt.Printf("%d. %s\n", i+1, risk)
		}
	}

	// DAG summary
	fmt.Println("\n\033[1m═══════════════════════════════════════════════════════════════")
	fmt.Println(" IMMUTABLE AUDIT TRAIL")
	fmt.Println("═══════════════════════════════════════════════════════════════\033[0m")
	fmt.Printf("\nDAG Nodes Created:         %d\n", len(dagMem.All()))
	fmt.Println("All ERT findings have been recorded to the immutable DAG.")
	fmt.Println()

	// Save full report
	reportFile := "ert_full_report.json"
	data, err := json.MarshalIndent(intel, "", "  ")
	if err != nil {
		fmt.Printf("⚠️  Warning: Failed to serialize report: %v\n", err)
	} else {
		if err := os.WriteFile(reportFile, data, 0644); err != nil {
			fmt.Printf("⚠️  Warning: Failed to save report: %v\n", err)
		} else {
			fmt.Printf("✅ Full report saved: %s\n", reportFile)
		}
	}

	fmt.Println()
	fmt.Println("═══════════════════════════════════════════════════════════════")
	printGreen("[+] EXECUTIVE ROUNDTABLE ANALYSIS COMPLETE")
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println()
}
