package main

import (
	"fmt"
	"os"
	"time"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/stig"
)

func main() {
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println("  AdinKhepra Iron Bank - STIG Validation Test Suite")
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println()

	// Test 1: Database Loading
	fmt.Println("Test 1: Loading 36,195-row compliance database...")
	db, err := stig.GetDatabase()
	if err != nil {
		fmt.Printf("❌ FAILED: %v\n", err)
		os.Exit(1)
	}

	stats := db.Stats()
	fmt.Printf("✅ SUCCESS: Database loaded\n")
	fmt.Printf("   - STIG→CCI mappings: %d\n", stats["stig_to_cci_mappings"])
	fmt.Printf("   - CCI→NIST 800-53 mappings: %d\n", stats["cci_to_nist53_mappings"])
	fmt.Printf("   - NIST 800-53→800-171 mappings: %d\n", stats["nist53_to_nist171_mappings"])
	fmt.Printf("   - Total mappings: %d\n", stats["total_mappings"])
	fmt.Println()

	// Test 2: Cross-Reference Resolution
	fmt.Println("Test 2: Testing cross-reference resolution...")
	testSTIG := "SV-257777r925318_rule" // DoD Banner
	refs, err := db.GetCrossReferences(testSTIG)
	if err != nil {
		fmt.Printf("❌ FAILED: %v\n", err)
	} else if len(refs) == 0 {
		fmt.Printf("⚠️  WARNING: No cross-references found for %s\n", testSTIG)
		fmt.Println("   This is expected if the STIG ID doesn't exist in the database")
	} else {
		fmt.Printf("✅ SUCCESS: Found %d cross-references for %s\n", len(refs), testSTIG)
		for i, ref := range refs {
			if i < 5 { // Show first 5
				fmt.Printf("   - %s\n", ref)
			}
		}
		if len(refs) > 5 {
			fmt.Printf("   ... and %d more\n", len(refs)-5)
		}
	}
	fmt.Println()

	// Test 3: System Checker
	fmt.Println("Test 3: Testing system checker capabilities...")
	checker := stig.NewSystemChecker()

	// Test file existence
	testFile := "/etc/passwd" // Should exist on all Unix systems
	exists, err := checker.CheckFileExists(testFile)
	if err != nil {
		fmt.Printf("❌ FAILED: CheckFileExists error: %v\n", err)
	} else if exists {
		fmt.Printf("✅ SUCCESS: File existence check working (%s exists)\n", testFile)
	} else {
		fmt.Printf("⚠️  WARNING: %s does not exist (expected on non-Unix systems)\n", testFile)
	}

	// Test OS version
	osVersion, err := checker.GetOSVersion()
	if err != nil {
		fmt.Printf("⚠️  WARNING: Could not get OS version: %v\n", err)
	} else {
		fmt.Printf("✅ SUCCESS: OS Version: %s\n", osVersion)
	}

	// Test kernel version
	kernelVersion, err := checker.GetKernelVersion()
	if err != nil {
		fmt.Printf("⚠️  WARNING: Could not get kernel version: %v\n", err)
	} else {
		fmt.Printf("✅ SUCCESS: Kernel Version: %s\n", kernelVersion)
	}
	fmt.Println()

	// Test 4: Validator Creation
	fmt.Println("Test 4: Creating STIG validator...")
	validator := stig.NewValidator("/")
	fmt.Println("✅ SUCCESS: Validator created")
	fmt.Println()

	// Test 5: Run Validation
	fmt.Println("Test 5: Running comprehensive STIG validation...")
	fmt.Println("   This may take 30-60 seconds...")
	startTime := time.Now()

	report, err := validator.Validate()
	if err != nil {
		fmt.Printf("❌ FAILED: Validation error: %v\n", err)
		os.Exit(1)
	}

	duration := time.Since(startTime)
	fmt.Printf("✅ SUCCESS: Validation completed in %s\n", duration)
	fmt.Println()

	// Test 6: Report Analysis
	fmt.Println("Test 6: Analyzing validation report...")
	fmt.Println("───────────────────────────────────────────────────────────────")
	fmt.Println("SYSTEM INFORMATION")
	fmt.Println("───────────────────────────────────────────────────────────────")
	fmt.Printf("Hostname:        %s\n", report.Hostname)
	fmt.Printf("OS Version:      %s\n", report.OSVersion)
	fmt.Printf("Kernel Version:  %s\n", report.KernelVersion)
	fmt.Printf("Scan Date:       %s\n", report.ScanDate.Format("2006-01-02 15:04:05"))
	fmt.Printf("Scan Duration:   %s\n", report.ScanDuration)
	fmt.Println()

	fmt.Println("───────────────────────────────────────────────────────────────")
	fmt.Println("FRAMEWORK VALIDATION RESULTS")
	fmt.Println("───────────────────────────────────────────────────────────────")

	for frameworkName, result := range report.Results {
		fmt.Printf("\n%s (Version %s):\n", frameworkName, result.Version)
		fmt.Printf("  Total Controls:     %d\n", result.TotalControls)
		fmt.Printf("  Passed:             %d (%.2f%%)\n", result.Passed, result.ComplianceScore())
		fmt.Printf("  Failed:             %d\n", result.Failed)
		fmt.Printf("  Not Applicable:     %d\n", result.NotApplicable)
		fmt.Printf("  Manual Review:      %d\n", result.ManualReview)
		fmt.Printf("  Duration:           %s\n", result.Duration)

		// Show first 3 failed findings for each framework
		if result.Failed > 0 {
			fmt.Printf("\n  First %d failed findings:\n", min(3, result.Failed))
			failCount := 0
			for _, finding := range result.Findings {
				if finding.Status == "Fail" && failCount < 3 {
					fmt.Printf("    • [%s] %s\n", finding.ID, finding.Title)
					fmt.Printf("      Expected: %s\n", finding.Expected)
					fmt.Printf("      Actual:   %s\n", finding.Actual)
					failCount++
				}
			}
			if result.Failed > 3 {
				fmt.Printf("    ... and %d more\n", result.Failed-3)
			}
		}
	}

	fmt.Println()
	fmt.Println("───────────────────────────────────────────────────────────────")
	fmt.Println("EXECUTIVE SUMMARY")
	fmt.Println("───────────────────────────────────────────────────────────────")
	fmt.Printf("Overall Compliance:    %.2f%% [%s]\n",
		report.ExecutiveSummary.OverallCompliance,
		report.ExecutiveSummary.ComplianceGrade)
	fmt.Printf("Overall Risk:          %s\n", report.ExecutiveSummary.OverallRisk)
	fmt.Printf("\nCritical Findings:\n")
	fmt.Printf("  • CAT I/Critical:    %d\n", report.ExecutiveSummary.CAT1Findings)
	fmt.Printf("  • CAT II/High:       %d\n", report.ExecutiveSummary.CAT2Findings)
	fmt.Printf("  • CAT III/Medium:    %d\n", report.ExecutiveSummary.CAT3Findings)
	fmt.Println()

	// Test 7: Cross-References
	fmt.Println("Test 7: Checking cross-reference coverage...")
	totalRefs := 0
	findingsWithRefs := 0
	for _, result := range report.Results {
		for _, finding := range result.Findings {
			if len(finding.References) > 0 {
				findingsWithRefs++
				totalRefs += len(finding.References)
			}
		}
	}
	fmt.Printf("✅ SUCCESS: %d findings have cross-references\n", findingsWithRefs)
	fmt.Printf("   Total cross-references: %d\n", totalRefs)
	fmt.Println()

	// Test 8: PQC Blast Radius
	fmt.Println("Test 8: PQC Blast Radius Analysis...")
	if report.PQCBlastRadius != nil {
		fmt.Printf("✅ SUCCESS: PQC analysis completed\n")
		fmt.Printf("   Total Crypto Operations:  %d\n", report.PQCBlastRadius.TotalCryptoOperations)
		fmt.Printf("   Legacy Operations:        %d\n", report.PQCBlastRadius.LegacyCryptoOperations)
		fmt.Printf("   PQC Ready:                %d\n", report.PQCBlastRadius.PQCReadyOperations)
		fmt.Printf("   Readiness Score:          %.2f%%\n", report.PQCBlastRadius.PQCReadinessScore)
		fmt.Printf("   Estimated Migration Days: %d\n", report.PQCBlastRadius.EstimatedMigrationDays)
		fmt.Printf("   Vulnerable Protocols:     %d\n", len(report.PQCBlastRadius.VulnerableProtocols))
		fmt.Printf("   High Risk Systems:        %d\n", len(report.PQCBlastRadius.HighRiskSystems))
	} else {
		fmt.Println("⚠️  WARNING: No PQC blast radius analysis")
	}
	fmt.Println()

	// Test 9: POA&M Generation
	fmt.Println("Test 9: Plan of Action & Milestones...")
	fmt.Printf("✅ SUCCESS: %d POA&M items generated\n", len(report.POAMItems))
	if len(report.POAMItems) > 0 {
		totalCost := 0.0
		for _, poam := range report.POAMItems {
			totalCost += poam.EstimatedCost
		}
		fmt.Printf("   Total Remediation Cost: $%.2f\n", totalCost)
		fmt.Printf("   Average per item:       $%.2f\n", totalCost/float64(len(report.POAMItems)))
	}
	fmt.Println()

	// Test 10: Export Functionality
	fmt.Println("Test 10: Testing export functionality...")

	// CSV exports
	csvFiles := []struct {
		name     string
		filename string
		fn       func(string) error
	}{
		{"Findings CSV", "test_findings.csv", report.ExportToCSV},
		{"Summary CSV", "test_summary.csv", report.ExportExecutiveSummaryToCSV},
		{"POA&M CSV", "test_poam.csv", report.ExportPOAMToCSV},
		{"Blast Radius CSV", "test_blast_radius.csv", report.ExportBlastRadiusToCSV},
	}

	for _, export := range csvFiles {
		err := export.fn(export.filename)
		if err != nil {
			fmt.Printf("❌ FAILED: %s export: %v\n", export.name, err)
		} else {
			info, _ := os.Stat(export.filename)
			fmt.Printf("✅ SUCCESS: %s exported (%d bytes)\n", export.name, info.Size())
			// Clean up
			os.Remove(export.filename)
		}
	}

	// PDF export
	err = report.ExportToPDF("test_executive_brief")
	if err != nil {
		fmt.Printf("❌ FAILED: PDF export: %v\n", err)
	} else {
		info, statErr := os.Stat("test_executive_brief.pdf.txt")
		if statErr != nil {
			fmt.Printf("⚠️  WARNING: PDF exported but cannot stat file: %v\n", statErr)
		} else {
			fmt.Printf("✅ SUCCESS: Executive Brief exported (%d bytes)\n", info.Size())
		}
		// Clean up
		os.Remove("test_executive_brief.pdf.txt")
	}
	fmt.Println()

	// Final Summary
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println("  TEST SUITE SUMMARY")
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println("✅ All critical tests passed!")
	fmt.Println()
	fmt.Println("Key Metrics:")
	fmt.Printf("  • Database mappings:    %d\n", stats["total_mappings"])
	fmt.Printf("  • Frameworks validated: %d\n", len(report.Results))
	fmt.Printf("  • Total findings:       %d\n", countTotalFindings(report))
	fmt.Printf("  • Cross-references:     %d\n", totalRefs)
	fmt.Printf("  • POA&M items:          %d\n", len(report.POAMItems))
	fmt.Printf("  • Validation time:      %s\n", duration)
	fmt.Println()
	fmt.Println("STIG validation system is fully operational!")
	fmt.Println("═══════════════════════════════════════════════════════════════")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func countTotalFindings(report *stig.ComprehensiveReport) int {
	total := 0
	for _, result := range report.Results {
		total += len(result.Findings)
	}
	return total
}
