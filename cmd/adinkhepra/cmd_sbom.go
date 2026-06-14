package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/sbom"
)

func sbomCmd(args []string) {
	if len(args) < 1 {
		printSBOMUsage()
		return
	}

	switch args[0] {
	case "generate":
		sbomGenerateCmd(args[1:])
	case "correlate":
		sbomCorrelateCmd(args[1:])
	case "diff":
		sbomDiffCmd(args[1:])
	case "risk-score":
		sbomRiskScoreCmd(args[1:])
	default:
		printSBOMUsage()
	}
}

func printSBOMUsage() {
	fmt.Println(`adinkhepra sbom - Software Bill of Materials Generation

Usage:
  adinkhepra sbom generate --target myapp:latest --scanner syft --output sbom.json
  adinkhepra sbom correlate --input sbom.json --cve-db data/cve-database --output vulnerable.json
  adinkhepra sbom diff --old sbom-v1.json --new sbom-v2.json --output delta.json
  adinkhepra sbom risk-score --input sbom.json --with-cve

Commands:
  generate      Generate SBOM using external scanner (Syft, Trivy, Grype)
  correlate     Correlate components with CVE database
  diff          Compare two SBOMs and detect changes
  risk-score    Calculate context-aware risk score

Scanners:
  syft          Anchore Syft (default)
  trivy         Aqua Trivy
  grype         Anchore Grype

Examples:
  # Generate SBOM for container image
  adinkhepra sbom generate --target myapp:latest --scanner syft

  # Generate SBOM for filesystem
  adinkhepra sbom generate --target /path/to/app --scanner trivy

  # Correlate with CVE database
  adinkhepra sbom correlate --input sbom.json --cve-db data/cve-database

  # Compare two SBOMs
  adinkhepra sbom diff --old v1.0-sbom.json --new v1.1-sbom.json`)
}

func sbomGenerateCmd(args []string) {
	fs := flag.NewFlagSet("sbom generate", flag.ExitOnError)
	target := fs.String("target", "", "Target to scan (image, directory, or binary)")
	scanner := fs.String("scanner", "syft", "Scanner to use (syft, trivy, grype)")
	output := fs.String("output", "sbom.json", "Output SBOM file (CycloneDX JSON)")
	fs.Parse(args)

	if *target == "" {
		fmt.Println("Error: --target is required")
		printSBOMUsage()
		return
	}

	fmt.Printf("[SBOM] Generating Software Bill of Materials...\n")
	fmt.Printf("   - Target: %s\n", *target)
	fmt.Printf("   - Scanner: %s\n", *scanner)

	// Create SBOM generator
	gen := sbom.NewSBOMGenerator(*scanner)

	// Generate SBOM (GenerateSBOM auto-detects target type)
	sbomData, err := gen.GenerateSBOM(*target)
	if err != nil {
		fatal("failed to generate SBOM", err)
	}

	fmt.Printf("   - Target: %s\n", sbomData.Target)
	fmt.Printf("   - Components: %d\n", sbomData.TotalCount)

	// Write to file
	data, err := json.MarshalIndent(sbomData, "", "  ")
	if err != nil {
		fatal("failed to marshal SBOM", err)
	}

	if err := os.WriteFile(*output, data, 0644); err != nil {
		fatal("failed to write SBOM", err)
	}

	fmt.Printf("\n[SUCCESS] SBOM generated.\n")
	fmt.Printf("   - Components: %d\n", len(sbomData.Components))
	fmt.Printf("   - Format: CycloneDX 1.4 JSON\n")
	fmt.Printf("   - Output: %s\n", *output)
	fmt.Println("\n[NEXT] Correlate with CVE database:")
	fmt.Printf("       adinkhepra sbom correlate --input %s --cve-db data/cve-database\n", *output)
}

func sbomCorrelateCmd(args []string) {
	fs := flag.NewFlagSet("sbom correlate", flag.ExitOnError)
	input := fs.String("input", "", "Input SBOM file (required)")
	cveDB := fs.String("cve-db", "data/cve-database", "Path to CVE database")
	output := fs.String("output", "vulnerable-components.json", "Output file")
	fs.Parse(args)

	if *input == "" {
		fmt.Println("Error: --input is required")
		printSBOMUsage()
		return
	}

	fmt.Printf("[SBOM] Correlating with CVE database...\n")
	fmt.Printf("   - SBOM: %s\n", *input)
	fmt.Printf("   - CVE DB: %s\n", *cveDB)

	// Load SBOM
	data, err := os.ReadFile(*input)
	if err != nil {
		fatal("failed to read SBOM", err)
	}

	var sbomData sbom.SBOM
	if err := json.Unmarshal(data, &sbomData); err != nil {
		fatal("failed to parse SBOM", err)
	}

	// Create generator with CVE database
	gen := sbom.NewSBOMGenerator("syft")
	gen.SetCVEDatabase(*cveDB)

	// Correlate vulnerabilities
	vulnerable, err := gen.CorrelateVulnerabilities(&sbomData)
	if err != nil {
		fatal("failed to correlate CVEs", err)
	}

	if len(vulnerable) == 0 {
		fmt.Println("\n[RESULT] No vulnerable components found!")
		return
	}

	fmt.Printf("\n[RESULT] Found %d vulnerable components:\n\n", len(vulnerable))

	criticalCount := 0
	highCount := 0

	for _, comp := range vulnerable {
		fmt.Printf("Component: %s@%s\n", comp.Component.Name, comp.Component.Version)
		fmt.Printf("   - CVEs: %d\n", len(comp.CVEs))
		fmt.Printf("   - Risk Score: %.1f/10.0\n", comp.RiskScore)

		if comp.Exploitable {
			fmt.Println("   - ⚠ ACTIVELY EXPLOITED (CISA KEV)")
			criticalCount++
		}

		if comp.PublicExploit {
			fmt.Println("   - ⚠ PUBLIC EXPLOIT AVAILABLE")
			highCount++
		}

		// Show top 3 CVEs
		for i, cve := range comp.CVEs {
			if i >= 3 {
				break
			}
			fmt.Printf("   - %s\n", cve)
		}
		fmt.Println()
	}

	// Write output
	outData, _ := json.MarshalIndent(vulnerable, "", "  ")
	if err := os.WriteFile(*output, outData, 0644); err != nil {
		fatal("failed to write output", err)
	}

	fmt.Printf("[SUMMARY]\n")
	fmt.Printf("   - Total Vulnerable: %d\n", len(vulnerable))
	fmt.Printf("   - Actively Exploited: %d\n", criticalCount)
	fmt.Printf("   - Public Exploits: %d\n", highCount)
	fmt.Printf("   - Output: %s\n", *output)
}

func sbomDiffCmd(args []string) {
	fs := flag.NewFlagSet("sbom diff", flag.ExitOnError)
	oldSBOM := fs.String("old", "", "Old SBOM file (required)")
	newSBOM := fs.String("new", "", "New SBOM file (required)")
	output := fs.String("output", "sbom-delta.json", "Output diff file")
	fs.Parse(args)

	if *oldSBOM == "" || *newSBOM == "" {
		fmt.Println("Error: --old and --new are required")
		printSBOMUsage()
		return
	}

	fmt.Printf("[SBOM] Comparing SBOMs...\n")
	fmt.Printf("   - Old: %s\n", *oldSBOM)
	fmt.Printf("   - New: %s\n", *newSBOM)

	// Load old SBOM
	oldData, err := os.ReadFile(*oldSBOM)
	if err != nil {
		fatal("failed to read old SBOM", err)
	}

	var old sbom.SBOM
	if err := json.Unmarshal(oldData, &old); err != nil {
		fatal("failed to parse old SBOM", err)
	}

	// Load new SBOM
	newData, err := os.ReadFile(*newSBOM)
	if err != nil {
		fatal("failed to read new SBOM", err)
	}

	var new sbom.SBOM
	if err := json.Unmarshal(newData, &new); err != nil {
		fatal("failed to parse new SBOM", err)
	}

	// Compute diff
	gen := sbom.NewSBOMGenerator("syft")
	diff := gen.ComputeDiff(&old, &new)

	fmt.Printf("\n[RESULT] SBOM Changes:\n\n")
	fmt.Printf("   - Added Components: %d\n", len(diff.Added))
	fmt.Printf("   - Removed Components: %d\n", len(diff.Removed))
	fmt.Printf("   - Updated Components: %d\n", len(diff.Updated))

	if len(diff.Added) > 0 {
		fmt.Println("\nAdded:")
		for _, comp := range diff.Added {
			fmt.Printf("   + %s@%s\n", comp.Name, comp.Version)
		}
	}

	if len(diff.Removed) > 0 {
		fmt.Println("\nRemoved:")
		for _, comp := range diff.Removed {
			fmt.Printf("   - %s@%s\n", comp.Name, comp.Version)
		}
	}

	if len(diff.Updated) > 0 {
		fmt.Println("\nUpdated:")
		for _, update := range diff.Updated {
			fmt.Printf("   ~ %s: %s → %s\n", update.Name, update.OldVersion, update.NewVersion)
		}
	}

	// Write diff
	diffData, _ := json.MarshalIndent(diff, "", "  ")
	if err := os.WriteFile(*output, diffData, 0644); err != nil {
		fatal("failed to write diff", err)
	}

	fmt.Printf("\n[OUTPUT] %s\n", *output)
}

func sbomRiskScoreCmd(args []string) {
	fs := flag.NewFlagSet("sbom risk-score", flag.ExitOnError)
	input := fs.String("input", "", "Input SBOM file (required)")
	withCVE := fs.Bool("with-cve", false, "Include CVE correlation")
	fs.Parse(args)

	if *input == "" {
		fmt.Println("Error: --input is required")
		printSBOMUsage()
		return
	}

	fmt.Printf("[SBOM] Calculating risk score...\n")

	// Load SBOM
	data, err := os.ReadFile(*input)
	if err != nil {
		fatal("failed to read SBOM", err)
	}

	var sbomData sbom.SBOM
	if err := json.Unmarshal(data, &sbomData); err != nil {
		fatal("failed to parse SBOM", err)
	}

	gen := sbom.NewSBOMGenerator("syft")

	var riskScore float64
	if *withCVE {
		// Correlate with CVE first
		vulnerable, err := gen.CorrelateVulnerabilities(&sbomData)
		if err != nil {
			fatal("failed to correlate CVEs", err)
		}

		// Calculate aggregate risk
		for _, comp := range vulnerable {
			riskScore += comp.RiskScore
		}

		if len(vulnerable) > 0 {
			riskScore = riskScore / float64(len(vulnerable))
		}
	} else {
		riskScore = 0.0 // No CVE data
	}

	fmt.Printf("\n[RESULT] Risk Assessment:\n\n")
	fmt.Printf("   - Components: %d\n", len(sbomData.Components))
	fmt.Printf("   - Risk Score: %.1f/10.0\n", riskScore)

	if riskScore >= 7.0 {
		fmt.Println("   - Severity: CRITICAL")
	} else if riskScore >= 4.0 {
		fmt.Println("   - Severity: HIGH")
	} else if riskScore >= 2.0 {
		fmt.Println("   - Severity: MEDIUM")
	} else {
		fmt.Println("   - Severity: LOW")
	}
}
