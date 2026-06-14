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

func blastRadiusCmd(args []string) {
	if len(args) < 1 {
		printBlastRadiusUsage()
		return
	}
	switch args[0] {
	case "scan", "report":
		blastRadiusReportCmd(args[1:])
	case "roadmap":
		blastRadiusRoadmapCmd(args[1:])
	default:
		// Default: treat first arg as a flag
		blastRadiusReportCmd(args)
	}
}

func printBlastRadiusUsage() {
	fmt.Println(`adinkhepra blast-radius - Quantum-Readiness Blast Radius Assessment

Usage:
  adinkhepra blast-radius report  [--scan results.json] [--output blast_radius.pdf]
  adinkhepra blast-radius roadmap [--scan results.json] [--output pqc_roadmap.pdf]

Commands:
  report    Full blast radius report: NTI score per asset, total crypto attack surface
  roadmap   PQC migration roadmap: phased plan with effort estimates and FIPS checkpoints

The Blast Radius Report answers:
  • Which cryptographic assets are quantum-vulnerable today?
  • What is the Nkyinkyim Threat Index (NTI) score? (0-10, 10=most exposed)  
  • How long and how much will it cost to migrate to NIST FIPS 204/203?
  • Which systems must be migrated first?

Examples:
  # Run discovery and generate blast radius report
  adinkhepra blast-radius report --output blast_radius_v1.pdf

  # Generate migration roadmap from existing scan
  adinkhepra blast-radius roadmap --scan scan_results.json --output pqc_roadmap.pdf`)
}

// NTIAsset represents a single cryptographic asset scored with the Nkyinkyim Threat Index.
type NTIAsset struct {
	AssetID       string    `json:"asset_id"`
	AssetType     string    `json:"asset_type"`     // TLS_CERT, SSH_KEY, VPN_TUNNEL, CODE_SIGN, X509_CERT
	Algorithm     string    `json:"algorithm"`      // RSA-2048, ECDSA-P256, etc.
	Location      string    `json:"location"`       // File path or endpoint
	NTIScore      float64   `json:"nti_score"`      // 0–10, 10 = most quantum-exposed
	PQCStatus     string    `json:"pqc_status"`     // VULNERABLE, HYBRID, QUANTUM_SAFE
	MigratePhase  string    `json:"migrate_phase"`  // PHASE_1 (<6mo), PHASE_2 (6-12mo), PHASE_3 (12-18mo)
	Remediation   string    `json:"remediation"`
	DiscoveredAt  time.Time `json:"discovered_at"`
}

// BlastRadiusReport is the full quantum-readiness blast radius report.
type BlastRadiusReport struct {
	GeneratedAt      time.Time  `json:"generated_at"`
	System           string     `json:"system"`
	Environment      string     `json:"environment"`

	// NTI Summary
	OverallNTIScore  float64    `json:"overall_nti_score"`   // 0–10 weighted average
	NTIGrade         string     `json:"nti_grade"`           // CRITICAL / HIGH / MODERATE / LOW
	QDayHorizon      string     `json:"q_day_horizon"`       // NSA/NIST planning horizon

	// Asset inventory
	TotalAssetsFound int        `json:"total_assets_found"`
	VulnerableAssets int        `json:"vulnerable_assets"`
	HybridAssets     int        `json:"hybrid_assets"`
	QuantumSafeAssets int       `json:"quantum_safe_assets"`
	Assets           []NTIAsset `json:"assets"`

	// Financial exposure
	EstimatedMigrationDays int     `json:"estimated_migration_days"`
	EstimatedMigrationCost float64 `json:"estimated_migration_cost_usd"`

	// Migration roadmap
	Phase1Systems    []string `json:"phase_1_systems_immediate"`  // Migrate <6 months
	Phase2Systems    []string `json:"phase_2_systems_near_term"`  // Migrate 6–12 months
	Phase3Systems    []string `json:"phase_3_systems_long_term"`  // Migrate 12–18 months

	// PQC target standards
	TargetSignature  string `json:"target_signature_standard"` // "ML-DSA (NIST FIPS 204)"
	TargetKEM        string `json:"target_kem_standard"`       // "ML-KEM (NIST FIPS 203)"
	TargetTLS        string `json:"target_tls_profile"`        // "TLS 1.3 + X25519Kyber768"
	TargetSSH        string `json:"target_ssh_profile"`        // "sntrup761x25519-sha512@openssh.com"
}

// ntiScore computes the Nkyinkyim Threat Index for an asset type.
// Formula: Impact(Q-Day) × Exploitability × Exposure weight.
// Based on NSA CNSA 2.0 timelines and NIST PQC migration guidance.
func ntiScore(assetType, algorithm string) float64 {
	// Base score by algorithm vulnerability (Shor's Algorithm impact)
	algoScore := map[string]float64{
		"RSA-1024":   10.0, // Immediately vulnerable
		"RSA-2048":   9.5,  // Vulnerable Q-Day ~2030
		"RSA-4096":   8.5,  // Longer key, still vulnerable
		"ECDSA-P256": 9.0,  // Fully vulnerable to Shor's
		"ECDSA-P384": 8.5,
		"ECDSA-P521": 8.0,
		"DH-2048":    9.0,  // Diffie-Hellman, vulnerable
		"Ed25519":    7.5,  // Less urgent but still classical
		"AES-128":    3.0,  // Grover's: doubles security bits needed
		"AES-256":    1.5,  // Grover's impact minimal
		"SHA-256":    2.0,  // Grover's impact
	}

	// Exposure multiplier by asset type (higher = more exposed to harvest-now-decrypt-later)
	typeMultiplier := map[string]float64{
		"TLS_CERT":   1.0,  // In-transit, active attack surface
		"SSH_KEY":    0.95,
		"VPN_TUNNEL": 1.0,
		"CODE_SIGN":  0.9,  // Supply chain risk
		"X509_CERT":  0.85,
	}

	base := 7.0 // Default if algorithm not recognized
	for alg, score := range algoScore {
		if strings.Contains(strings.ToUpper(algorithm), strings.ToUpper(alg)) {
			base = score
			break
		}
	}

	mult := 0.9
	if m, ok := typeMultiplier[assetType]; ok {
		mult = m
	}

	score := base * mult
	if score > 10.0 {
		score = 10.0
	}
	return score
}

func ntiGrade(score float64) string {
	switch {
	case score >= 9.0:
		return "CRITICAL"
	case score >= 7.0:
		return "HIGH"
	case score >= 4.0:
		return "MODERATE"
	default:
		return "LOW"
	}
}

func migratePhase(ntiScore float64) string {
	switch {
	case ntiScore >= 9.0:
		return "PHASE_1" // Immediately — <6 months
	case ntiScore >= 7.0:
		return "PHASE_2" // Near-term — 6–12 months
	default:
		return "PHASE_3" // Long-term — 12–18 months
	}
}

// buildBlastRadiusReport constructs the full report from a ComprehensiveReport.
func buildBlastRadiusReport(report *stig.ComprehensiveReport) *BlastRadiusReport {
	br := &BlastRadiusReport{
		GeneratedAt:      time.Now(),
		System:           report.Hostname,
		Environment:      report.OSVersion,
		QDayHorizon:      "2030–2035 (NIST SP 800-208 / NSA CNSA 2.0)",
		TargetSignature:  "ML-DSA-65 (NIST FIPS 204 / Dilithium)",
		TargetKEM:        "ML-KEM-1024 (NIST FIPS 203 / Kyber)",
		TargetTLS:        "TLS 1.3 with X25519Kyber768 hybrid key exchange",
		TargetSSH:        "sntrup761x25519-sha512@openssh.com (OpenSSH 9.0+)",
	}

	// Build asset list from PQC framework results
	if pqcResult, ok := report.Results[stig.FrameworkPQC]; ok {
		for _, finding := range pqcResult.Findings {
			if finding.ID == "PQC-INVENTORY-SUMMARY" {
				continue // Skip the summary finding
			}

			// Map finding IDs to asset types and algorithms
			assetType, algorithm := mapFindingToAsset(finding.ID)
			score := ntiScore(assetType, algorithm)

			asset := NTIAsset{
				AssetID:      finding.ID,
				AssetType:    assetType,
				Algorithm:    algorithm,
				Location:     inferAssetLocation(finding.ID),
				NTIScore:     score,
				PQCStatus:    "VULNERABLE",
				MigratePhase: migratePhase(score),
				Remediation:  finding.Remediation,
				DiscoveredAt: finding.CheckedAt,
			}

			if finding.Status == "Pass" {
				asset.PQCStatus = "QUANTUM_SAFE"
			}
			br.Assets = append(br.Assets, asset)
		}
	}

	// Include crypto inventory from PQCMetrics if available
	if pqcResult, ok := report.Results[stig.FrameworkPQC]; ok && pqcResult.PQCMetrics != nil {
		m := pqcResult.PQCMetrics
		br.TotalAssetsFound = m.TotalAssetsFound
		br.VulnerableAssets = m.VulnerableAssets
		br.EstimatedMigrationDays = m.EstimatedDays
		br.EstimatedMigrationCost = m.EstimatedCostUSD
	}

	// Augment with BlastRadiusAnalysis from validator
	if report.PQCBlastRadius != nil {
		ba := report.PQCBlastRadius
		br.Phase1Systems = ba.ImmediateActions
		br.Phase2Systems = ba.ShortTermActions
		br.Phase3Systems = ba.LongTermActions
		if br.TotalAssetsFound == 0 {
			br.TotalAssetsFound = ba.TotalCryptoOperations
			br.VulnerableAssets = ba.LegacyCryptoOperations
			br.EstimatedMigrationDays = ba.EstimatedMigrationDays
		}
	}

	// Compute overall NTI score (weighted average)
	if len(br.Assets) > 0 {
		total := 0.0
		for _, a := range br.Assets {
			total += a.NTIScore
		}
		br.OverallNTIScore = total / float64(len(br.Assets))
	} else {
		br.OverallNTIScore = 8.5 // Default: classical-only environment is HIGH
	}
	br.NTIGrade = ntiGrade(br.OverallNTIScore)

	// Populate phase-based system lists if not already set
	for _, a := range br.Assets {
		desc := fmt.Sprintf("%s (%s) at %s", a.AssetType, a.Algorithm, a.Location)
		switch a.MigratePhase {
		case "PHASE_1":
			br.Phase1Systems = appendUnique(br.Phase1Systems, desc)
		case "PHASE_2":
			br.Phase2Systems = appendUnique(br.Phase2Systems, desc)
		case "PHASE_3":
			br.Phase3Systems = appendUnique(br.Phase3Systems, desc)
		}
	}

	return br
}

func mapFindingToAsset(findingID string) (assetType, algorithm string) {
	switch findingID {
	case "PQC-TLS-001":
		return "TLS_CERT", "RSA-2048 / ECDSA-P256"
	case "PQC-SSH-001":
		return "SSH_KEY", "Ed25519 / RSA-2048"
	case "PQC-CERT-001":
		return "X509_CERT", "RSA-2048"
	case "PQC-VPN-001":
		return "VPN_TUNNEL", "DH-2048 / ECDH-P256"
	case "PQC-SIGN-001":
		return "CODE_SIGN", "RSA-2048 / ECDSA-P256"
	default:
		return "UNKNOWN", "Classical"
	}
}

func inferAssetLocation(findingID string) string {
	locations := map[string]string{
		"PQC-TLS-001":  "/etc/pki/tls/certs/ (TLS endpoints)",
		"PQC-SSH-001":  "/etc/ssh/ssh_host_*_key",
		"PQC-CERT-001": "/etc/pki/ca-trust/",
		"PQC-VPN-001":  "VPN gateway configuration",
		"PQC-SIGN-001": "Code signing infrastructure",
	}
	if loc, ok := locations[findingID]; ok {
		return loc
	}
	return "Unknown"
}

func appendUnique(slice []string, item string) []string {
	for _, s := range slice {
		if s == item {
			return slice
		}
	}
	return append(slice, item)
}

func blastRadiusReportCmd(args []string) {
	fs := flag.NewFlagSet("blast-radius report", flag.ExitOnError)
	scanFile := fs.String("scan", "", "Scan results JSON (optional; runs live scan if omitted)")
	output := fs.String("output", "blast_radius_v1.pdf", "Output file")
	fs.Parse(args)

	fmt.Println("╔══════════════════════════════════════════════════════════════╗")
	fmt.Println("║    KHEPRA PROTOCOL // QUANTUM-READINESS BLAST RADIUS         ║")
	fmt.Println("║    Nkyinkyim Threat Index (NTI) — Cryptographic Attack Surface║")
	fmt.Println("╚══════════════════════════════════════════════════════════════╝")
	fmt.Println()

	var report *stig.ComprehensiveReport

	if *scanFile != "" {
		data, err := os.ReadFile(*scanFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		report = &stig.ComprehensiveReport{}
		json.Unmarshal(data, report)
		fmt.Printf("[*] Loaded scan: %s\n", *scanFile)
	} else {
		fmt.Println("[*] Running live PQC discovery scan...")
		v := stig.NewValidator(".")
		var err error
		report, err = v.Validate()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Scan error: %v\n", err)
			os.Exit(1)
		}
	}

	brReport := buildBlastRadiusReport(report)

	// Display summary
	fmt.Printf("\n  QUANTUM-READINESS BLAST RADIUS — %s\n", brReport.System)
	fmt.Println("  ══════════════════════════════════════════════════")
	fmt.Printf("  Overall NTI Score: %.1f / 10.0 (%s)\n", brReport.OverallNTIScore, brReport.NTIGrade)
	fmt.Printf("  Q-Day Horizon:     %s\n", brReport.QDayHorizon)
	fmt.Printf("  Vulnerable Assets: %d of %d total crypto assets\n", brReport.VulnerableAssets, brReport.TotalAssetsFound)
	fmt.Printf("  Migration Effort:  %d days / $%.0f USD\n", brReport.EstimatedMigrationDays, brReport.EstimatedMigrationCost)
	fmt.Println()

	fmt.Println("  PQC ASSET INVENTORY:")
	for _, a := range brReport.Assets {
		fmt.Printf("    [NTI %.1f/%s] %s — %s → %s\n",
			a.NTIScore, a.MigratePhase, a.AssetType, a.Algorithm, a.PQCStatus)
	}
	fmt.Println()

	// Export — real binary PDF via stig.ExportBlastRadiusToPDF
	outputPath := *output
	if !strings.HasSuffix(outputPath, ".pdf") {
		outputPath += ".pdf"
	}

	assets := make([]stig.BlastRadiusAsset, 0, len(brReport.Assets))
	for _, a := range brReport.Assets {
		assets = append(assets, stig.BlastRadiusAsset{
			Name:      a.AssetID,
			Algorithm: a.Algorithm,
			NTIScore:  a.NTIScore,
			Phase:     a.MigratePhase,
		})
	}

	exportData := &stig.BlastRadiusExportData{
		System:        brReport.System,
		GeneratedAt:   brReport.GeneratedAt,
		TotalAssets:   brReport.TotalAssetsFound,
		HighRisk:      brReport.VulnerableAssets,
		AvgNTIScore:   brReport.OverallNTIScore,
		Assets:        assets,
		Phase1Actions: brReport.Phase1Systems,
		Phase2Actions: brReport.Phase2Systems,
		Phase3Actions: brReport.Phase3Systems,
	}

	if err := stig.ExportBlastRadiusToPDF(exportData, outputPath); err != nil {
		// Fallback to Markdown on PDF error
		mdPath := strings.TrimSuffix(outputPath, ".pdf") + ".md"
		fmt.Fprintf(os.Stderr, "[!] PDF export failed (%v) — falling back to Markdown: %s\n", err, mdPath)
		exportBlastRadiusMarkdown(brReport, mdPath)
		outputPath = mdPath
	}
	fmt.Printf("\n✓ Blast Radius Report: %s\n", outputPath)

}

func exportBlastRadiusMarkdown(br *BlastRadiusReport, outputPath string) {
	var sb strings.Builder

	sb.WriteString("# QUANTUM-READINESS BLAST RADIUS REPORT\n")
	sb.WriteString("## Nkyinkyim Threat Index (NTI) Assessment\n\n")
	sb.WriteString(fmt.Sprintf("**System:** %s  \n", br.System))
	sb.WriteString(fmt.Sprintf("**Generated:** %s  \n", br.GeneratedAt.Format("January 2, 2006")))
	sb.WriteString(fmt.Sprintf("**Q-Day Horizon:** %s  \n\n", br.QDayHorizon))

	sb.WriteString(fmt.Sprintf("## Overall NTI Score: %.1f / 10.0 — **%s**\n\n", br.OverallNTIScore, br.NTIGrade))
	sb.WriteString(fmt.Sprintf("- Vulnerable assets: **%d** of %d total\n", br.VulnerableAssets, br.TotalAssetsFound))
	sb.WriteString(fmt.Sprintf("- Migration effort: **%d days / $%.0f USD**\n\n", br.EstimatedMigrationDays, br.EstimatedMigrationCost))

	sb.WriteString("## Cryptographic Asset Inventory\n\n")
	sb.WriteString("| Asset ID | Type | Algorithm | NTI Score | PQC Status | Migration Phase |\n")
	sb.WriteString("|---|---|---|---|---|---|\n")
	for _, a := range br.Assets {
		sb.WriteString(fmt.Sprintf("| %s | %s | %s | %.1f | %s | %s |\n",
			a.AssetID, a.AssetType, a.Algorithm, a.NTIScore, a.PQCStatus, a.MigratePhase))
	}

	sb.WriteString("\n## Migration Roadmap\n\n")
	sb.WriteString(fmt.Sprintf("**Target signature:** %s  \n", br.TargetSignature))
	sb.WriteString(fmt.Sprintf("**Target KEM:** %s  \n", br.TargetKEM))
	sb.WriteString(fmt.Sprintf("**Target TLS:** %s  \n", br.TargetTLS))
	sb.WriteString(fmt.Sprintf("**Target SSH:** %s  \n\n", br.TargetSSH))

	sb.WriteString("### Phase 1 — Immediate (<6 months)\n\n")
	for _, s := range br.Phase1Systems {
		sb.WriteString(fmt.Sprintf("- %s\n", s))
	}
	sb.WriteString("\n### Phase 2 — Near-Term (6–12 months)\n\n")
	for _, s := range br.Phase2Systems {
		sb.WriteString(fmt.Sprintf("- %s\n", s))
	}
	sb.WriteString("\n### Phase 3 — Long-Term (12–18 months)\n\n")
	for _, s := range br.Phase3Systems {
		sb.WriteString(fmt.Sprintf("- %s\n", s))
	}

	os.WriteFile(outputPath, []byte(sb.String()), 0644)
}

func blastRadiusRoadmapCmd(args []string) {
	// Alias to report with roadmap-focused output
	blastRadiusReportCmd(append(args, "--roadmap"))
}
