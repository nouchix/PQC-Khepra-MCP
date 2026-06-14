package crypto

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// CBOM - Cryptographic Bill of Materials
// CycloneDX-compatible format for cryptographic asset transparency

// CBOM represents a complete cryptographic bill of materials
type CBOM struct {
	BOMFormat    string            `json:"bomFormat"`
	SpecVersion  string            `json:"specVersion"`
	SerialNumber string            `json:"serialNumber"`
	Version      int               `json:"version"`
	Metadata     CBOMMetadata      `json:"metadata"`
	Components   []CBOMComponent   `json:"components"`
	Dependencies []CBOMDependency  `json:"dependencies,omitempty"`
	Compositions []CBOMComposition `json:"compositions,omitempty"`
}

// CBOMMetadata contains scan/generation metadata
type CBOMMetadata struct {
	Timestamp  time.Time      `json:"timestamp"`
	Tools      []CBOMTool     `json:"tools"`
	Authors    []CBOMAuthor   `json:"authors,omitempty"`
	Component  CBOMComponent  `json:"component,omitempty"` // Root component
	Properties []CBOMProperty `json:"properties,omitempty"`
}

// CBOMTool describes the tool that generated the CBOM
type CBOMTool struct {
	Vendor  string `json:"vendor"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

// CBOMAuthor represents the CBOM creator
type CBOMAuthor struct {
	Name  string `json:"name"`
	Email string `json:"email,omitempty"`
}

// CBOMComponent represents a cryptographic component
type CBOMComponent struct {
	Type        string         `json:"type"` // "cryptographic-asset"
	BOMRef      string         `json:"bom-ref"`
	Name        string         `json:"name"`
	Version     string         `json:"version,omitempty"`
	Description string         `json:"description,omitempty"`
	Hashes      []CBOMHash     `json:"hashes,omitempty"`
	Licenses    []CBOMLicense  `json:"licenses,omitempty"`
	Properties  []CBOMProperty `json:"properties"`
	Evidence    *CBOMEvidence  `json:"evidence,omitempty"`
}

// CBOMHash represents a cryptographic hash
type CBOMHash struct {
	Alg     string `json:"alg"` // "SHA-256", etc.
	Content string `json:"content"`
}

// CBOMLicense represents software license
type CBOMLicense struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

// CBOMProperty is a key-value pair for custom metadata
type CBOMProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// CBOMEvidence provides proof of component existence
type CBOMEvidence struct {
	Occurrences []CBOMOccurrence `json:"occurrences,omitempty"`
}

// CBOMOccurrence describes where a component was found
type CBOMOccurrence struct {
	Location string `json:"location"` // File path
	Line     int    `json:"line,omitempty"`
}

// CBOMDependency describes component relationships
type CBOMDependency struct {
	Ref       string   `json:"ref"` // BOM-Ref of dependent
	DependsOn []string `json:"dependsOn"`
}

// CBOMComposition describes aggregate relationships
type CBOMComposition struct {
	Aggregate    string   `json:"aggregate"` // "complete", "incomplete"
	Assemblies   []string `json:"assemblies,omitempty"`
	Dependencies []string `json:"dependencies,omitempty"`
}

// GenerateCBOM creates a CycloneDX-compatible CBOM from discovered assets
func GenerateCBOM(inventory *CryptoInventory) (*CBOM, error) {
	cbom := &CBOM{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.5",
		SerialNumber: fmt.Sprintf("urn:uuid:cbom-%s", inventory.ScanID),
		Version:      1,
		Metadata: CBOMMetadata{
			Timestamp: inventory.ScanTimestamp,
			Tools: []CBOMTool{
				{
					Vendor:  "NouchiX SecRed Knowledge Inc.",
					Name:    "AdinKhepra SONAR",
					Version: "2.0.0-NUCLEAR",
				},
			},
			Authors: []CBOMAuthor{
				{
					Name:  "AdinKhepra Cryptographic Discovery Engine",
					Email: "cyber@nouchix.com",
				},
			},
			Properties: []CBOMProperty{
				{Name: "scan_id", Value: inventory.ScanID},
				{Name: "total_assets", Value: fmt.Sprintf("%d", inventory.Statistics.TotalAssets)},
				{Name: "quantum_safe", Value: fmt.Sprintf("%d", inventory.Statistics.QuantumSafe)},
				{Name: "requires_migration", Value: fmt.Sprintf("%d", inventory.Statistics.RequiresMigration)},
			},
		},
		Components:   []CBOMComponent{},
		Dependencies: []CBOMDependency{},
	}

	// Convert assets to components
	for i, asset := range inventory.Assets {
		component := assetToComponent(asset, i)
		cbom.Components = append(cbom.Components, component)

		// Add dependency relationships if available
		deps, ok := inventory.DAGMap[asset.FilePath]
		if ok && len(deps) > 0 {
			cbom.Dependencies = append(cbom.Dependencies, CBOMDependency{
				Ref:       component.BOMRef,
				DependsOn: deps,
			})
		}
	}

	return cbom, nil
}

// assetToComponent converts a CryptoAsset to a CBOMComponent
func assetToComponent(asset CryptoAsset, index int) CBOMComponent {
	component := CBOMComponent{
		Type:    "cryptographic-asset",
		BOMRef:  fmt.Sprintf("crypto-asset-%d", index),
		Name:    fmt.Sprintf("%s-%d", asset.Algorithm, asset.KeyLength),
		Version: asset.Implementation,
		Description: fmt.Sprintf("%s cryptographic implementation (Usage: %s, Risk: %s)",
			asset.Algorithm, asset.UsageContext, asset.QuantumRisk),
		Properties: []CBOMProperty{
			{Name: "algorithm", Value: asset.Algorithm},
			{Name: "key_length", Value: fmt.Sprintf("%d", asset.KeyLength)},
			{Name: "usage_context", Value: string(asset.UsageContext)},
			{Name: "quantum_risk", Value: string(asset.QuantumRisk)},
			{Name: "migration_path", Value: asset.MigrationPath},
			{Name: "vendor", Value: asset.Vendor},
			{Name: "implementation", Value: asset.Implementation},
			{Name: "blast_radius", Value: fmt.Sprintf("%d", asset.BlastRadius)},
			{Name: "manual_review", Value: fmt.Sprintf("%t", asset.ManualReview)},
			{Name: "discovery_method", Value: asset.DiscoveryMethod},
			{Name: "discovered_at", Value: asset.DiscoveredAt.Format(time.RFC3339)},
		},
		Evidence: &CBOMEvidence{
			Occurrences: []CBOMOccurrence{
				{
					Location: asset.FilePath,
					Line:     asset.LineNumber,
				},
			},
		},
	}

	// Add expiration date if available
	if !asset.ExpirationDate.IsZero() {
		component.Properties = append(component.Properties, CBOMProperty{
			Name:  "expiration_date",
			Value: asset.ExpirationDate.Format(time.RFC3339),
		})
	}

	// Add symbol binding if present (Adinkra integration)
	if asset.Symbol != "" {
		component.Properties = append(component.Properties, CBOMProperty{
			Name:  "adinkra_symbol",
			Value: asset.Symbol,
		})
	}

	return component
}

// WriteCBOMToFile exports CBOM to JSON file
func WriteCBOMToFile(cbom *CBOM, outputPath string) error {
	data, err := json.MarshalIndent(cbom, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal CBOM: %w", err)
	}

	return os.WriteFile(outputPath, data, 0644)
}

// WriteCBOMToSPDX exports CBOM in SPDX 2.3 JSON format (NTIA-minimum element compliant).
// Maps CycloneDX components to SPDX Package descriptors.
func WriteCBOMToSPDX(cbom *CBOM, outputPath string) error {
	type spdxPackage struct {
		SPDXID           string `json:"SPDXID"`
		Name             string `json:"name"`
		VersionInfo      string `json:"versionInfo"`
		DownloadLocation string `json:"downloadLocation"`
		FilesAnalyzed    bool   `json:"filesAnalyzed"`
	}
	type spdxDoc struct {
		SPDXVersion     string       `json:"spdxVersion"`
		DataLicense     string       `json:"dataLicense"`
		SPDXID          string       `json:"SPDXID"`
		Name            string       `json:"name"`
		DocumentNS      string       `json:"documentNamespace"`
		Created         string       `json:"created"`
		Creators        []string     `json:"creators"`
		Packages        []spdxPackage `json:"packages"`
	}

	doc := spdxDoc{
		SPDXVersion: "SPDX-2.3",
		DataLicense: "CC0-1.0",
		SPDXID:      "SPDXRef-DOCUMENT",
		Name:        cbom.SerialNumber,
		DocumentNS:  fmt.Sprintf("https://khepra.nouchix.com/sbom/%s", cbom.SerialNumber),
		Created:     cbom.Metadata.Timestamp.UTC().Format("2006-01-02T15:04:05Z"),
		Creators:    []string{"Tool: AdinKhepra SONAR"},
	}

	for i, comp := range cbom.Components {
		doc.Packages = append(doc.Packages, spdxPackage{
			SPDXID:           fmt.Sprintf("SPDXRef-Package-%d", i),
			Name:             comp.Name,
			VersionInfo:      comp.Version,
			DownloadLocation: "NOASSERTION",
			FilesAnalyzed:    false,
		})
	}

	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal SPDX document: %w", err)
	}
	return os.WriteFile(outputPath, data, 0644)
}

// GenerateMigrationReport creates a human-readable migration plan
func GenerateMigrationReport(inventory *CryptoInventory) string {
	report := "=================================================================\n"
	report += "     ADINKHEPRA™ POST-QUANTUM MIGRATION REPORT\n"
	report += "=================================================================\n\n"

	report += fmt.Sprintf("Scan ID: %s\n", inventory.ScanID)
	report += fmt.Sprintf("Timestamp: %s\n\n", inventory.ScanTimestamp.Format("2006-01-02 15:04:05 UTC"))

	report += "EXECUTIVE SUMMARY:\n"
	report += fmt.Sprintf("  Total Cryptographic Assets: %d\n", inventory.Statistics.TotalAssets)
	report += fmt.Sprintf("  ✅ Quantum-Safe: %d\n", inventory.Statistics.QuantumSafe)
	report += fmt.Sprintf("  ⚠️  Requires Migration: %d\n", inventory.Statistics.RequiresMigration)
	report += fmt.Sprintf("  🔍 Needs Manual Review: %d\n\n", inventory.Statistics.NeedsReview)

	report += "RISK BREAKDOWN:\n"
	for risk, count := range inventory.Statistics.ByRiskLevel {
		emoji := getRiskEmoji(RiskLevel(risk))
		report += fmt.Sprintf("  %s %s: %d assets\n", emoji, risk, count)
	}

	report += "\nALGORITHM DISTRIBUTION:\n"
	for alg, count := range inventory.Statistics.ByAlgorithm {
		report += fmt.Sprintf("  • %s: %d\n", alg, count)
	}

	report += "\nUSAGE CONTEXT:\n"
	for usage, count := range inventory.Statistics.ByUsageContext {
		report += fmt.Sprintf("  • %s: %d\n", usage, count)
	}

	report += "\n=================================================================\n"
	report += "MIGRATION PRIORITIES (Sorted by Risk × Blast Radius):\n"
	report += "=================================================================\n\n"

	// Sort assets by priority
	priorities := calculateMigrationPriorities(inventory)

	for i, asset := range priorities {
		if i >= 10 {
			break // Top 10 only
		}

		report += fmt.Sprintf("%d. [%s] %s-%d\n", i+1, asset.QuantumRisk, asset.Algorithm, asset.KeyLength)
		report += fmt.Sprintf("   Location: %s", asset.FilePath)
		if asset.LineNumber > 0 {
			report += fmt.Sprintf(":%d", asset.LineNumber)
		}
		report += "\n"
		report += fmt.Sprintf("   Usage: %s\n", asset.UsageContext)
		report += fmt.Sprintf("   Migration: %s\n", asset.MigrationPath)
		report += fmt.Sprintf("   Blast Radius: %d dependent systems\n", asset.BlastRadius)
		if asset.ManualReview {
			report += fmt.Sprintf("   ⚠️  %s\n", asset.ReviewNotes)
		}
		report += "\n"
	}

	report += "=================================================================\n"
	report += "NEXT STEPS:\n"
	report += "=================================================================\n"
	report += "1. Review CBOM (cbom.json) for full inventory\n"
	report += "2. Generate STIG checklist (.CKL) for compliance tracking\n"
	report += "3. Prioritize high-risk, high-blast-radius assets first\n"
	report += "4. Test migrations in staging environment\n"
	report += "5. Execute rollout plan with rollback procedures\n"
	report += "6. Update documentation and security policies\n"
	report += "\n"
	report += "Generated by: AdinKhepra™ ASAF - Agentic Security Attestation Framework\n"
	report += "=================================================================\n"

	return report
}

// calculateMigrationPriorities sorts assets by risk and blast radius
func calculateMigrationPriorities(inventory *CryptoInventory) []CryptoAsset {
	// Create a copy
	assets := make([]CryptoAsset, len(inventory.Assets))
	copy(assets, inventory.Assets)

	// Sort by priority score (risk weight × blast radius)
	// Using simple bubble sort for clarity
	for i := 0; i < len(assets); i++ {
		for j := i + 1; j < len(assets); j++ {
			score_i := riskWeight(assets[i].QuantumRisk) * (assets[i].BlastRadius + 1)
			score_j := riskWeight(assets[j].QuantumRisk) * (assets[j].BlastRadius + 1)

			if score_j > score_i {
				assets[i], assets[j] = assets[j], assets[i]
			}
		}
	}

	return assets
}

// riskWeight assigns numerical weight to risk levels
func riskWeight(risk RiskLevel) int {
	switch risk {
	case RiskCritical:
		return 100
	case RiskHigh:
		return 50
	case RiskMedium:
		return 20
	case RiskLow:
		return 5
	case RiskSafe:
		return 0
	default:
		return 10
	}
}

// getRiskEmoji returns emoji for risk level
func getRiskEmoji(risk RiskLevel) string {
	switch risk {
	case RiskCritical:
		return "🔴"
	case RiskHigh:
		return "🟠"
	case RiskMedium:
		return "🟡"
	case RiskLow:
		return "🟢"
	case RiskSafe:
		return "✅"
	default:
		return "⚪"
	}
}
