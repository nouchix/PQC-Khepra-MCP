// Package sca — SCA Pipeline Orchestrator
//
// Pipeline is the high-level public API that chains:
//   Syft (SBOM generation) → Grype (vulnerability matching) → Enricher (threat intel)
//
// This is the single entry point for MCP tools requesting an SCA assessment.

package sca

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/nouchix/PQC-Khepra-MCP/pkg/vuln"
)

// ──────────────────────────────────────────────────────────────────────────────
// Pipeline
// ──────────────────────────────────────────────────────────────────────────────

// Pipeline orchestrates the full SCA flow: SBOM → Vulnerability Matching → Enrichment.
// It is the primary public API surface for ERT integration.
type Pipeline struct {
	syft       *SyftAdapter
	grype      *GrypeAdapter
	enricher   *Enricher
	compliance *ComplianceMapper
}

// NewPipeline creates a fully wired SCA pipeline.
func NewPipeline(feedManager *vuln.IntelFeedManager) *Pipeline {
	return &Pipeline{
		syft:       NewSyftAdapter(),
		grype:      NewGrypeAdapter(),
		enricher:   NewEnricher(feedManager),
		compliance: NewComplianceMapper(),
	}
}

// LoadComplianceData loads all CMMC/NIST/CCI crosswalk CSVs from a docs directory.
// Expected files: CCI_to_NIST53.csv, NIST53_to_171.csv, NIST53_to_172.csv
// Non-fatal: if any file is missing, defaults are still active.
func (p *Pipeline) LoadComplianceData(docsDir string) {
	if p.compliance == nil {
		return
	}

	if err := p.compliance.LoadCSV(filepath.Join(docsDir, "NIST53_to_171.csv")); err != nil {
		log.Printf("[SCA] Warning: could not load NIST53_to_171.csv: %v (using defaults)", err)
	}
	if err := p.compliance.LoadCSV172(filepath.Join(docsDir, "NIST53_to_172.csv")); err != nil {
		log.Printf("[SCA] Warning: could not load NIST53_to_172.csv: %v (using defaults)", err)
	}
	if err := p.compliance.LoadCCICSV(filepath.Join(docsDir, "CCI_to_NIST53.csv")); err != nil {
		log.Printf("[SCA] Warning: could not load CCI_to_NIST53.csv: %v (CCI/STIG tracing disabled)", err)
	} else {
		log.Println("[SCA] CCI→STIG crosswalk loaded successfully")
	}
}

// ScanResult contains the complete output of an SCA pipeline run.
type ScanResult struct {
	// Findings are the fully enriched vulnerability findings.
	Findings []EnrichedFinding `json:"findings"`

	// HighRiskCount is the number of findings that pass IsHighRisk().
	HighRiskCount int `json:"high_risk_count"`

	// TotalCount is the total number of findings.
	TotalCount int `json:"total_count"`

	// SBOMComponentCount is the number of components found in the SBOM.
	SBOMComponentCount int `json:"sbom_component_count"`

	// ScannerMeta records the tool versions used.
	ScannerMeta ScannerMetadata `json:"scanner_meta"`

	// Duration is the total scan wall time.
	Duration time.Duration `json:"duration"`

	// ProjectPath is the absolute path that was scanned.
	ProjectPath string `json:"project_path"`
}

// ScanAndEnrich runs the full SCA pipeline against a project directory.
//
// Flow:
//  1. Syft generates a CycloneDX SBOM
//  2. Grype matches vulnerabilities against the SBOM
//  3. Enricher wires findings with CISA KEV, EPSS, InTheWild data
//  4. Results are packaged with metadata for ERT consumption
func (p *Pipeline) ScanAndEnrich(ctx context.Context, projectPath string) (*ScanResult, error) {
	start := time.Now()

	absPath, err := filepath.Abs(projectPath)
	if err != nil {
		return nil, fmt.Errorf("sca/pipeline: invalid path: %w", err)
	}

	if _, err := os.Stat(absPath); err != nil {
		return nil, fmt.Errorf("sca/pipeline: project does not exist: %w", err)
	}

	log.Printf("[SCA] Starting pipeline scan: %s", absPath)

	// ── Phase 1: SBOM Generation (Syft) ──────────────────────────────────
	log.Println("[SCA] Phase 1/3: Generating SBOM via Syft...")
	bom, syftMeta, err := p.syft.GenerateSBOM(ctx, absPath)
	if err != nil {
		return nil, fmt.Errorf("sca/pipeline: SBOM generation failed: %w", err)
	}

	componentCount := 0
	if bom != nil {
		componentCount = len(bom.Components)
	}
	log.Printf("[SCA] Phase 1/3 complete: %d components in SBOM", componentCount)

	// ── Phase 2: Vulnerability Matching (Grype) ──────────────────────────
	// Zero-copy SBOM handoff: pass the raw Syft SBOM directly to Grype
	log.Println("[SCA] Phase 2/3: Matching vulnerabilities via Grype...")
	var findings []EnrichedFinding
	var grypeMeta *ScannerMetadata

	rawSBOM := p.syft.GetLastSBOM()
	if rawSBOM != nil {
		// Preferred path: direct SBOM handoff, no serialization
		findings, grypeMeta, err = p.grype.MatchVulnerabilitiesFromSBOM(ctx, rawSBOM)
	} else {
		// Fallback: pass directory directly to Grype
		log.Println("[SCA] Warning: no cached SBOM, using directory scan")
		findings, grypeMeta, err = p.grype.MatchVulnerabilities(ctx, absPath)
	}

	if err != nil {
		return nil, fmt.Errorf("sca/pipeline: vulnerability matching failed: %w", err)
	}
	log.Printf("[SCA] Phase 2/3 complete: %d raw findings", len(findings))

	// ── Phase 3: Enrichment ──────────────────────────────────────────────
	log.Println("[SCA] Phase 3/3: Enriching findings with threat intelligence...")
	enriched, err := p.enricher.Enrich(ctx, findings)
	if err != nil {
		// Non-fatal: return unenriched findings rather than failing
		log.Printf("[SCA] Enrichment warning (using raw findings): %v", err)
		enriched = findings
	}
	log.Printf("[SCA] Phase 3/3 complete: %d enriched findings", len(enriched))

	// ── Phase 4: CMMC Compliance Mapping ────────────────────────────────
	if p.compliance != nil {
		p.compliance.MapFindings(enriched)
		log.Println("[SCA] CMMC/CCI/STIG compliance mapping applied")
	}

	// ── Build result ─────────────────────────────────────────────────────
	result := &ScanResult{
		Findings:           enriched,
		TotalCount:         len(enriched),
		SBOMComponentCount: componentCount,
		Duration:           time.Since(start),
		ProjectPath:        absPath,
	}

	// Merge scanner metadata
	result.ScannerMeta = mergeScannerMeta(syftMeta, grypeMeta)

	// Count high-risk findings
	for _, f := range enriched {
		if f.IsHighRisk() {
			result.HighRiskCount++
		}
	}

	log.Printf("[SCA] Pipeline complete: %d findings (%d high-risk) in %s",
		result.TotalCount, result.HighRiskCount, result.Duration.Round(time.Millisecond))

	return result, nil
}

// ──────────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────────




// mergeScannerMeta combines metadata from Syft and Grype into a single record.
func mergeScannerMeta(syft, grype *ScannerMetadata) ScannerMetadata {
	meta := ScannerMetadata{
		ScannedAt: time.Now().UTC(),
	}

	if syft != nil {
		meta.SyftVersion = syft.SyftVersion
	}
	if grype != nil {
		meta.GrypeVersion = grype.GrypeVersion
		meta.GrypeDBVersion = grype.GrypeDBVersion
	}

	return meta
}
