package ert

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/sca"
)

// ──────────────────────────────────────────────────────────────────────────────
// SCA Lane — wraps the sovereign Syft → Grype → Enricher pipeline
//
// Uses the actual Go SDK APIs:
//   SyftAdapter.GenerateSBOM(ctx, path) → (*CycloneDXBOM, *ScannerMetadata, error)
//   GrypeAdapter.MatchVulnerabilities(ctx, target) → ([]EnrichedFinding, *ScannerMetadata, error)
//   Enricher.Enrich(ctx, findings) → ([]EnrichedFinding, error)
// ──────────────────────────────────────────────────────────────────────────────

// SCALane wraps the sovereign SCA pipeline (Syft → Grype → Enricher)
// as a LaneRunner for the ScanOrchestrator.
type SCALane struct {
	syft     *sca.SyftAdapter
	grype    *sca.GrypeAdapter
	enricher *sca.Enricher
}

// NewSCALane creates a new SCA lane with configured adapters.
// syft and grype are required; enricher is optional (EPSS/KEV enrichment).
func NewSCALane(syft *sca.SyftAdapter, grype *sca.GrypeAdapter, enricher *sca.Enricher) *SCALane {
	return &SCALane{
		syft:     syft,
		grype:    grype,
		enricher: enricher,
	}
}

// Name returns the lane identifier.
func (l *SCALane) Name() ScanLane {
	return LaneSCA
}

// Run executes the full SCA pipeline: SBOM → Vulnerability Match → Enrichment.
// The resulting sca.EnrichedFindings are wrapped as UnifiedFindings.
func (l *SCALane) Run(ctx context.Context, req ScanRequest) ([]UnifiedFinding, error) {
	if l.grype == nil {
		return nil, fmt.Errorf("sca lane: grype adapter required")
	}

	target := req.TargetPath
	if target == "" {
		target = req.ImageRef
	}

	log.Printf("[SCA-LANE] Starting SCA pipeline for: %s", target)

	// Step 1: Generate SBOM via Syft (optional — Grype can scan directly)
	if l.syft != nil {
		bom, meta, err := l.syft.GenerateSBOM(ctx, target)
		if err != nil {
			log.Printf("[SCA-LANE] WARN: Syft SBOM generation failed: %v (falling back to Grype direct scan)", err)
		} else {
			log.Printf("[SCA-LANE] SBOM generated: %d components (Syft %s)", len(bom.Components), meta.SyftVersion)
		}
	}

	// Step 2: Vulnerability matching via Grype
	// Grype can scan the target directly without requiring a Syft SBOM
	matches, meta, err := l.grype.MatchVulnerabilities(ctx, target)
	if err != nil {
		return nil, fmt.Errorf("grype vulnerability matching failed: %w", err)
	}

	log.Printf("[SCA-LANE] Grype matched %d vulnerabilities (DB: %s)", len(matches), meta.GrypeDBVersion)

	// Step 3: Enrich with EPSS/KEV/CVSS if enricher is available
	var enrichedFindings []sca.EnrichedFinding
	if l.enricher != nil {
		enrichedFindings, err = l.enricher.Enrich(ctx, matches)
		if err != nil {
			log.Printf("[SCA-LANE] WARN: Enrichment failed, using raw matches: %v", err)
			enrichedFindings = matches // Fall back to unenriched
		}
	} else {
		enrichedFindings = matches
	}

	// Step 4: Convert to UnifiedFindings
	unified := make([]UnifiedFinding, 0, len(enrichedFindings))
	for _, ef := range enrichedFindings {
		unified = append(unified, scaToUnified(ef))
	}

	log.Printf("[SCA-LANE] Pipeline complete: %d unified findings", len(unified))
	return unified, nil
}

// scaToUnified converts an sca.EnrichedFinding to a UnifiedFinding.
// This preserves the full EnrichedFinding in the Raw field for later
// EA conversion without data loss.
func scaToUnified(ef sca.EnrichedFinding) UnifiedFinding {
	return UnifiedFinding{
		ID:       fmt.Sprintf("sca:%s:%s:%s", ef.Component, ef.Version, ef.CVEID),
		Source:   "sca",
		Category: CategorySCA,

		Severity:    ef.Severity,
		Title:       fmt.Sprintf("%s in %s@%s", ef.CVEID, ef.Component, ef.Version),
		Description: fmt.Sprintf("CVSSv3: %.1f | EPSS: %.4f | KEV: %v", ef.CVSSv3Score, ef.EPSSScore, ef.InCISAKEV),

		Asset:    ef.Component,
		Location: ef.PackageURL,

		CVEID:     ef.CVEID,
		CVSSv3:    ef.CVSSv3Score,
		EPSSScore: ef.EPSSScore,
		InCISAKEV: ef.InCISAKEV,

		Evidence: map[string]interface{}{
			"ecosystem":         ef.Ecosystem,
			"cvss_vector":       ef.CVSSv3Vector,
			"sources":           ef.Sources,
			"nist_53_controls":  ef.NIST53Controls,
			"nist_171_controls": ef.NIST171Controls,
			"stig_findings":     ef.STIGFindings,
		},

		Timestamp: ef.DetectedAt,
		Raw:       ef, // Preserve for EA boundary conversion
	}
}

// SCALaneTimings captures per-stage wall-clock durations for observability.
// Populated by instrumented runs and surfaced in the ERT scan summary.
type SCALaneTimings struct {
	SBOMGeneration time.Duration `json:"sbom_generation"`
	VulnMatching   time.Duration `json:"vuln_matching"`
	Enrichment     time.Duration `json:"enrichment"`
	Normalization  time.Duration `json:"normalization"`
}
