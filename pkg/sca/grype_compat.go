// Package sca — Grype backward-compatibility helpers
//
// These functions bridge the old shell-out JSON parsing types (GrypeMatch, etc.)
// to the new in-process library flow. They allow the JSON parsing tests to
// continue validating our Grype output type definitions, which are used by
// reporting, export, and any future shell-out fallback path.

package sca

import (
	"strings"
	"time"
)

// convertGrypeToEnriched converts legacy GrypeMatch JSON types to EnrichedFinding.
// This is used by tests and by any code path that parses Grype CLI JSON output
// (e.g., external grype invocation, cached JSON files).
func convertGrypeToEnriched(matches []GrypeMatch) []EnrichedFinding {
	if len(matches) == 0 {
		return make([]EnrichedFinding, 0)
	}

	findings := make([]EnrichedFinding, 0, len(matches))
	now := time.Now().UTC()

	for _, m := range matches {
		f := EnrichedFinding{
			Component:  m.Artifact.Name,
			Version:    m.Artifact.Version,
			Ecosystem:  normalizeEcosystem(m.Artifact.Type),
			PackageURL: m.Artifact.PURL,
			CPE:        firstOrEmpty(m.Artifact.CPEs),

			CVEID:    m.Vulnerability.ID,
			Severity: normalizeSeverity(m.Vulnerability.Severity),

			Sources:    []string{"grype"},
			DetectedAt: now,
		}

		// Extract best CVSS v3 score
		if best := bestCVSSv3(m.Vulnerability.CVSS); best != nil {
			f.CVSSv3Score = best.Metrics.BaseScore
			f.CVSSv3Vector = best.Vector
		}

		// Derive severity from CVSS if not set
		if f.Severity == "UNKNOWN" && f.CVSSv3Score > 0 {
			f.Severity = string(SeverityFromCVSS(f.CVSSv3Score))
		}

		findings = append(findings, f)
	}

	return findings
}

// bestCVSSv3 selects the most authoritative CVSS v3 score from a slice.
// Prefers NVD source; falls back to first v3 entry; returns nil if no v3 available.
func bestCVSSv3(scores []GrypeCVSS) *GrypeCVSS {
	if len(scores) == 0 {
		return nil
	}

	var nvd *GrypeCVSS
	var firstV3 *GrypeCVSS

	for i := range scores {
		s := &scores[i]
		if !strings.HasPrefix(s.Version, "3") {
			continue
		}
		if firstV3 == nil {
			firstV3 = s
		}
		if strings.Contains(strings.ToLower(s.Source), "nvd") || strings.Contains(strings.ToLower(s.Source), "nist") {
			nvd = s
		}
	}

	if nvd != nil {
		return nvd
	}
	return firstV3
}

// extractGrypeMetadata builds ScannerMetadata from a Grype JSON descriptor.
func extractGrypeMetadata(desc *GrypeDescriptor) *ScannerMetadata {
	meta := &ScannerMetadata{
		ScannedAt: time.Now().UTC(),
	}
	if desc != nil {
		meta.GrypeVersion = desc.Version
		meta.GrypeDBVersion = desc.DB.Built
	}
	return meta
}

// extractSyftMetadata builds ScannerMetadata from a parsed CycloneDX BOM.
// This is the backward-compatible version that works with our CycloneDX types.
func extractSyftMetadata(bom *CycloneDXBOM) *ScannerMetadata {
	meta := &ScannerMetadata{
		ScannedAt: time.Now().UTC(),
	}
	if bom == nil {
		return meta
	}
	for _, tool := range bom.Metadata.Tools.Components {
		if strings.EqualFold(tool.Name, "syft") {
			meta.SyftVersion = tool.Version
			break
		}
	}
	return meta
}
