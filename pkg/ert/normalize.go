package ert

import (
	"fmt"
	"time"

	"github.com/nouchix/PQC-Khepra-MCP/pkg/sca"
)

// ──────────────────────────────────────────────────────────────────────────────
// normalize.go — Conversion layer between UnifiedFinding and EnrichedFinding
//
// This is the ONLY place where UnifiedFinding → sca.EnrichedFinding conversion
// happens. The EA engine consumes EnrichedFindings exclusively, so all scanner
// outputs must pass through this normalization layer before reaching the
// KernelRouter.RouteWithFindings() entry point.
//
// Design rationale: Keeping this conversion isolated preserves provenance
// in the orchestrator while giving the EA a normalized feed. Non-CVE findings
// (secrets, compliance gaps, misconfigs) get synthetic CVE-IDs for EA
// compatibility, but their original semantics are preserved in the Evidence map.
// ──────────────────────────────────────────────────────────────────────────────

// ToEnrichedFinding converts a UnifiedFinding to an sca.EnrichedFinding
// for consumption by the EA engine.
//
// If the UnifiedFinding was originally produced by the SCA lane, the
// original EnrichedFinding is extracted from Raw (lossless roundtrip).
// Otherwise, a best-effort mapping is performed.
func ToEnrichedFinding(f UnifiedFinding) sca.EnrichedFinding {
	// Fast path: if this was originally an SCA finding, extract the original
	if f.Source == "sca" && f.Raw != nil {
		if ef, ok := f.Raw.(sca.EnrichedFinding); ok {
			return ef
		}
	}

	// Slow path: build an EnrichedFinding from UnifiedFinding fields
	ef := sca.EnrichedFinding{
		Component:   f.Asset,
		Version:     extractStringEvidence(f.Evidence, "version"),
		Ecosystem:   extractStringEvidence(f.Evidence, "ecosystem"),
		PackageURL:  f.Location,
		CVEID:       f.CVEID,
		CVSSv3Score: f.CVSSv3,
		Severity:    f.Severity,
		InCISAKEV:   f.InCISAKEV,
		EPSSScore:   f.EPSSScore,
		DetectedAt:  f.Timestamp,
		Sources:     []string{f.Source},
		Confidence:  "medium",
	}

	// Category-specific mappings
	switch f.Category {
	case CategorySecret:
		// Secrets get a synthetic CVE-ID for EA compatibility
		ef.CVEID = fmt.Sprintf("SECRET-%s", f.SecretType)
		ef.Severity = f.Severity
		ef.CVSSv3Score = secretSeverityToCVSS(f.Severity)
		ef.Component = f.Asset // file path
		ef.Confidence = "high"

	case CategoryCompliance:
		// Compliance gaps get a synthetic ID from the control
		ef.CVEID = fmt.Sprintf("COMPLIANCE-%s-%s", f.Framework, f.ControlID)
		ef.CVSSv3Score = complianceSeverityToCVSS(f.Severity)
		ef.Component = f.Framework
		ef.Confidence = "high"
		// Map compliance control to NIST references
		ef.NIST53Controls = extractStringSliceEvidence(f.Evidence, "nist_53_controls")
		ef.STIGFindings = []string{f.ControlID}

	case CategoryMisconfigure:
		// Container/config misconfigurations
		ef.CVEID = fmt.Sprintf("MISCONFIG-%s", f.ID)
		ef.CVSSv3Score = complianceSeverityToCVSS(f.Severity)
		ef.Component = f.Asset
		ef.Confidence = "medium"

	case CategoryVulnerability:
		// Horus vuln findings already have CVE IDs
		ef.Confidence = "medium"

	default:
		// Generic mapping
		if ef.CVEID == "" {
			ef.CVEID = f.ID
		}
	}

	// Ensure timestamp is set
	if ef.DetectedAt.IsZero() {
		ef.DetectedAt = time.Now().UTC()
	}

	return ef
}

// ToEnrichedFindings batch-converts UnifiedFindings to EnrichedFindings.
func ToEnrichedFindings(findings []UnifiedFinding) []sca.EnrichedFinding {
	result := make([]sca.EnrichedFinding, 0, len(findings))
	for _, f := range findings {
		result = append(result, ToEnrichedFinding(f))
	}
	return result
}

// ──────────────────────────────────────────────────────────────────────────────
// Severity → CVSS mapping helpers
// ──────────────────────────────────────────────────────────────────────────────

func secretSeverityToCVSS(severity string) float64 {
	switch severity {
	case "CRITICAL":
		return 9.8
	case "HIGH":
		return 8.5
	case "MEDIUM":
		return 6.0
	case "LOW":
		return 3.5
	default:
		return 5.0
	}
}

func complianceSeverityToCVSS(severity string) float64 {
	switch severity {
	case "HIGH":
		return 7.5
	case "MEDIUM":
		return 5.0
	case "LOW":
		return 3.0
	default:
		return 4.0
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Evidence extraction helpers
// ──────────────────────────────────────────────────────────────────────────────

func extractStringEvidence(evidence map[string]interface{}, key string) string {
	if evidence == nil {
		return ""
	}
	if v, ok := evidence[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func extractStringSliceEvidence(evidence map[string]interface{}, key string) []string {
	if evidence == nil {
		return nil
	}
	if v, ok := evidence[key]; ok {
		if slice, ok := v.([]string); ok {
			return slice
		}
		// Handle []interface{} from JSON unmarshal
		if iSlice, ok := v.([]interface{}); ok {
			result := make([]string, 0, len(iSlice))
			for _, item := range iSlice {
				if s, ok := item.(string); ok {
					result = append(result, s)
				}
			}
			return result
		}
	}
	return nil
}
