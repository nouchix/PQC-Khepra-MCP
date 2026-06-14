// Package sca implements Software Composition Analysis for the Khepra Protocol ERT.
//
// "The Scarab dissects what others merely scan — every dependency weighed, every exploit measured."
//
// This package owns the EnrichedFinding schema (the contract between SCA and ERT analysis),
// adapters for Syft (SBOM generation) and Grype (vulnerability matching), and the
// enrichment pipeline that synthesizes findings from multiple threat intelligence feeds.
package sca

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Severity represents the severity classification of a vulnerability finding.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityNone     Severity = "NONE"
)

// VEXStatus represents the VEX (Vulnerability Exploitability eXchange) status.
type VEXStatus string

const (
	VEXNotAffected       VEXStatus = "not_affected"
	VEXAffected          VEXStatus = "affected"
	VEXFixed             VEXStatus = "fixed"
	VEXUnderInvestigation VEXStatus = "under_investigation"
)

// Confidence represents the confidence level of a finding.
type Confidence string

const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
)

// EnrichedFinding is the core contract between the SCA stage and ERT analysis.
// Every vulnerability finding flows through this schema before reaching the EA kernel router.
//
// Fields are grouped into: Component Identity, Vulnerability, Sources,
// Enrichment (our competitive moat), MITRE ATT&CK, VEX, and Metadata.
type EnrichedFinding struct {
	// ── Component Identity ──────────────────────────────────────────────
	Component  string `json:"component"`       // e.g. "lodash", "golang.org/x/crypto"
	Version    string `json:"version"`         // installed version
	Ecosystem  string `json:"ecosystem"`       // go, npm, pip, cargo, maven, nuget
	PackageURL string `json:"purl"`            // pkg:golang/golang.org/x/crypto@v0.17.0
	CPE        string `json:"cpe,omitempty"`   // cpe:2.3:a:vendor:product:version:...

	// ── Vulnerability ──────────────────────────────────────────────────
	CVEID        string  `json:"cve_id"`         // CVE-2024-XXXXX
	CVSSv3Score  float64 `json:"cvss_v3_score"`  // 0.0 – 10.0
	CVSSv3Vector string  `json:"cvss_v3_vector"` // CVSS:3.1/AV:N/AC:L/...
	Severity     string  `json:"severity"`       // CRITICAL | HIGH | MEDIUM | LOW

	// ── Sources ────────────────────────────────────────────────────────
	Sources []string `json:"sources"` // ["grype", "nvd", "cisa-kev"]

	// ── Enrichment (our moat) ──────────────────────────────────────────
	InCISAKEV      bool    `json:"in_cisa_kev"`
	KEVDateAdded   string  `json:"kev_date_added,omitempty"` // RFC3339 date
	InTheWild      bool    `json:"in_the_wild"`
	ExploitDBID    string  `json:"exploitdb_id,omitempty"`
	PoCAvailable   bool    `json:"poc_available"`
	EPSSScore      float64 `json:"epss_score"`      // 0.0 – 1.0
	EPSSPercentile float64 `json:"epss_percentile"` // 0.0 – 1.0

	// ── MITRE ATT&CK ──────────────────────────────────────────────────
	MITRETactics    []string `json:"mitre_tactics"`
	MITRETechniques []string `json:"mitre_techniques"`

	// ── VEX & Confidence ───────────────────────────────────────────────
	VEXStatus   string `json:"vex_status"`             // not_affected | affected | fixed | under_investigation
	Confidence  string `json:"confidence"`             // high | medium | low
	UserVerdict string `json:"user_verdict,omitempty"` // analyst override

	// ── CMMC / NIST 800-171 Compliance ──────────────────────────────────
	// Mapped from CCI→NIST 800-53→NIST 800-171/172→CMMC (docs/CCI_to_NIST53.csv, NIST53_to_171.csv, NIST53_to_172.csv)
	NIST53Controls  []string `json:"nist_53_controls"`  // e.g. ["RA-5", "SI-2"]
	NIST171Controls []string `json:"nist_171_controls"` // e.g. ["3.11.2", "3.14.1"]
	NIST172Controls []string `json:"nist_172_controls"` // e.g. ["3.14.1e", "3.11.2e"] (enhanced controls)
	CCIReferences   []string `json:"cci_references"`    // e.g. ["CCI-001643", "CCI-002605"]
	STIGFindings    []string `json:"stig_findings"`     // STIG requirement definitions from CCI mapping
	CMMCDomain      string   `json:"cmmc_domain,omitempty"` // e.g. "Risk Assessment"

	// ── Metadata ───────────────────────────────────────────────────────
	DetectedAt  time.Time       `json:"detected_at"`
	ScannerMeta ScannerMetadata `json:"scanner_meta"`
}

// ScannerMetadata records tool versions for audit reproducibility.
type ScannerMetadata struct {
	SyftVersion  string    `json:"syft_version,omitempty"`
	GrypeVersion string    `json:"grype_version,omitempty"`
	GrypeDBVersion string  `json:"grype_db_version,omitempty"`
	ScannedAt    time.Time `json:"scanned_at"`
}

// ──────────────────────────────────────────────────────────────────────────────
// Severity Classification
// ──────────────────────────────────────────────────────────────────────────────

// SeverityFromCVSS maps a CVSS v3 base score to a severity string.
// Based on NIST NVD severity ratings:
//
//	9.0 – 10.0  → CRITICAL
//	7.0 –  8.9  → HIGH
//	4.0 –  6.9  → MEDIUM
//	0.1 –  3.9  → LOW
//	0.0         → NONE
func SeverityFromCVSS(score float64) Severity {
	switch {
	case score >= 9.0:
		return SeverityCritical
	case score >= 7.0:
		return SeverityHigh
	case score >= 4.0:
		return SeverityMedium
	case score > 0:
		return SeverityLow
	default:
		return SeverityNone
	}
}

// ClassifySeverity applies CVSS-based severity to the finding, setting
// the Severity field. This is idempotent.
func (f *EnrichedFinding) ClassifySeverity() {
	f.Severity = string(SeverityFromCVSS(f.CVSSv3Score))
}

// ──────────────────────────────────────────────────────────────────────────────
// Risk Heuristics
// ──────────────────────────────────────────────────────────────────────────────

// IsHighRisk returns true if a finding meets any of the "immediate action" thresholds:
//   - CRITICAL severity
//   - HIGH severity AND (EPSS > 0.1 OR in CISA KEV)
//   - Any severity AND actively exploited in the wild
//
// This is the primary triage filter for the ERT analysis stage.
func (f *EnrichedFinding) IsHighRisk() bool {
	sev := Severity(strings.ToUpper(f.Severity))

	// Active exploitation is always high risk regardless of CVSS
	if f.InCISAKEV || f.InTheWild {
		return true
	}

	// CRITICAL is always high risk
	if sev == SeverityCritical {
		return true
	}

	// HIGH + elevated exploit probability
	if sev == SeverityHigh && f.EPSSScore > 0.1 {
		return true
	}

	// PoC available with HIGH severity
	if sev == SeverityHigh && f.PoCAvailable {
		return true
	}

	return false
}

// RiskScore computes a composite risk score (0.0 – 10.0) that accounts for
// CVSS base score, EPSS exploit probability, and threat intelligence signals.
func (f *EnrichedFinding) RiskScore() float64 {
	base := f.CVSSv3Score

	// EPSS weight: up to +1.5 for very high exploit probability
	epssBoost := f.EPSSScore * 1.5

	// Threat intel multipliers
	var intelBoost float64
	if f.InCISAKEV {
		intelBoost += 1.0
	}
	if f.InTheWild {
		intelBoost += 0.5
	}
	if f.PoCAvailable {
		intelBoost += 0.5
	}

	score := base + epssBoost + intelBoost
	if score > 10.0 {
		score = 10.0
	}
	return score
}

// ──────────────────────────────────────────────────────────────────────────────
// EPSS Helpers
// ──────────────────────────────────────────────────────────────────────────────

// EPSSRank returns a human-readable ranking based on EPSS percentile.
func (f *EnrichedFinding) EPSSRank() string {
	switch {
	case f.EPSSPercentile >= 0.95:
		return "top-5%"
	case f.EPSSPercentile >= 0.90:
		return "top-10%"
	case f.EPSSPercentile >= 0.75:
		return "top-25%"
	case f.EPSSPercentile >= 0.50:
		return "top-50%"
	default:
		return "below-50%"
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Serialization Helpers
// ──────────────────────────────────────────────────────────────────────────────

// MarshalJSON implements custom JSON marshaling to ensure consistent output.
func (f *EnrichedFinding) MarshalJSON() ([]byte, error) {
	// Ensure slices are never nil (marshal as [] not null)
	if f.Sources == nil {
		f.Sources = []string{}
	}
	if f.MITRETactics == nil {
		f.MITRETactics = []string{}
	}
	if f.MITRETechniques == nil {
		f.MITRETechniques = []string{}
	}
	if f.NIST53Controls == nil {
		f.NIST53Controls = []string{}
	}
	if f.NIST171Controls == nil {
		f.NIST171Controls = []string{}
	}
	if f.NIST172Controls == nil {
		f.NIST172Controls = []string{}
	}
	if f.CCIReferences == nil {
		f.CCIReferences = []string{}
	}
	if f.STIGFindings == nil {
		f.STIGFindings = []string{}
	}

	// Use type alias to avoid infinite recursion
	type Alias EnrichedFinding
	return json.Marshal((*Alias)(f))
}

// String returns a one-line summary suitable for logging.
func (f *EnrichedFinding) String() string {
	risk := ""
	if f.IsHighRisk() {
		risk = " ⚠️ HIGH-RISK"
	}
	return fmt.Sprintf("[%s] %s %s@%s (CVSS=%.1f, EPSS=%.2f)%s",
		f.Severity, f.CVEID, f.Component, f.Version,
		f.CVSSv3Score, f.EPSSScore, risk)
}
