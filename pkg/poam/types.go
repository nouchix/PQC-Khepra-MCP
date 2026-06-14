// Package poam provides a standalone POAM (Plan of Action & Milestones) engine
// for KHEPRA Protocol. Extracted from pkg/stig to allow Enterprise-tier isolation:
// the POAM lifecycle (generate, track, export, eMASS upload) can be consumed
// independently of the full STIG validation pipeline.
//
// NIST SP 800-171A compliance: all POAM items carry dollar-weighted priority
// scores, eMASS artifact IDs, and DAG evidence references.
package poam

import "time"

// ─── Core Types ───────────────────────────────────────────────────────────────

// Severity mirrors pkg/stig.Severity — redeclared here so pkg/poam has no
// circular dependency on pkg/stig.
type Severity string

const (
	SeverityCAT1     Severity = "CAT I"    // High (STIG)
	SeverityCAT2     Severity = "CAT II"   // Medium (STIG)
	SeverityCAT3     Severity = "CAT III"  // Low (STIG)
	SeverityCritical Severity = "Critical" // Critical (CIS/NIST)
	SeverityHigh     Severity = "High"     // High (NIST/CMMC)
	SeverityMedium   Severity = "Medium"   // Medium (NIST/CMMC)
	SeverityLow      Severity = "Low"      // Low (NIST/CMMC)
)

// Item is a single POAM entry — NIST SP 800-171A format with dollar-weighting.
// Field names align with the eMASS POAM import template.
type Item struct {
	// NIST SP 800-171A required fields
	ID                  string    `json:"id"`                   // POAM-YYYY-NNN
	ControlID           string    `json:"control_id"`           // e.g. "3.1.1", "AC-2"
	Weakness            string    `json:"weakness"`             // Description of deficiency
	Severity            Severity  `json:"severity"`
	Status              string    `json:"status"`               // Open | In Progress | Completed | Risk Accepted
	PointOfContact      string    `json:"point_of_contact"`
	EstimatedCost       float64   `json:"estimated_cost_usd"`
	ScheduledCompletion time.Time `json:"scheduled_completion"`
	MilestoneActions    []string  `json:"milestone_actions"`
	Resources           []string  `json:"resources,omitempty"`

	// Dollar-weighted priority fields (KHEPRA extension)
	DollarImpact   float64 `json:"dollar_impact_usd"`  // Financial exposure
	SeverityWeight float64 `json:"severity_weight"`    // CAT I=3.0, CAT II=2.0, CAT III=1.0
	PriorityScore  float64 `json:"priority_score"`     // DollarImpact / EstimatedDays * SeverityWeight
	EstimatedDays  int     `json:"estimated_days"`

	// Evidence & eMASS tracking
	EvidenceRefs    []string   `json:"evidence_refs,omitempty"`
	EMASSArtifactID string     `json:"emass_artifact_id,omitempty"`
	ClosedAt        *time.Time `json:"closed_at,omitempty"`
}

// Register holds a complete POAM register for a system assessment.
type Register struct {
	System        string    `json:"system"`
	GeneratedAt   time.Time `json:"generated_at"`
	TotalExposure float64   `json:"total_exposure_usd"`
	Items         []Item    `json:"items"`
}

// ─── Severity config table ────────────────────────────────────────────────────

// SeverityConfig defines the dollar impact, remediation timeline, and priority
// weight for each severity level. Based on IBM Cost of Data Breach Report 2024
// ($500K baseline) and DoD remediation effort benchmarks.
type SeverityConfig struct {
	Days   int
	Weight float64
	Cost   float64 // USD per finding
}

// DefaultSeverityTable is the standard severity → cost/effort mapping.
var DefaultSeverityTable = map[Severity]SeverityConfig{
	SeverityCAT1:     {Days: 7, Weight: 3.0, Cost: 150000},
	SeverityCritical: {Days: 7, Weight: 3.0, Cost: 150000},
	SeverityCAT2:     {Days: 14, Weight: 2.0, Cost: 50000},
	SeverityHigh:     {Days: 14, Weight: 2.0, Cost: 50000},
	SeverityCAT3:     {Days: 30, Weight: 1.0, Cost: 10000},
	SeverityMedium:   {Days: 30, Weight: 1.0, Cost: 10000},
	SeverityLow:      {Days: 60, Weight: 0.5, Cost: 2500},
}

// DefaultSeverityConfig is the fallback when severity is unknown.
var DefaultSeverityConfig = SeverityConfig{Days: 30, Weight: 1.0, Cost: 10000}
