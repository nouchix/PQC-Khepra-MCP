package nist80171

import (
	"time"
)

// NIST 800-171 Families (14 total)
const (
	FamilyAC = "Access Control"
	FamilyAU = "Audit and Accountability"
	FamilyAT = "Awareness and Training"
	FamilyCM = "Configuration Management"
	FamilyIA = "Identification and Authentication"
	FamilyIR = "Incident Response"
	FamilyMA = "Maintenance"
	FamilyMP = "Media Protection"
	FamilyPS = "Personnel Security"
	FamilyPE = "Physical Protection"
	FamilyRA = "Risk Assessment"
	FamilyCA = "Security Assessment"
	FamilySC = "System and Communications Protection"
	FamilySI = "System and Information Integrity"
)

// ControlResult represents the outcome of a single NIST 800-171 control check
type ControlResult struct {
	ControlID   string    `json:"control_id"`
	Title       string    `json:"title"`
	Family      string    `json:"family"`
	Description string    `json:"description"`
	Status      string    `json:"status"` // PASS, FAIL, NOT_APPLICABLE, MANUAL_REVIEW
	Finding     string    `json:"finding"`
	Remediation string    `json:"remediation"`
	Evidence    []string  `json:"evidence"` // IDs of evidence nodes (DAG)
	CheckedAt   time.Time `json:"checked_at"`
}

// ComplianceSummary provides a high-level view of NIST 800-171 posture
type ComplianceSummary struct {
	TotalControls   int     `json:"total_controls"`
	Passed          int     `json:"passed"`
	Failed          int     `json:"failed"`
	ManualReview    int     `json:"manual_review"`
	NotApplicable   int     `json:"not_applicable"`
	Score           float64 `json:"score"`            // 0-100%
	BaselineVersion string  `json:"baseline_version"` // Rev 2
}

// Validator validates a system against NIST 800-171
type Validator struct {
	Results []ControlResult
	Summary ComplianceSummary
}

// NewValidator initializes a new NIST 800-171 validator
func NewValidator() *Validator {
	return &Validator{
		Results: []ControlResult{},
		Summary: ComplianceSummary{
			TotalControls:   110,
			BaselineVersion: "Rev 2",
		},
	}
}
