package nist80172

import (
	"time"
)

// NIST 800-172 Families (corresponds to NIST 800-171 plus enhanced requirements)
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

// EnhancedResult represents the outcome of a NIST 800-172 enhanced security requirement check
type EnhancedResult struct {
	ControlID   string    `json:"control_id"` // e.g., 3.1.1e, 3.1.2e
	Title       string    `json:"title"`
	Family      string    `json:"family"`
	Description string    `json:"description"`
	Status      string    `json:"status"` // PASS, FAIL, NOT_APPLICABLE, MANUAL_REVIEW
	Finding     string    `json:"finding"`
	Remediation string    `json:"remediation"`
	Evidence    []string  `json:"evidence"` // IDs of evidence nodes (DAG)
	CheckedAt   time.Time `json:"checked_at"`
}

// EnhancedSummary provides a high-level view of NIST 800-172 posture
type EnhancedSummary struct {
	TotalControls   int     `json:"total_controls"`
	Passed          int     `json:"passed"`
	Failed          int     `json:"failed"`
	ManualReview    int     `json:"manual_review"`
	NotApplicable   int     `json:"not_applicable"`
	Score           float64 `json:"score"`            // 0-100%
	BaselineVersion string  `json:"baseline_version"` // Rev 1
}

// EnhancedValidator validates a system against NIST 800-172
type EnhancedValidator struct {
	Results []EnhancedResult
	Summary EnhancedSummary
}

// NewEnhancedValidator initializes a new NIST 800-172 validator
func NewEnhancedValidator() *EnhancedValidator {
	return &EnhancedValidator{
		Results: []EnhancedResult{},
		Summary: EnhancedSummary{
			TotalControls:   35, // Approximate number of enhanced requirements in Rev 1
			BaselineVersion: "Enhanced (Rev 1)",
		},
	}
}
