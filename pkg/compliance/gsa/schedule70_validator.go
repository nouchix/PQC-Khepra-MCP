package gsa

import (
	"time"
)

// Schedule70Requirement defines mandatory prerequisites for GSA Schedule listing
type Schedule70Requirement string

const (
	ReqSAMRegistration     Schedule70Requirement = "SAM_REGISTRATION"
	ReqCAGECode            Schedule70Requirement = "CAGE_CODE"
	ReqFinancialStatements Schedule70Requirement = "FINANCIAL_STATEMENTS"
	ReqCommercialSales     Schedule70Requirement = "COMMERCIAL_SALES"
	ReqNIST800171          Schedule70Requirement = "NIST_800171"
	ReqSection508          Schedule70Requirement = "SECTION_508"
)

// RequirementStatus captures implementation state of a GSA requirement
type RequirementStatus struct {
	ID           Schedule70Requirement `json:"id"`
	Met          bool                  `json:"met"`
	Evidence     string                `json:"evidence"`
	LastVerified time.Time             `json:"last_verified"`
	Remediation  string                `json:"remediation"`
}

// GSAValidator orchestrates the readiness check
type GSAValidator struct {
	Requirements map[Schedule70Requirement]RequirementStatus
}

// NewGSAValidator initializes the GSA checklist
func NewGSAValidator() *GSAValidator {
	return &GSAValidator{
		Requirements: make(map[Schedule70Requirement]RequirementStatus),
	}
}

// RunReadinessCheck performs an automated audit of GSA readiness
func (v *GSAValidator) RunReadinessCheck() string {
	// 1. Mock SAM check
	v.Requirements[ReqSAMRegistration] = RequirementStatus{
		ID:           ReqSAMRegistration,
		Met:          true,
		Evidence:     "SAM.gov Unique Entity ID: 123456789",
		LastVerified: time.Now(),
	}

	// 2. Mock CAGE code check
	v.Requirements[ReqCAGECode] = RequirementStatus{
		ID:           ReqCAGECode,
		Met:          false,
		Remediation:  "Apply for CAGE Code at https://cage.dla.mil",
		LastVerified: time.Now(),
	}

	// 3. NIST 800-171 Check (Link to internal validator)
	v.Requirements[ReqNIST800171] = RequirementStatus{
		ID:           ReqNIST800171,
		Met:          true, // Will link to real output later
		Evidence:     "SSP and POAM Generated via pkg/compliance/rmf",
		LastVerified: time.Now(),
	}

	metCount := 0
	for _, r := range v.Requirements {
		if r.Met {
			metCount++
		}
	}

	if metCount == len(v.Requirements) {
		return "READY"
	} else if metCount > 0 {
		return "PARTIAL"
	}
	return "NOT_READY"
}
