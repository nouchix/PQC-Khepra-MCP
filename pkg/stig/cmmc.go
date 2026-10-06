package stig

import (
	"fmt"
	"strings"
	"time"
)

// StatusNotAssessed marks a practice for which this validation holds no
// evidence either way. It is the default: a practice is "Pass" only when
// every NIST 800-53 control it maps to has passing automated checks and no
// rule is still waiting for manual review.
const StatusNotAssessed = "Not Assessed"

// controlEvidence is what the other frameworks in this validation say about
// one NIST 800-53 control.
type controlEvidence struct {
	passed     int    // passing automated rules mapped to the control
	failed     int    // failing rules mapped to the control
	pending    int    // rules mapped to the control that await manual review
	failReason string // title of the first failing rule
}

// validateCMMC derives CMMC Level 2 (NIST 800-171) and Level 3 (800-172)
// practice status from the findings of the other frameworks that ran in this
// validation, through the STIG → CCI → NIST 800-53 crosswalk.
func (v *Validator) validateCMMC(result *ValidationResult) error {
	result.Version = "3.0 Level 3"

	db, err := GetDatabase()
	if err != nil {
		return err
	}

	evidence := make(map[string]*controlEvidence)
	for name, res := range v.report.Results {
		if name == FrameworkCMMC || res == nil {
			continue // Avoid recursion
		}
		for _, f := range res.Findings {
			if f.Status == "Not Applicable" {
				continue
			}
			refs, _ := db.GetCrossReferences(f.ID)
			for _, ref := range refs {
				if !strings.HasPrefix(ref, "NIST-800-53:") {
					continue
				}
				ctrl := strings.TrimPrefix(ref, "NIST-800-53:")
				e := evidence[ctrl]
				if e == nil {
					e = &controlEvidence{}
					evidence[ctrl] = e
				}
				switch f.Status {
				case "Fail":
					e.failed++
					if e.failReason == "" {
						e.failReason = f.Title
					}
				case "Pass":
					e.passed++
				default:
					e.pending++
				}
			}
		}
	}

	// 1. Process Level 2 Controls (NIST 800-171)
	for nist171, nist53Refs := range db.NIST171to53 {
		v.processCMMCControl(result, db, "L2", nist171, nist53Refs, evidence)
	}

	// 2. Process Level 3 Controls (NIST 800-172)
	for nist172, nist53Refs := range db.NIST172to53 {
		v.processCMMCControl(result, db, "L3", nist172, nist53Refs, evidence)
	}

	v.addPQCAdvancedL3(result)

	return nil
}

func (v *Validator) processCMMCControl(result *ValidationResult, db *ComplianceDatabase, level string, nistRef string, nist53Refs []string, evidence map[string]*controlEvidence) {
	// Identify family
	family := "General"
	if len(nist53Refs) > 0 {
		// Try to find mapping in 171 database
		for _, m := range db.NIST53to171[nist53Refs[0]] {
			if m.NIST171Ref == nistRef {
				family = m.ControlFamily
				break
			}
		}
		// If not found (could be L3), try 172 database
		if family == "General" {
			for _, m := range db.NIST53to172[nist53Refs[0]] {
				if m.NIST171Ref == nistRef {
					family = m.ControlFamily
					break
				}
			}
		}
	}

	status, actual := cmmcPracticeStatus(nist53Refs, evidence)

	finding := Finding{
		ID:          fmt.Sprintf("CMMC:%s.%s-%s", strings.ReplaceAll(family, " ", ""), level, nistRef),
		Title:       fmt.Sprintf("CMMC %s Control %s", level, nistRef),
		Description: fmt.Sprintf("%s requirement derived from NIST %s: %s", level, v.getSourceDoc(level), nistRef),
		Severity:    v.getSeverity(nistRef, nist53Refs),
		Status:      status,
		Expected:    "Requirement implementation meets CMMC/NIST standards",
		Actual:      actual,
		Remediation: v.getRemediation(status, nist53Refs),
		References:  append([]string{fmt.Sprintf("NIST-800-%s:%s", v.getSourceDoc(level)[4:], nistRef)}, nist53Refs...),
		CheckedAt:   time.Now(),
	}

	result.Findings = append(result.Findings, finding)
}

// cmmcPracticeStatus decides a practice's status from the evidence for the
// NIST 800-53 controls it maps to.
func cmmcPracticeStatus(nist53Refs []string, evidence map[string]*controlEvidence) (status, actual string) {
	var failures []string
	covered, passedRules, pending := 0, 0, 0
	for _, ref := range nist53Refs {
		e := evidence[ref]
		if e == nil {
			continue
		}
		if e.failed > 0 {
			failures = append(failures, fmt.Sprintf("%s (%s)", ref, e.failReason))
		}
		if e.passed > 0 {
			covered++
			passedRules += e.passed
		}
		pending += e.pending
	}
	switch {
	case len(failures) > 0:
		return "Fail", "Non-compliance detected in underlying security control(s): " + strings.Join(failures, "; ")
	case len(nist53Refs) > 0 && covered == len(nist53Refs) && pending == 0:
		return "Pass", fmt.Sprintf("All %d mapped NIST 800-53 control(s) have passing automated checks (%d rule results) and no rule awaits manual review. Technical checks only; confirm the practice's NIST SP 800-171A objectives with evidence.", len(nist53Refs), passedRules)
	case covered > 0 || pending > 0:
		return StatusNotAssessed, fmt.Sprintf("Not assessed: %d of %d mapped NIST 800-53 control(s) have passing automated checks; %d rule result(s) await manual review.", covered, len(nist53Refs), pending)
	default:
		return StatusNotAssessed, "Not assessed: no check in this validation covers the NIST 800-53 controls this practice maps to. Provide evidence against the NIST SP 800-171A assessment objectives."
	}
}

func (v *Validator) getSourceDoc(level string) string {
	if level == "L3" {
		return "800-172"
	}
	return "800-171"
}

func (v *Validator) getSeverity(ref string, nist53 []string) Severity {
	for _, ctrl := range nist53 {
		if strings.HasPrefix(ctrl, "SC-13") || strings.HasPrefix(ctrl, "SC-28") {
			return SeverityCAT1
		}
	}
	if strings.Contains(ref, "L3") {
		return SeverityHigh
	}
	return SeverityMedium
}

func (v *Validator) getRemediation(status string, nist53 []string) string {
	if status == "Pass" {
		return "N/A"
	}
	if status == StatusNotAssessed {
		if len(nist53) > 0 {
			return fmt.Sprintf("Run the STIG benchmarks that cover %s, or attach assessment evidence for this practice.", strings.Join(nist53, ", "))
		}
		return "Attach assessment evidence for this practice."
	}
	if len(nist53) > 0 {
		return fmt.Sprintf("Apply STIG configuration settings associated with %s controls.", strings.Join(nist53, ", "))
	}
	return "Manual remediation required."
}

func (v *Validator) addPQCAdvancedL3(result *ValidationResult) {
	status := StatusNotAssessed
	actual := "Not assessed: the PQC-01-STIG framework did not run in this validation."
	if res, ok := v.report.Results[FrameworkPQCStig]; ok && res != nil && res.Passed+res.Failed > 0 {
		if res.Failed > 0 {
			status = "Fail"
			actual = fmt.Sprintf("%d of %d executed PQC-01-STIG checks failed.", res.Failed, res.Passed+res.Failed)
		} else {
			status = "Pass"
			actual = fmt.Sprintf("All %d executed PQC-01-STIG checks passed.", res.Passed)
		}
	}
	result.Findings = append(result.Findings, Finding{
		ID:          "CMMC:SC.L3-PQC-001",
		Title:       "Post-Quantum Cryptography Readiness (NouchiX extension, not a CMMC practice)",
		Description: "NouchiX extension reported alongside CMMC: quantum-vulnerable cryptography, from the PQC-01-STIG results.",
		Severity:    SeverityCritical,
		Status:      status,
		Expected:    "No failing PQC-01-STIG checks.",
		Actual:      actual,
		References:  []string{"NouchiX-PQC-01-STIG", "NIST-800-53:SC-13"},
		CheckedAt:   time.Now(),
	})
}
