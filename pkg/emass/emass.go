package emass

// pkg/emass — eMASS (Enterprise Mission Assurance Support Service) export
//
// Generates eMASS-compatible XML for:
//   - System Security Plans (SSP) per DoDI 8510.01
//   - Plan of Action & Milestones (POAM) per NIST SP 800-137
//   - Test Results (STIG findings → eMASS "Test Result" records)
//
// eMASS XML schema reference:
//   https://emass.army.mil/emass/xsd/emass_poc.xsd (internal DoD network)
//
// Usage:
//   exporter := emass.NewExporter("ABC Defense Corp", "12345")
//   exporter.AddSSP(sspDoc)
//   exporter.AddPOAMItems(poamItems)
//   exporter.AddTestResults(findings)
//   err := exporter.WriteXML("emass_package.xml")

import (
	"encoding/xml"
	"fmt"
	"os"
	"strings"
	"time"
)

// ─── eMASS XML document structures ───────────────────────────────────────────
// Field names match the eMASS import template column headers exactly.

// EMassPackage is the root element of an eMASS import XML file.
type EMassPackage struct {
	XMLName    xml.Name      `xml:"eMASS"`
	Version    string        `xml:"version,attr"`
	ExportDate string        `xml:"exportDate,attr"`
	SystemInfo SystemInfo    `xml:"systemInformation"`
	SSP        *SSPSection   `xml:"systemSecurityPlan,omitempty"`
	POAM       *POAMSection  `xml:"planOfActionAndMilestones,omitempty"`
	TestResult *TRSection    `xml:"testResults,omitempty"`
}

// SystemInfo matches eMASS "System Information" tab fields.
type SystemInfo struct {
	SystemName        string `xml:"systemName"`
	SystemID          string `xml:"systemId"`           // eMASS system ID (if assigned)
	OrganizationID    string `xml:"organizationId"`
	SystemType        string `xml:"systemType"`         // "IS" (Information System) or "PIT"
	ImpactLevel       string `xml:"impactLevel"`        // Low / Moderate / High
	CUIOverlay        string `xml:"cuiOverlay"`         // CUI or N/A
	ClassificationStr string `xml:"classification"`     // U, CUI, S, TS
	ISSO              string `xml:"isso"`
	AuthorizingOfficial string `xml:"authorizingOfficial"`
	AuthorizationDate string `xml:"authorizationDate"`
	AuthorizationType string `xml:"authorizationType"` // "ATO", "IATT", "DATO"
	ATOExpirationDate string `xml:"atoExpirationDate"`
	RegistrationDate  string `xml:"registrationDate"`
	Description       string `xml:"description"`
	PackagingDate     string `xml:"packagingDate"`
}

// SSPSection maps to the eMASS "SSP" import tab.
type SSPSection struct {
	Controls []SSPControl `xml:"control"`
}

// SSPControl is a single NIST 800-53/171 control implementation record.
type SSPControl struct {
	ControlNumber          string `xml:"controlNumber"`      // e.g. "AC-1" or "3.1.1"
	ControlAcronym         string `xml:"controlAcronym"`     // e.g. "AC.L2-3.1.1"
	ImplementationStatus   string `xml:"implementationStatus"` // Implemented | Planned | Inherited | Not Applicable | Manually Inherited
	ControlText            string `xml:"controlText"`
	ImplementationNarrative string `xml:"implementationNarrative"`
	ResponsibleEntities    string `xml:"responsibleEntities"`
	EstimatedCompletionDate string `xml:"estimatedCompletionDate,omitempty"`
	MilestoneChanges       string `xml:"milestoneChanges,omitempty"`
}

// POAMSection maps to the eMASS "POA&M" import tab.
type POAMSection struct {
	Items []POAMItem `xml:"poamItem"`
}

// POAMItem is a single POA&M entry in eMASS format.
type POAMItem struct {
	POAMID                   string `xml:"poamId"`
	ControlVulnerabilityDesc string `xml:"controlVulnerabilityDescription"`
	SecurityControlNumber    string `xml:"securityControlNumber"`   // e.g. "AC-2"
	OfficeOrg                string `xml:"officeOrg"`
	SecurityChecks           string `xml:"securityChecks"`          // STIG IDs
	Resources                string `xml:"resources"`               // Est. cost
	Status                   string `xml:"status"`                  // Ongoing | Completed | Risk Accepted
	MitigatedBy              string `xml:"mitigatedBy,omitempty"`
	Scheduled                string `xml:"scheduledCompletionDate"` // MM/DD/YYYY
	Milestone                string `xml:"milestone"`
	MilestoneChanges         string `xml:"milestoneChanges,omitempty"`
	SourceID                 string `xml:"sourceIdentificationId"`
	ReviewerNotes            string `xml:"reviewerNotes,omitempty"`
	Severity                 string `xml:"rawSeverity"` // I, II, III (CAT I/II/III)
	Relevance                string `xml:"relevanceOfThreat"` // High, Moderate, Low
	Likelihood               string `xml:"likelihood"`
	Impact                   string `xml:"impact"`
	ImpactDescription        string `xml:"impactDescription"`
	Residual                 string `xml:"residualRiskLevel"`
	Recommendations          string `xml:"recommendations"`
}

// TRSection maps to eMASS "Test Results" import tab.
type TRSection struct {
	Results []TestResult `xml:"testResult"`
}

// TestResult is a single STIG finding imported as an eMASS test result.
type TestResult struct {
	SystemID      string `xml:"systemId"`
	ControlNumber string `xml:"controlNumber"`
	CCID          string `xml:"cci"`
	TestDate      string `xml:"testDate"`   // MM/DD/YYYY
	ComplianceStatus string `xml:"complianceStatus"` // Compliant | Non-Compliant | Not Applicable | Not Reviewed
	TestedBy      string `xml:"testedBy"`
	TestComments  string `xml:"testComments"`
	FindingDetails string `xml:"findingDetails"`
}

// ─── Exporter ─────────────────────────────────────────────────────────────────

// Exporter builds eMASS-compatible XML packages from KHEPRA scan results.
type Exporter struct {
	pkg *EMassPackage
}

// NewExporter creates a new eMASS package for the given system.
// systemID: eMASS-assigned system ID (use "TBD" if not yet registered)
func NewExporter(systemName, systemID string) *Exporter {
	return &Exporter{
		pkg: &EMassPackage{
			Version:    "1.0",
			ExportDate: time.Now().Format("01/02/2006"),
			SystemInfo: SystemInfo{
				SystemName:        systemName,
				SystemID:          systemID,
				SystemType:        "IS",
				ImpactLevel:       "Moderate",
				CUIOverlay:        "CUI",
				ClassificationStr: "U",
				RegistrationDate:  time.Now().Format("01/02/2006"),
				PackagingDate:     time.Now().Format("01/02/2006"),
			},
		},
	}
}

// SetSystemInfo populates optional system metadata fields.
func (e *Exporter) SetSystemInfo(isso, ao, authType, atoExpiry, desc string) {
	e.pkg.SystemInfo.ISSO = isso
	e.pkg.SystemInfo.AuthorizingOfficial = ao
	e.pkg.SystemInfo.AuthorizationType = authType
	e.pkg.SystemInfo.ATOExpirationDate = atoExpiry
	e.pkg.SystemInfo.Description = desc
	if authType == "ATO" {
		e.pkg.SystemInfo.AuthorizationDate = time.Now().Format("01/02/2006")
	}
}

// AddSSPControl adds a single control implementation record.
func (e *Exporter) AddSSPControl(controlNum, acronym, status, narrative string) {
	if e.pkg.SSP == nil {
		e.pkg.SSP = &SSPSection{}
	}
	e.pkg.SSP.Controls = append(e.pkg.SSP.Controls, SSPControl{
		ControlNumber:           controlNum,
		ControlAcronym:          acronym,
		ImplementationStatus:    mapSSPStatus(status),
		ImplementationNarrative: narrative,
		ResponsibleEntities:     e.pkg.SystemInfo.ISSO,
	})
}

// AddPOAMItem adds a single POA&M entry from KHEPRA POAM data.
// severity: "CAT1"/"CAT2"/"CAT3" → maps to eMASS "I"/"II"/"III"
func (e *Exporter) AddPOAMItem(id, controlNum, description, stigID, severity string,
	estimatedCost float64, scheduledCompletion time.Time, milestone string) {
	if e.pkg.POAM == nil {
		e.pkg.POAM = &POAMSection{}
	}

	catRoman := mapSeverityToCAT(severity)
	relevance := "High"
	if catRoman == "II" {
		relevance = "Moderate"
	} else if catRoman == "III" {
		relevance = "Low"
	}

	e.pkg.POAM.Items = append(e.pkg.POAM.Items, POAMItem{
		POAMID:                   id,
		ControlVulnerabilityDesc: description,
		SecurityControlNumber:    controlNum,
		OfficeOrg:                e.pkg.SystemInfo.ISSO,
		SecurityChecks:           stigID,
		Resources:                fmt.Sprintf("$%.0f", estimatedCost),
		Status:                   "Ongoing",
		Scheduled:                scheduledCompletion.Format("01/02/2006"),
		Milestone:                milestone,
		SourceID:                 stigID,
		Severity:                 catRoman,
		Relevance:                relevance,
		Likelihood:               relevance,
		Impact:                   relevance,
		ImpactDescription:        fmt.Sprintf("Failure to remediate %s control %s exposes CUI to unauthorized access.", catRoman, controlNum),
		Residual:                 relevance,
		Recommendations:          milestone,
	})
}

// AddTestResult adds a STIG finding as an eMASS test result record.
func (e *Exporter) AddTestResult(controlNum, cciID, testedBy, finding, status string, testDate time.Time) {
	if e.pkg.TestResult == nil {
		e.pkg.TestResult = &TRSection{}
	}

	compliance := "Non-Compliant"
	switch strings.ToLower(status) {
	case "pass", "compliant", "implemented":
		compliance = "Compliant"
	case "not applicable", "n/a":
		compliance = "Not Applicable"
	case "not reviewed":
		compliance = "Not Reviewed"
	}

	e.pkg.TestResult.Results = append(e.pkg.TestResult.Results, TestResult{
		SystemID:         e.pkg.SystemInfo.SystemID,
		ControlNumber:    controlNum,
		CCID:             cciID,
		TestDate:         testDate.Format("01/02/2006"),
		ComplianceStatus: compliance,
		TestedBy:         testedBy,
		TestComments:     fmt.Sprintf("Automated assessment by AdinKhepra ASAF v2.0 on %s", testDate.Format("2006-01-02")),
		FindingDetails:   finding,
	})
}

// WriteXML serializes the eMASS package to an XML file.
// The output is compatible with eMASS bulk import.
func (e *Exporter) WriteXML(outputPath string) error {
	f, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("emass: create output: %w", err)
	}
	defer f.Close()

	f.WriteString(xml.Header)
	f.WriteString("<?xml-stylesheet type=\"text/xsl\" href=\"emass.xsl\"?>\n")

	enc := xml.NewEncoder(f)
	enc.Indent("", "  ")
	if err := enc.Encode(e.pkg); err != nil {
		return fmt.Errorf("emass: encode XML: %w", err)
	}
	return enc.Close()
}

// Summary returns a human-readable summary of the package contents.
func (e *Exporter) Summary() string {
	sspCount, poamCount, trCount := 0, 0, 0
	if e.pkg.SSP != nil {
		sspCount = len(e.pkg.SSP.Controls)
	}
	if e.pkg.POAM != nil {
		poamCount = len(e.pkg.POAM.Items)
	}
	if e.pkg.TestResult != nil {
		trCount = len(e.pkg.TestResult.Results)
	}
	return fmt.Sprintf(
		"eMASS Package: %s (ID: %s)\n  SSP controls:  %d\n  POAM items:    %d\n  Test results:  %d",
		e.pkg.SystemInfo.SystemName, e.pkg.SystemInfo.SystemID,
		sspCount, poamCount, trCount,
	)
}

// ─── Mapping helpers ──────────────────────────────────────────────────────────

// mapSSPStatus converts KHEPRA status strings to eMASS implementation status values.
func mapSSPStatus(status string) string {
	switch strings.ToUpper(status) {
	case "IMPLEMENTED", "PASS":
		return "Implemented"
	case "PLANNED", "OPEN":
		return "Planned"
	case "PARTIAL", "PARTIALLY_IMPLEMENTED":
		return "Partially Implemented"
	case "INHERITED":
		return "Inherited"
	case "N/A", "NOT_APPLICABLE":
		return "Not Applicable"
	case "FAILED_SCAN":
		return "Planned" // Failed scan items become planned remediations in eMASS
	default:
		return "Planned"
	}
}

// mapSeverityToCAT maps KHEPRA severity strings to eMASS CAT Roman numerals.
func mapSeverityToCAT(severity string) string {
	switch strings.ToUpper(severity) {
	case "CAT1", "CRITICAL", "HIGH", "CAT_I":
		return "I"
	case "CAT2", "MEDIUM", "CAT_II":
		return "II"
	case "CAT3", "LOW", "CAT_III":
		return "III"
	default:
		return "II"
	}
}
