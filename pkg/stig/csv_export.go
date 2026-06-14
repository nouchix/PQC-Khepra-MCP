package stig

import (
	"encoding/csv"
	"fmt"
	"os"
	"strings"
	"time"
)

// ExportToCSV exports comprehensive validation results to CSV format
// Suitable for bulk analysis, Excel import, and automated processing
func (r *ComprehensiveReport) ExportToCSV(outputPath string) error {
	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create CSV file: %w", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write header row
	header := []string{
		"Framework",
		"Control ID",
		"Title",
		"Description",
		"Severity",
		"Status",
		"Expected",
		"Actual",
		"Remediation",
		"References",
		"Checked At",
	}
	if err := writer.Write(header); err != nil {
		return fmt.Errorf("failed to write CSV header: %w", err)
	}

	// Write findings from each framework
	for frameworkName, result := range r.Results {
		for _, finding := range result.Findings {
			row := []string{
				frameworkName,
				finding.ID,
				finding.Title,
				finding.Description,
				string(finding.Severity),
				finding.Status,
				finding.Expected,
				finding.Actual,
				finding.Remediation,
				strings.Join(finding.References, "; "),
				finding.CheckedAt.Format(time.RFC3339),
			}
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("failed to write CSV row: %w", err)
			}
		}
	}

	return nil
}

// ExportExecutiveSummaryToCSV exports executive summary to CSV
func (r *ComprehensiveReport) ExportExecutiveSummaryToCSV(outputPath string) error {
	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create summary CSV: %w", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Summary metadata
	metadata := [][]string{
		{"Report Date", r.ScanDate.Format(time.RFC3339)},
		{"Hostname", r.Hostname},
		{"OS Version", r.OSVersion},
		{"Scan Duration", r.ScanDuration.String()},
		{"", ""},
		{"Metric", "Value"},
		{"Overall Compliance", fmt.Sprintf("%.2f%%", r.ExecutiveSummary.OverallCompliance)},
		{"Compliance Grade", r.ExecutiveSummary.ComplianceGrade},
		{"Overall Risk", r.ExecutiveSummary.OverallRisk},
		{"CAT I Findings", fmt.Sprintf("%d", r.ExecutiveSummary.CAT1Findings)},
		{"CAT II Findings", fmt.Sprintf("%d", r.ExecutiveSummary.CAT2Findings)},
		{"CAT III Findings", fmt.Sprintf("%d", r.ExecutiveSummary.CAT3Findings)},
		{"", ""},
		{"Framework Compliance", "Score"},
		{"RHEL-09-STIG", fmt.Sprintf("%.2f%%", r.ExecutiveSummary.STIGCompliance)},
		{"CIS Benchmark", fmt.Sprintf("%.2f%%", r.ExecutiveSummary.CISCompliance)},
		{"NIST 800-53", fmt.Sprintf("%.2f%%", r.ExecutiveSummary.NIST80053Compliance)},
		{"NIST 800-171", fmt.Sprintf("%.2f%%", r.ExecutiveSummary.NIST800171Compliance)},
		{"CMMC 3.0 L3", fmt.Sprintf("%.2f%%", r.ExecutiveSummary.CMMCCompliance)},
		{"", ""},
		{"PQC Readiness", r.ExecutiveSummary.PQCReadinessGrade},
		{"PQC Migration Required", fmt.Sprintf("%v", r.ExecutiveSummary.PQCMigrationRequired)},
	}

	for _, row := range metadata {
		if err := writer.Write(row); err != nil {
			return fmt.Errorf("failed to write summary row: %w", err)
		}
	}

	// Top risks
	writer.Write([]string{"", ""})
	writer.Write([]string{"Top Risks", ""})
	for i, risk := range r.ExecutiveSummary.TopRisks {
		writer.Write([]string{fmt.Sprintf("%d", i+1), risk})
	}

	// Recommendations
	writer.Write([]string{"", ""})
	writer.Write([]string{"Executive Recommendations", ""})
	for i, rec := range r.ExecutiveSummary.ExecutiveRecommendations {
		writer.Write([]string{fmt.Sprintf("%d", i+1), rec})
	}

	return nil
}

// ExportPOAMToCSV exports Plan of Action & Milestones to CSV
func (r *ComprehensiveReport) ExportPOAMToCSV(outputPath string) error {
	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create POAM CSV: %w", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// POAM header (standard DoD POAM format)
	header := []string{
		"POAM ID",
		"Control ID",
		"Weakness Description",
		"Severity",
		"Status",
		"Point of Contact",
		"Estimated Cost (USD)",
		"Scheduled Completion",
		"Milestone Actions",
		"Required Resources",
	}
	if err := writer.Write(header); err != nil {
		return fmt.Errorf("failed to write POAM header: %w", err)
	}

	// Write POAM items
	for _, poam := range r.POAMItems {
		row := []string{
			poam.ID,
			poam.ControlID,
			poam.Weakness,
			string(poam.Severity),
			poam.Status,
			poam.PointOfContact,
			fmt.Sprintf("$%.2f", poam.EstimatedCost),
			poam.ScheduledCompletion.Format("2006-01-02"),
			strings.Join(poam.MilestoneActions, "; "),
			strings.Join(poam.Resources, "; "),
		}
		if err := writer.Write(row); err != nil {
			return fmt.Errorf("failed to write POAM row: %w", err)
		}
	}

	return nil
}

// ExportBlastRadiusToCSV exports PQC blast radius analysis to CSV
func (r *ComprehensiveReport) ExportBlastRadiusToCSV(outputPath string) error {
	if r.PQCBlastRadius == nil {
		return fmt.Errorf("no blast radius analysis available")
	}

	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create blast radius CSV: %w", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Summary metrics
	summary := [][]string{
		{"Metric", "Value"},
		{"Total Crypto Operations", fmt.Sprintf("%d", r.PQCBlastRadius.TotalCryptoOperations)},
		{"Legacy Crypto Operations", fmt.Sprintf("%d", r.PQCBlastRadius.LegacyCryptoOperations)},
		{"PQC Ready Operations", fmt.Sprintf("%d", r.PQCBlastRadius.PQCReadyOperations)},
		{"PQC Readiness Score", fmt.Sprintf("%.2f%%", r.PQCBlastRadius.PQCReadinessScore)},
		{"Estimated Migration Days", fmt.Sprintf("%d", r.PQCBlastRadius.EstimatedMigrationDays)},
		{"", ""},
	}

	for _, row := range summary {
		writer.Write(row)
	}

	// Vulnerable protocols
	writer.Write([]string{"Vulnerable Protocols", ""})
	for _, protocol := range r.PQCBlastRadius.VulnerableProtocols {
		writer.Write([]string{"", protocol})
	}
	writer.Write([]string{"", ""})

	// Risk systems
	writer.Write([]string{"High Risk Systems", ""})
	for _, sys := range r.PQCBlastRadius.HighRiskSystems {
		writer.Write([]string{"High", sys})
	}
	for _, sys := range r.PQCBlastRadius.MediumRiskSystems {
		writer.Write([]string{"Medium", sys})
	}
	for _, sys := range r.PQCBlastRadius.LowRiskSystems {
		writer.Write([]string{"Low", sys})
	}
	writer.Write([]string{"", ""})

	// Actions
	writer.Write([]string{"Action Timeline", "Action"})
	for _, action := range r.PQCBlastRadius.ImmediateActions {
		writer.Write([]string{"Immediate", action})
	}
	for _, action := range r.PQCBlastRadius.ShortTermActions {
		writer.Write([]string{"Short-term (3 months)", action})
	}
	for _, action := range r.PQCBlastRadius.LongTermActions {
		writer.Write([]string{"Long-term (12 months)", action})
	}

	return nil
}
