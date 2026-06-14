package audit

import (
	"encoding/csv"
	"os"
	"strconv"
)

// ExportToCSV converts a RiskReport into a CSV file suitable for Apache Superset.
func ExportToCSV(report *RiskReport, outputPath string) error {
	file, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// 1. Header Row
	header := []string{
		"scan_id",
		"client",
		"severity",
		"title",
		"description",
		"remediation",
		"causal_link_id",
		"stig_reference",
		"risk_score", // Numeric mapping for visualization
	}
	if err := writer.Write(header); err != nil {
		return err
	}

	// 2. Data Rows
	for _, risk := range report.Risks {
		score := 0
		switch risk.Severity {
		case "CRITICAL":
			score = 100
		case "HIGH":
			score = 75
		case "MEDIUM":
			score = 50
		case "LOW":
			score = 25
		}

		row := []string{
			report.ScanID,
			report.Client,
			risk.Severity,
			risk.Title,
			risk.Description,
			risk.Remediation,
			risk.CausalLink,
			risk.STIGReference,
			strconv.Itoa(score),
		}

		if err := writer.Write(row); err != nil {
			return err
		}
	}

	return nil
}
