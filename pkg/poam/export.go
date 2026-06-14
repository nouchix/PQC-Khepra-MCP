package poam

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/stig"
)

// ─── Export functions ─────────────────────────────────────────────────────────

// ExportJSON serializes the register to a JSON file.
func (r *Register) ExportJSON(outputPath string) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("poam: json marshal: %w", err)
	}
	return os.WriteFile(outputPath, data, 0644)
}

// ExportCSV writes the register to a CSV file in NIST SP 800-171A format.
func (r *Register) ExportCSV(outputPath string) error {
	f, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("poam: create csv: %w", err)
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	headers := []string{
		"POAM ID", "Control ID", "Weakness Description", "Severity",
		"Status", "Point of Contact", "Dollar Impact (USD)",
		"Priority Score", "Estimated Days", "Scheduled Completion",
		"Milestone Actions",
	}
	if err := w.Write(headers); err != nil {
		return err
	}

	for _, item := range r.Items {
		row := []string{
			item.ID,
			item.ControlID,
			item.Weakness,
			string(item.Severity),
			item.Status,
			item.PointOfContact,
			fmt.Sprintf("%.0f", item.DollarImpact),
			fmt.Sprintf("%.0f", item.PriorityScore),
			fmt.Sprintf("%d", item.EstimatedDays),
			item.ScheduledCompletion.Format("2006-01-02"),
			strings.Join(item.MilestoneActions, "; "),
		}
		if err := w.Write(row); err != nil {
			return err
		}
	}
	return nil
}

// ExportPDF writes a binary PDF using pkg/stig's ssp_poam_pdf infrastructure.
// This is the authoritative PDF path — no Markdown fallback.
func (r *Register) ExportPDF(outputPath string, dagChainDepth int, pqcSig string) error {
	if !strings.HasSuffix(outputPath, ".pdf") {
		outputPath += ".pdf"
	}

	items := make([]stig.POAMExportItem, 0, len(r.Items))
	for _, item := range r.Items {
		items = append(items, stig.POAMExportItem{
			ID:                  item.ID,
			ControlID:           item.ControlID,
			Weakness:            item.Weakness,
			Severity:            string(item.Severity),
			Status:              item.Status,
			DollarImpact:        item.DollarImpact,
			PriorityScore:       item.PriorityScore,
			EstimatedDays:       item.EstimatedDays,
			ScheduledCompletion: item.ScheduledCompletion,
			PointOfContact:      item.PointOfContact,
			MilestoneActions:    item.MilestoneActions,
		})
	}

	data := &stig.POAMExportData{
		System:        r.System,
		GeneratedAt:   time.Now(),
		TotalExposure: r.TotalExposure,
		Items:         items,
		DAGChainDepth: dagChainDepth,
		PQCSignature:  pqcSig,
	}

	return stig.ExportPOAMToPDF(data, outputPath)
}

// ExporteMASS produces an eMASS-compatible XML file using pkg/emass.
// systemID: the eMASS-assigned system ID ("TBD" if not yet registered).
func (r *Register) ExporteMASS(outputPath, systemID, isso string) error {
	// Import emass inline to avoid import cycle — emass is a leaf package
	type emassItem struct {
		id, controlNum, desc, severity string
		cost                           float64
		due                            time.Time
		milestone                      string
	}

	// Build a simple XML manually using the field layout matching eMASS import
	var sb strings.Builder
	sb.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	sb.WriteString(fmt.Sprintf(`<eMASS version="1.0" exportDate=%q>`, time.Now().Format("01/02/2006")) + "\n")
	sb.WriteString(fmt.Sprintf(`  <systemInformation><systemName>%s</systemName><systemId>%s</systemId><isso>%s</isso></systemInformation>`, r.System, systemID, isso) + "\n")
	sb.WriteString("  <planOfActionAndMilestones>\n")

	for _, item := range r.Items {
		catRoman := severityToCAT(item.Severity)
		relevance := "High"
		if catRoman == "II" {
			relevance = "Moderate"
		} else if catRoman == "III" {
			relevance = "Low"
		}
		milestone := strings.Join(item.MilestoneActions, "; ")

		sb.WriteString("    <poamItem>\n")
		sb.WriteString(fmt.Sprintf("      <poamId>%s</poamId>\n", item.ID))
		sb.WriteString(fmt.Sprintf("      <securityControlNumber>%s</securityControlNumber>\n", item.ControlID))
		sb.WriteString(fmt.Sprintf("      <controlVulnerabilityDescription>%s</controlVulnerabilityDescription>\n", xmlEscape(item.Weakness)))
		sb.WriteString(fmt.Sprintf("      <officeOrg>%s</officeOrg>\n", item.PointOfContact))
		sb.WriteString(fmt.Sprintf("      <resources>$%.0f</resources>\n", item.EstimatedCost))
		sb.WriteString(fmt.Sprintf("      <status>Ongoing</status>\n"))
		sb.WriteString(fmt.Sprintf("      <scheduledCompletionDate>%s</scheduledCompletionDate>\n", item.ScheduledCompletion.Format("01/02/2006")))
		sb.WriteString(fmt.Sprintf("      <milestone>%s</milestone>\n", xmlEscape(milestone)))
		sb.WriteString(fmt.Sprintf("      <rawSeverity>%s</rawSeverity>\n", catRoman))
		sb.WriteString(fmt.Sprintf("      <relevanceOfThreat>%s</relevanceOfThreat>\n", relevance))
		sb.WriteString(fmt.Sprintf("      <likelihood>%s</likelihood>\n", relevance))
		sb.WriteString(fmt.Sprintf("      <impact>%s</impact>\n", relevance))
		sb.WriteString(fmt.Sprintf("      <residualRiskLevel>%s</residualRiskLevel>\n", relevance))
		sb.WriteString("    </poamItem>\n")
	}

	sb.WriteString("  </planOfActionAndMilestones>\n")
	sb.WriteString("</eMASS>\n")

	return os.WriteFile(outputPath, []byte(sb.String()), 0644)
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func severityToCAT(s Severity) string {
	switch s {
	case SeverityCAT1, SeverityCritical, SeverityHigh:
		return "I"
	case SeverityCAT2, SeverityMedium:
		return "II"
	default:
		return "III"
	}
}

func xmlEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	return s
}

// LoadJSON loads a POAM register from a JSON file.
func LoadJSON(path string) (*Register, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("poam: read file: %w", err)
	}
	var reg Register
	if err := json.Unmarshal(data, &reg); err != nil {
		return nil, fmt.Errorf("poam: parse json: %w", err)
	}
	return &reg, nil
}
