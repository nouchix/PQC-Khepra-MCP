package main

import (
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/stig"
)

func poamCmd(args []string) {
	if len(args) < 1 {
		printPOAMUsage()
		return
	}
	switch args[0] {
	case "generate":
		poamGenerateCmd(args[1:])
	case "status":
		poamStatusCmd(args[1:])
	case "export":
		poamExportCmd(args[1:])
	case "update":
		poamUpdateCmd(args[1:])
	default:
		printPOAMUsage()
	}
}

func printPOAMUsage() {
	fmt.Println(`adinkhepra poam - Plan of Action & Milestones (NIST SP 800-171A)

Usage:
  adinkhepra poam generate --scan <results.json> [--output poam.pdf] [--format pdf|csv|json]
  adinkhepra poam status   --poam <poam.json>
  adinkhepra poam export   --poam <poam.json> --format emass|csv|json [--output <file>]
  adinkhepra poam update   --poam <poam.json> --item POAM-2026-001 --status "In Progress"

Commands:
  generate    Generate POAM from scan results (dollar-weighted, priority-sorted)
  status      Display open items, completion dates, and total dollar exposure
  export      Export POAM in eMASS, CSV, or JSON format
  update      Update a POAM item status and attach evidence

Examples:
  # Generate POAM from last scan — outputs PDF by default
  adinkhepra poam generate --scan scan_results.json --output poam_v1.pdf

  # Generate in all formats
  adinkhepra poam generate --scan scan_results.json --format csv --output poam_v1.csv

  # Check dashboard status
  adinkhepra poam status --poam poam_v1.json

  # Export for eMASS upload
  adinkhepra poam export --poam poam_v1.json --format emass --output poam_emass.xml`)
}

func poamGenerateCmd(args []string) {
	fs := flag.NewFlagSet("poam generate", flag.ExitOnError)
	scanFile := fs.String("scan", "", "Scan results JSON file (from adinkhepra compliance scan)")
	output := fs.String("output", "poam.pdf", "Output file path")
	format := fs.String("format", "pdf", "Output format: pdf, csv, json")
	company := fs.String("company", "", "Client company name (for report header)")
	fs.Parse(args)

	fmt.Println("╔══════════════════════════════════════════════════════════════╗")
	fmt.Println("║          KHEPRA PROTOCOL // POAM GENERATOR                  ║")
	fmt.Println("║    Plan of Action & Milestones — NIST SP 800-171A           ║")
	fmt.Println("╚══════════════════════════════════════════════════════════════╝")
	fmt.Println()

	var report *stig.ComprehensiveReport

	if *scanFile != "" {
		// Load from existing scan results JSON
		data, err := os.ReadFile(*scanFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading scan file: %v\n", err)
			os.Exit(1)
		}
		report = &stig.ComprehensiveReport{}
		if err := json.Unmarshal(data, report); err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing scan results: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("[*] Loaded scan results: %s\n", *scanFile)
	} else {
		// Run a fresh scan
		fmt.Println("[*] No scan file provided — running live assessment...")
		v := stig.NewValidator(".")
		var err error
		report, err = v.Validate()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Scan error: %v\n", err)
			os.Exit(1)
		}
	}

	if *company != "" && report.Hostname == "" {
		report.Hostname = *company
	}

	// Display POAM summary
	printPOAMSummary(report)

	// Export in requested format
	switch strings.ToLower(*format) {
	case "csv":
		if err := exportPOAMCSV(report, *output); err != nil {
			fmt.Fprintf(os.Stderr, "CSV export error: %v\n", err)
			os.Exit(1)
		}
	case "json":
		if err := exportPOAMJSON(report, *output); err != nil {
			fmt.Fprintf(os.Stderr, "JSON export error: %v\n", err)
			os.Exit(1)
		}
	default: // pdf
		if err := exportPOAMPDF(report, *output); err != nil {
			fmt.Fprintf(os.Stderr, "PDF export error: %v\n", err)
			os.Exit(1)
		}
	}

	fmt.Printf("\n✓ POAM exported: %s\n", *output)
	fmt.Printf("  Open items:   %d\n", len(report.POAMItems))
	totalExposure := 0.0
	for _, item := range report.POAMItems {
		totalExposure += item.DollarImpact
	}
	fmt.Printf("  Total exposure: $%.0f\n", totalExposure)
}

func printPOAMSummary(report *stig.ComprehensiveReport) {
	if len(report.POAMItems) == 0 {
		fmt.Println("[✓] No open POAM items — system is fully compliant!")
		return
	}

	totalExposure := 0.0
	cat1, cat2, cat3 := 0, 0, 0
	for _, item := range report.POAMItems {
		totalExposure += item.DollarImpact
		switch item.Severity {
		case stig.SeverityCAT1, stig.SeverityCritical:
			cat1++
		case stig.SeverityCAT2, stig.SeverityHigh:
			cat2++
		default:
			cat3++
		}
	}

	fmt.Printf("\n  POAM REGISTER — %s\n", time.Now().Format("2006-01-02"))
	fmt.Println("  ─────────────────────────────────────────────")
	fmt.Printf("  Total open items:    %d\n", len(report.POAMItems))
	fmt.Printf("  CAT I / Critical:    %d  ($%s each)\n", cat1, "150,000")
	fmt.Printf("  CAT II / High:       %d  ($%s each)\n", cat2, "50,000")
	fmt.Printf("  CAT III / Medium:    %d  ($%s each)\n", cat3, "10,000")
	fmt.Printf("  Total $ Exposure:    $%.0f\n", totalExposure)
	fmt.Println()
	fmt.Println("  TOP 5 PRIORITY ITEMS (highest dollar impact per remediation day):")
	fmt.Println("  ─────────────────────────────────────────────")
	limit := 5
	if len(report.POAMItems) < limit {
		limit = len(report.POAMItems)
	}
	for i, item := range report.POAMItems[:limit] {
		fmt.Printf("  %d. [%s] %s — $%.0f / %d days (priority: %.0f)\n",
			i+1, item.Severity, item.ControlID,
			item.DollarImpact, item.EstimatedDays, item.PriorityScore)
	}
	fmt.Println()
}

func exportPOAMCSV(report *stig.ComprehensiveReport, outputPath string) error {
	f, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	// NIST SP 800-171A POAM headers
	headers := []string{
		"POAM ID", "Control ID", "Weakness Description", "Severity",
		"Status", "Point of Contact", "Dollar Impact (USD)",
		"Priority Score", "Estimated Days", "Scheduled Completion",
		"Milestone Actions",
	}
	w.Write(headers)

	for _, item := range report.POAMItems {
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
		w.Write(row)
	}
	return nil
}

func exportPOAMJSON(report *stig.ComprehensiveReport, outputPath string) error {
	type POAMExport struct {
		GeneratedAt  string          `json:"generated_at"`
		System       string          `json:"system"`
		TotalItems   int             `json:"total_items"`
		TotalExposure float64        `json:"total_exposure_usd"`
		Items        []stig.POAMItem `json:"items"`
	}

	totalExposure := 0.0
	for _, item := range report.POAMItems {
		totalExposure += item.DollarImpact
	}

	export := POAMExport{
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		System:        report.Hostname,
		TotalItems:    len(report.POAMItems),
		TotalExposure: totalExposure,
		Items:         report.POAMItems,
	}

	data, err := json.MarshalIndent(export, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(outputPath, data, 0644)
}

// exportPOAMPDF produces a true binary PDF using pkg/stig/ssp_poam_pdf.go.
func exportPOAMPDF(report *stig.ComprehensiveReport, outputPath string) error {
	if !strings.HasSuffix(outputPath, ".pdf") {
		outputPath += ".pdf"
	}

	totalExposure := 0.0
	for _, item := range report.POAMItems {
		totalExposure += item.DollarImpact
	}

	// Map stig.POAMItem slice → stig.POAMExportItem slice
	items := make([]stig.POAMExportItem, 0, len(report.POAMItems))
	for _, item := range report.POAMItems {
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
		System:        report.Hostname,
		GeneratedAt:   time.Now(),
		TotalExposure: totalExposure,
		Items:         items,
	}

	return stig.ExportPOAMToPDF(data, outputPath)
}

func poamStatusCmd(args []string) {
	fs := flag.NewFlagSet("poam status", flag.ExitOnError)
	poamFile := fs.String("poam", "", "POAM JSON file")
	fs.Parse(args)

	if *poamFile == "" {
		fmt.Fprintln(os.Stderr, "Error: --poam required")
		os.Exit(1)
	}

	data, err := os.ReadFile(*poamFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading POAM file: %v\n", err)
		os.Exit(1)
	}

	type POAMExport struct {
		GeneratedAt   string          `json:"generated_at"`
		System        string          `json:"system"`
		TotalItems    int             `json:"total_items"`
		TotalExposure float64         `json:"total_exposure_usd"`
		Items         []stig.POAMItem `json:"items"`
	}

	var export POAMExport
	if err := json.Unmarshal(data, &export); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing POAM file: %v\n", err)
		os.Exit(1)
	}

	open, inProgress, completed := 0, 0, 0
	for _, item := range export.Items {
		switch item.Status {
		case "Open":
			open++
		case "In Progress":
			inProgress++
		case "Completed":
			completed++
		}
	}

	fmt.Printf("\nPOAM STATUS — %s\n", export.System)
	fmt.Println("────────────────────────────────")
	fmt.Printf("Open:        %d\n", open)
	fmt.Printf("In Progress: %d\n", inProgress)
	fmt.Printf("Completed:   %d\n", completed)
	fmt.Printf("Total exposure: $%.0f USD\n", export.TotalExposure)
}

func poamExportCmd(args []string) {
	fs := flag.NewFlagSet("poam export", flag.ExitOnError)
	poamFile := fs.String("poam", "", "POAM JSON file")
	format := fs.String("format", "csv", "Export format: csv, json, emass")
	output := fs.String("output", "", "Output file path")
	fs.Parse(args)

	if *poamFile == "" {
		fmt.Fprintln(os.Stderr, "Error: --poam required")
		os.Exit(1)
	}

	fmt.Printf("[*] Exporting POAM as %s...\n", *format)
	// Re-use generate with the loaded file
	poamGenerateCmd([]string{"--scan", *poamFile, "--format", *format, "--output", *output})
}

func poamUpdateCmd(args []string) {
	fs := flag.NewFlagSet("poam update", flag.ExitOnError)
	poamFile := fs.String("poam", "", "POAM JSON file")
	itemID := fs.String("item", "", "POAM item ID (e.g., POAM-2026-001)")
	status := fs.String("status", "", "New status: Open|In Progress|Completed|Risk Accepted")
	evidence := fs.String("evidence", "", "Evidence file or DAG node ID to attach")
	fs.Parse(args)

	if *poamFile == "" || *itemID == "" || *status == "" {
		fmt.Fprintln(os.Stderr, "Error: --poam, --item, and --status are required")
		os.Exit(1)
	}

	data, err := os.ReadFile(*poamFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading POAM: %v\n", err)
		os.Exit(1)
	}

	type POAMExport struct {
		GeneratedAt   string          `json:"generated_at"`
		System        string          `json:"system"`
		TotalItems    int             `json:"total_items"`
		TotalExposure float64         `json:"total_exposure_usd"`
		Items         []stig.POAMItem `json:"items"`
	}

	var export POAMExport
	if err := json.Unmarshal(data, &export); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing POAM: %v\n", err)
		os.Exit(1)
	}

	updated := false
	for i, item := range export.Items {
		if item.ID == *itemID {
			export.Items[i].Status = *status
			if *status == "Completed" {
				now := time.Now()
				export.Items[i].ClosedAt = &now
			}
			if *evidence != "" {
				export.Items[i].EvidenceRefs = append(export.Items[i].EvidenceRefs, *evidence)
			}
			updated = true
			fmt.Printf("✓ Updated %s → %s\n", *itemID, *status)
			break
		}
	}

	if !updated {
		fmt.Fprintf(os.Stderr, "Item %s not found\n", *itemID)
		os.Exit(1)
	}

	newData, _ := json.MarshalIndent(export, "", "  ")
	os.WriteFile(*poamFile, newData, 0644)
}
