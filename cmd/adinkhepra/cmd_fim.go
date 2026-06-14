package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/fim"
)

func fimCmd(args []string) {
	if len(args) < 1 {
		printFIMUsage()
		return
	}

	switch args[0] {
	case "init":
		fimInitCmd(args[1:])
	case "watch":
		fimWatchCmd(args[1:])
	case "verify":
		fimVerifyCmd(args[1:])
	case "export":
		fimExportCmd(args[1:])
	case "import":
		fimImportCmd(args[1:])
	default:
		printFIMUsage()
	}
}

func printFIMUsage() {
	fmt.Println(`adinkhepra fim - File Integrity Monitoring

Usage:
  adinkhepra fim init [-out baseline.json] [-paths file1,file2,...]
  adinkhepra fim watch --baseline baseline.json [--alert-on CRITICAL]
  adinkhepra fim verify --baseline baseline.json --path /etc/shadow
  adinkhepra fim export --baseline baseline.json --out exported.json
  adinkhepra fim import --baseline baseline.json

Commands:
  init     Initialize FIM baseline (hash critical files)
  watch    Monitor files for unauthorized changes (real-time)
  verify   Check if a specific file matches baseline
  export   Export baseline to JSON
  import   Import baseline from JSON

Examples:
  # Initialize baseline with default paths
  adinkhepra fim init

  # Initialize with custom paths
  adinkhepra fim init -paths /etc/passwd,/etc/shadow,/var/log/secure

  # Start real-time monitoring
  adinkhepra fim watch --baseline baseline.json --alert-on CRITICAL

  # Verify specific file
  adinkhepra fim verify --baseline baseline.json --path /etc/shadow`)
}

func fimInitCmd(args []string) {
	fs := flag.NewFlagSet("fim init", flag.ExitOnError)
	out := fs.String("out", "fim_baseline.json", "Output baseline file")
	pathsFlag := fs.String("paths", "", "Comma-separated list of paths (overrides defaults)")
	fs.Parse(args)

	var criticalPaths []string
	if *pathsFlag != "" {
		// Parse custom paths
		fmt.Printf("[FIM] Using custom paths: %s\n", *pathsFlag)
		criticalPaths = parsePaths(*pathsFlag)
	} else {
		// Use defaults based on OS
		if runtime.GOOS == "windows" {
			criticalPaths = fim.DefaultCriticalPathsWindows
		} else {
			criticalPaths = fim.DefaultCriticalPathsLinux
		}
		fmt.Printf("[FIM] Using default paths for OS: %s\n", runtime.GOOS)
	}

	fmt.Println("[FIM] Initializing baseline...")
	watcher, err := fim.NewFIMWatcher(criticalPaths)
	if err != nil {
		fatal("failed to create FIM watcher", err)
	}

	if err := watcher.EstablishBaseline(); err != nil {
		fatal("failed to establish baseline", err)
	}

	// Export baseline using existing method
	if err := watcher.ExportBaseline(*out); err != nil {
		fatal("failed to export baseline", err)
	}

	fmt.Printf("\n[SUCCESS] Baseline established.\n")
	fmt.Printf("   - Files monitored: %d\n", len(criticalPaths))
	fmt.Printf("   - Output: %s\n", *out)
	fmt.Println("\n[NEXT] Start monitoring:")
	fmt.Printf("       adinkhepra fim watch --baseline %s\n", *out)
}

func fimWatchCmd(args []string) {
	fs := flag.NewFlagSet("fim watch", flag.ExitOnError)
	baselinePath := fs.String("baseline", "", "Baseline JSON file (required)")
	alertOn := fs.String("alert-on", "CRITICAL", "Minimum severity to alert on (CRITICAL, HIGH, MEDIUM, LOW)")
	fs.Parse(args)

	if *baselinePath == "" {
		fmt.Println("Error: --baseline is required")
		printFIMUsage()
		return
	}

	// Load baseline to determine paths
	data, err := os.ReadFile(*baselinePath)
	if err != nil {
		fatal("failed to read baseline", err)
	}

	var baseline fim.Baseline
	if err := json.Unmarshal(data, &baseline); err != nil {
		fatal("failed to parse baseline", err)
	}

	// Create watcher with paths from baseline
	paths := make([]string, 0, len(baseline.Hashes))
	for path := range baseline.Hashes {
		paths = append(paths, path)
	}

	watcher, err := fim.NewFIMWatcher(paths)
	if err != nil {
		fatal("failed to create watcher", err)
	}

	// Import baseline using existing method
	if err := watcher.ImportBaseline(*baselinePath); err != nil {
		fatal("failed to import baseline", err)
	}

	fmt.Printf("[FIM] Starting real-time monitoring...\n")
	fmt.Printf("   - Monitored files: %d\n", len(paths))
	fmt.Printf("   - Alert threshold: %s\n", *alertOn)
	fmt.Println("\n[PRESS CTRL+C TO STOP]")

	// Start watching
	watcher.Start() // Returns no error

	// Listen for events
	go func() {
		for event := range watcher.Events() {
			if shouldAlert(event.Severity, *alertOn) {
				printAlert(event)
			}
		}
	}()

	// Block forever
	select {}
}

func fimVerifyCmd(args []string) {
	fs := flag.NewFlagSet("fim verify", flag.ExitOnError)
	baselinePath := fs.String("baseline", "", "Baseline JSON file (required)")
	filePath := fs.String("path", "", "File to verify (required)")
	fs.Parse(args)

	if *baselinePath == "" || *filePath == "" {
		fmt.Println("Error: --baseline and --path are required")
		printFIMUsage()
		return
	}

	// Load baseline
	data, err := os.ReadFile(*baselinePath)
	if err != nil {
		fatal("failed to read baseline", err)
	}

	var baseline fim.Baseline
	if err := json.Unmarshal(data, &baseline); err != nil {
		fatal("failed to parse baseline", err)
	}

	// Get expected hash
	expectedHash, exists := baseline.Hashes[*filePath]
	if !exists {
		fmt.Printf("[WARN] File not in baseline: %s\n", *filePath)
		os.Exit(1)
	}

	// Compute current hash
	actualHash, err := fim.ComputeSHA256(*filePath)
	if err != nil {
		fatal("failed to compute hash", err)
	}

	// Compare
	if expectedHash == actualHash {
		fmt.Printf("[✓] MATCH: %s\n", *filePath)
		fmt.Printf("   Expected: %s\n", expectedHash)
		fmt.Printf("   Actual  : %s\n", actualHash)
	} else {
		fmt.Printf("[✗] MISMATCH: %s\n", *filePath)
		fmt.Printf("   Expected: %s\n", expectedHash)
		fmt.Printf("   Actual  : %s\n", actualHash)
		fmt.Println("\n[ALERT] FILE INTEGRITY VIOLATION DETECTED!")
		os.Exit(1)
	}
}

func fimExportCmd(args []string) {
	fs := flag.NewFlagSet("fim export", flag.ExitOnError)
	baselinePath := fs.String("baseline", "", "Baseline to export (required)")
	out := fs.String("out", "fim_baseline_export.json", "Output file")
	fs.Parse(args)

	if *baselinePath == "" {
		fmt.Println("Error: --baseline is required")
		printFIMUsage()
		return
	}

	// Just copy the file (it's already JSON)
	data, err := os.ReadFile(*baselinePath)
	if err != nil {
		fatal("failed to read baseline", err)
	}

	if err := os.WriteFile(*out, data, 0644); err != nil {
		fatal("failed to write export", err)
	}

	fmt.Printf("[SUCCESS] Baseline exported to: %s\n", *out)
}

func fimImportCmd(args []string) {
	fs := flag.NewFlagSet("fim import", flag.ExitOnError)
	baselinePath := fs.String("baseline", "", "Baseline JSON to import (required)")
	fs.Parse(args)

	if *baselinePath == "" {
		fmt.Println("Error: --baseline is required")
		printFIMUsage()
		return
	}

	data, err := os.ReadFile(*baselinePath)
	if err != nil {
		fatal("failed to read baseline", err)
	}

	var baseline fim.Baseline
	if err := json.Unmarshal(data, &baseline); err != nil {
		fatal("failed to parse baseline", err)
	}

	fmt.Printf("[SUCCESS] Baseline imported.\n")
	fmt.Printf("   - Files: %d\n", len(baseline.Hashes))
	fmt.Printf("   - Created: %s\n", baseline.CreatedAt.Format("2006-01-02 15:04:05"))
}

// Helper functions
func parsePaths(pathsStr string) []string {
	// Simple comma-separated parser
	paths := []string{}
	current := ""
	for _, ch := range pathsStr {
		if ch == ',' {
			if current != "" {
				paths = append(paths, current)
				current = ""
			}
		} else {
			current += string(ch)
		}
	}
	if current != "" {
		paths = append(paths, current)
	}
	return paths
}

func shouldAlert(severity, threshold string) bool {
	severityLevels := map[string]int{
		"LOW":      1,
		"MEDIUM":   2,
		"HIGH":     3,
		"CRITICAL": 4,
	}

	return severityLevels[severity] >= severityLevels[threshold]
}

func printAlert(event fim.FIMEvent) {
	fmt.Printf("\n[ALERT] %s - %s\n", event.Severity, event.EventType)
	fmt.Printf("   File: %s\n", event.FilePath)
	fmt.Printf("   Time: %s\n", event.Timestamp.Format("2006-01-02 15:04:05"))
	if event.STIGControl != "" {
		fmt.Printf("   STIG: %s\n", event.STIGControl)
	}
	fmt.Printf("   Desc: %s\n", event.Description)
	if event.ExpectedHash != "" {
		fmt.Printf("   Expected Hash: %s\n", event.ExpectedHash)
		fmt.Printf("   Actual Hash  : %s\n", event.ActualHash)
	}
	fmt.Println()
}
