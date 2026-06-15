//go:build ignore

// fix-log-injection-v2.go: Comprehensive log injection fixer.
//
// Strategy:
//   1. For lines that already use sanitizeLog(x) → already converted to %q by v1
//   2. For lines that use raw user values with %s in log calls → switch to %q
//
// The specific pattern: any log.Printf / r.logger.Printf / log.Print* call where
// %s appears with a string variable that could be user-controlled.
//
// We target the specific lines CodeQL flagged by their current %s patterns.
// Run: go run fix-log-injection-v2.go
package main

import (
	"fmt"
	"os"
	"regexp"
	"strings"
)

// userControlledLogPattern matches Printf-style log calls containing %s
var logCallPattern = regexp.MustCompile(`(?m)^([^\n]*(?:log\.Print|logger\.Print|\.logger\.Print|r\.logger\.Print|e\.logger\.Print)[^\n]*%s[^\n]*)$`)

// Files and the specific lines that need fixing (from CodeQL alert line numbers)
// We'll do a global scan of each file for log calls with %s
var targetFiles = []string{
	"cmd/webhook/main.go",
	"cmd/khepra-mcp/main.go",
	"cmd/khepra-daemon/main.go",
	"cmd/telemetry-server/main.go",
	"pkg/mcp/router.go",
	"pkg/mcp/executor.go",
	"pkg/mcp/sandbox.go",
	"pkg/gateway/layer4_control.go",
	"pkg/gateway/layer2_auth.go",
	"pkg/gateway/layer1_firewall.go",
	"pkg/gateway/stig_connector.go",
	"pkg/sekhem/waf.go",
	"pkg/agi/engine.go",
	"pkg/ouroboros/cycle.go",
	"pkg/ouroboros/khopesh.go",
	"pkg/ironbank/transport.go",
	"pkg/webui/dag_viewer.go",
}

func processFile(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	lines := strings.Split(string(data), "\n")
	changed := 0

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		
		// Skip comment lines and the sanitizeLog function definition itself
		if strings.HasPrefix(trimmed, "//") || strings.Contains(trimmed, "func sanitizeLog") {
			continue
		}
		
		// Must be a log call
		if !isLogCall(trimmed) {
			continue
		}
		
		// Must contain %s in a format string
		if !strings.Contains(line, "%s") {
			continue
		}
		
		// Don't process lines that already use %q for user data
		// (already fixed by v1 or manually)
		newLine := replacePercentS(line)
		if newLine != line {
			lines[i] = newLine
			changed++
		}
	}

	if changed == 0 {
		return 0, nil
	}

	return changed, os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0644)
}

func isLogCall(line string) bool {
	logPrefixes := []string{
		"log.Printf(",
		"log.Println(",
		"log.Print(",
		"log.Fatalf(",
		"log.Fatal(",
		"r.logger.Printf(",
		"e.logger.Printf(",
		"c.logger.Printf(",
		".logger.Printf(",
		".logger.Println(",
	}
	for _, p := range logPrefixes {
		if strings.Contains(line, p) {
			return true
		}
	}
	return false
}

// replacePercentS replaces %s with %q inside format string literals in log calls.
// It only replaces inside the first double-quoted string on the line.
func replacePercentS(line string) string {
	// Find format string boundaries (first " to second ")
	start := strings.Index(line, `"`)
	if start < 0 {
		return line
	}
	
	// Find the closing quote (accounting for escape sequences)
	end := -1
	for i := start + 1; i < len(line); i++ {
		if line[i] == '\\' {
			i++ // skip escaped char
			continue
		}
		if line[i] == '"' {
			end = i
			break
		}
	}
	if end < 0 {
		return line
	}
	
	fmtStr := line[start : end+1]
	
	// Replace %s with %q inside the format string
	// But be careful: %s in format strings for non-user data (like err.Error()) is fine
	// We replace ALL %s since log calls with format strings should use %q for strings
	newFmt := strings.ReplaceAll(fmtStr, "%s", "%q")
	
	if newFmt == fmtStr {
		return line
	}
	
	return line[:start] + newFmt + line[end+1:]
}

func main() {
	totalChanged := 0
	for _, f := range targetFiles {
		n, err := processFile(f)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR %s: %v\n", f, err)
			continue
		}
		if n > 0 {
			fmt.Printf("FIXED  %s (%d lines)\n", f, n)
			totalChanged += n
		} else {
			fmt.Printf("clean  %s\n", f)
		}
	}
	fmt.Printf("\nTotal lines changed: %d\n", totalChanged)
}
