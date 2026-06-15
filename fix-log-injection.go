//go:build ignore
// +build ignore

// fix-log-injection.go: replaces sanitizeLog(x) wrapper approach with %q format verb.
//
// The sanitizeLog() approach is NOT recognized by CodeQL's taint analysis.
// Using %q (Go's quoted-string format) escapes ALL control characters including
// \n and \r at the fmt layer itself — CodeQL recognizes %q as a sanitizing sink.
//
// Run: go run fix-log-injection.go
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Pattern: log.Printf("... %s ...", sanitizeLog(x), ...)
// Replace: log.Printf("... %q ...", x, ...)
// Also handles: r.logger.Printf, log.Printf, logger.Printf etc.

var (
	// Match sanitizeLog(expr) in argument position
	sanitizeLogArg = regexp.MustCompile(`sanitizeLog\(([^)]+)\)`)
	// Match format string %s that should become %q (only where sanitizeLog wraps the arg)
	// We'll do a two-pass: first find lines with sanitizeLog(), then fix %s→%q count
)

func fixFile(path string) (changed bool, err error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	original := string(data)
	lines := strings.Split(original, "\n")
	modified := false

	for i, line := range lines {
		if !sanitizeLogArg.MatchString(line) {
			continue
		}
		// Count how many sanitizeLog() calls are on this line
		matches := sanitizeLogArg.FindAllString(line, -1)
		if len(matches) == 0 {
			continue
		}
		// Replace sanitizeLog(x) → x in arguments
		newLine := sanitizeLogArg.ReplaceAllString(line, "$1")

		// Replace matching %s → %q in the format string portion
		// Strategy: find the format string (first quoted arg), replace %s count times
		newLine = replaceFormatVerbs(newLine, len(matches))

		if newLine != line {
			lines[i] = newLine
			modified = true
		}
	}

	if !modified {
		return false, nil
	}

	result := strings.Join(lines, "\n")
	if err := os.WriteFile(path, []byte(result), 0644); err != nil {
		return false, err
	}
	return true, nil
}

// replaceFormatVerbs replaces up to n occurrences of %s with %q in the format
// string literal within a log/Printf call. It only replaces %s inside the first
// double-quoted string argument.
func replaceFormatVerbs(line string, n int) string {
	// Find first " ... " in line (the format string)
	start := strings.Index(line, `"`)
	if start < 0 {
		return line
	}
	end := strings.Index(line[start+1:], `"`)
	if end < 0 {
		return line
	}
	end = start + 1 + end

	fmtStr := line[start : end+1]
	// Replace %s with %q, up to n times
	replaced := 0
	newFmt := strings.NewReplacer() // dummy
	_ = newFmt
	result := ""
	pos := 0
	for i := 0; i < len(fmtStr)-1; i++ {
		if fmtStr[i] == '%' && fmtStr[i+1] == 's' && replaced < n {
			result += fmtStr[pos:i] + "%q"
			pos = i + 2
			i++
			replaced++
		}
	}
	result += fmtStr[pos:]
	return line[:start] + result + line[end+1:]
}

func main() {
	// Files with log injection alerts
	targets := []string{
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

	for _, rel := range targets {
		changed, err := fixFile(rel)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR %s: %v\n", rel, err)
			continue
		}
		if changed {
			fmt.Printf("FIXED  %s\n", rel)
		} else {
			fmt.Printf("skip   %s (no sanitizeLog calls found)\n", rel)
		}
	}

	// Also scan all .go files for any remaining sanitizeLog calls we missed
	fmt.Println("\nChecking for any remaining sanitizeLog() calls...")
	filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		if strings.Contains(path, "fix-log-injection") {
			return nil
		}
		data, _ := os.ReadFile(path)
		if strings.Contains(string(data), "sanitizeLog(") {
			// Check if it's a call site (not the definition)
			lines := strings.Split(string(data), "\n")
			for i, line := range lines {
				if strings.Contains(line, "sanitizeLog(") && !strings.Contains(line, "func sanitizeLog") {
					fmt.Printf("  REMAINING: %s:%d: %s\n", path, i+1, strings.TrimSpace(line))
				}
			}
		}
		return nil
	})
}
