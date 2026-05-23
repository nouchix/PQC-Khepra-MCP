// Safe command execution - should PASS validation
package executor

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
)

// RunGitCommand executes git commands safely with validated input
func RunGitCommand(ctx context.Context, repoPath string, args []string) (string, error) {
	// ✅ CORRECT: Validate repo path first
	if err := validatePath(repoPath); err != nil {
		return "", fmt.Errorf("invalid repo path: %w", err)
	}

	// ✅ CORRECT: Fixed command with separate arguments (not concatenated)
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = repoPath

	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("git command failed: %w", err)
	}

	return string(output), nil
}

// validatePath ensures the path doesn't contain malicious characters
func validatePath(path string) error {
	// Only allow alphanumeric, slashes, dashes, underscores, dots
	validPath := regexp.MustCompile(`^[a-zA-Z0-9/_.-]+$`)
	if !validPath.MatchString(path) {
		return fmt.Errorf("path contains invalid characters")
	}
	return nil
}

// RunSTIGScan executes a STIG compliance scan with validated parameters
func RunSTIGScan(ctx context.Context, endpoint string) error {
	// ✅ CORRECT: Validate input before using
	if err := validateEndpoint(endpoint); err != nil {
		return err
	}

	// ✅ CORRECT: Use exec.Command with separate arguments
	cmd := exec.CommandContext(ctx, "/usr/bin/stig-scanner", "--endpoint", endpoint, "--format", "json")

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("STIG scan failed: %w", err)
	}

	return nil
}

func validateEndpoint(endpoint string) error {
	// Validate endpoint format
	validEndpoint := regexp.MustCompile(`^[a-zA-Z0-9-]+$`)
	if !validEndpoint.MatchString(endpoint) {
		return fmt.Errorf("invalid endpoint format")
	}
	return nil
}
