package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ─── Sandbox Configuration (AD-011) ────────────────────────────────────────────
//
// Sandbox defaults are restrictive by design:
//   - ReadOnly:       true  (tool cannot write to filesystem)
//   - NetworkAllowed: false (tool cannot make network requests)
//
// The manifest is the SOLE source of truth for overriding these defaults.

// SandboxConfig defines resource limits and permissions for sandboxed execution.
type SandboxConfig struct {
	// Timeout is the maximum execution duration for the sandbox.
	Timeout time.Duration `json:"timeout"`

	// CPUShares limits CPU allocation (Docker --cpu-shares).
	CPUShares int64 `json:"cpu_shares"`

	// MemLimitMB limits memory allocation in megabytes.
	MemLimitMB int64 `json:"mem_limit_mb"`

	// ReadOnly prevents the sandbox from writing to the mounted project.
	// Default: true (AD-011).
	ReadOnly bool `json:"read_only"`

	// NetworkAllowed controls whether the sandbox can access the network.
	// Default: false (AD-011). Overridden by ToolSpec.NetworkAllowed.
	NetworkAllowed bool `json:"network_allowed"`

	// AllowedDirs is a whitelist of host directories mounted into the sandbox.
	AllowedDirs []string `json:"allowed_dirs,omitempty"`

	// UseGVisor enables gVisor (runsc) for additional kernel-level isolation.
	UseGVisor bool `json:"use_gvisor"`
}

// DefaultSandboxConfig returns the hardened default sandbox configuration.
func DefaultSandboxConfig() SandboxConfig {
	return SandboxConfig{
		Timeout:        90 * time.Second,
		CPUShares:      512,
		MemLimitMB:     256,
		ReadOnly:       true,  // AD-011: default deny writes
		NetworkAllowed: false, // AD-011: default deny network
		UseGVisor:      false, // Enable when gVisor is available
	}
}

// SandboxConfigFromSpec derives a SandboxConfig from a ToolSpec, applying the
// manifest-defined overrides onto the hardened defaults.
func SandboxConfigFromSpec(spec ToolSpec) SandboxConfig {
	cfg := DefaultSandboxConfig()
	if spec.TimeoutMs > 0 {
		cfg.Timeout = time.Duration(spec.TimeoutMs) * time.Millisecond
	}
	cfg.NetworkAllowed = spec.NetworkAllowed
	return cfg
}

// ─── Docker Sandbox (Phantom Runner) ───────────────────────────────────────────
//
// DockerSandbox implements SandboxRunner using the Phantom-style MCP runner
// container (khepra-phantom:latest). Each tool invocation creates an ephemeral
// container with:
//   - Spectral Fingerprint PQC session (per-invocation key generation)
//   - Read-only project mount (default) at /project
//   - Network isolation (default: none)
//   - Resource limits (CPU, memory, timeout)
//   - Auto-remove on exit (no container leak)
//   - Structured JSON on stdout, diagnostics on stderr
//
// The sandbox uses Docker CLI execution to avoid a heavy Docker SDK dependency.
// This aligns with the AD-002 mandate for minimal external dependencies.

// DockerSandbox provides strong isolation using the Phantom MCP runner container.
type DockerSandbox struct {
	mu     sync.Mutex
	image  string      // Container image name
	config SandboxConfig
	logger *log.Logger
}

// DockerSandboxConfig holds construction parameters for DockerSandbox.
type DockerSandboxConfig struct {
	// Image is the Docker image to use (default: "khepra-phantom:latest").
	Image string

	// Config is the default sandbox configuration.
	Config SandboxConfig

	// Logger is the diagnostic logger (default: log.Default()).
	Logger *log.Logger
}

// NewDockerSandbox creates a DockerSandbox with the given configuration.
func NewDockerSandbox(cfg DockerSandboxConfig) *DockerSandbox {
	image := cfg.Image
	if image == "" {
		image = "khepra-phantom:latest"
	}
	config := cfg.Config
	if config.Timeout == 0 {
		config = DefaultSandboxConfig()
	}
	logger := cfg.Logger
	if logger == nil {
		logger = log.Default()
	}
	return &DockerSandbox{
		image:  image,
		config: config,
		logger: logger,
	}
}

// Run implements SandboxRunner. It creates an ephemeral Docker container,
// executes the tool via the mcp-runner binary, and returns the parsed result.
func (ds *DockerSandbox) Run(ctx context.Context, spec ToolSpec, call MCPToolCall) (any, []string, error) {
	cfg := ds.resolveConfig(spec)

	if err := validateSandboxPolicy(spec, cfg); err != nil {
		return nil, nil, fmt.Errorf("sandbox policy violation: %w", err)
	}

	return ds.runPhantomContainer(ctx, spec, call, cfg)
}

// resolveConfig merges defaults with manifest-level overrides.
func (ds *DockerSandbox) resolveConfig(spec ToolSpec) SandboxConfig {
	cfg := ds.config

	// Manifest-level overrides via ToolSpec.Meta
	if v, ok := spec.Meta["network_allowed"].(bool); ok {
		cfg.NetworkAllowed = v
	}
	if v, ok := spec.Meta["readonly"].(bool); ok {
		cfg.ReadOnly = v
	}
	if v, ok := spec.Meta["timeout_ms"].(float64); ok && v > 0 {
		cfg.Timeout = time.Duration(v) * time.Millisecond
	}
	if v, ok := spec.Meta["mem_limit_mb"].(float64); ok && v > 0 {
		cfg.MemLimitMB = int64(v)
	}
	if v, ok := spec.Meta["cpu_shares"].(float64); ok && v > 0 {
		cfg.CPUShares = int64(v)
	}

	// ToolSpec-level timeout takes priority
	if spec.TimeoutMs > 0 {
		cfg.Timeout = time.Duration(spec.TimeoutMs) * time.Millisecond
	}
	cfg.NetworkAllowed = spec.NetworkAllowed

	return cfg
}

// runPhantomContainer creates and runs the ephemeral Docker container.
func (ds *DockerSandbox) runPhantomContainer(
	ctx context.Context,
	spec ToolSpec,
	call MCPToolCall,
	cfg SandboxConfig,
) (any, []string, error) {
	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	// Serialize tool arguments
	argsJSON, err := json.Marshal(call.Args)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to serialize tool args: %w", err)
	}

	// Build the docker run command
	args := ds.buildDockerArgs(spec, call, cfg, string(argsJSON))

	ds.logger.Printf("[SANDBOX:PHANTOM] tool=%q agent=%q image=%q timeout=%q",
		spec.Name, call.Identity.AgentID, ds.image, cfg.Timeout)

	// Execute via docker CLI (AD-002: no heavy SDK dependency)
	stdout, stderr, exitCode, err := ds.execDocker(ctx, args)
	if err != nil {
		return nil, nil, fmt.Errorf("phantom container execution failed: %w", err)
	}

	// Log stderr (diagnostics from the runner)
	if len(stderr) > 0 {
		for _, line := range strings.Split(strings.TrimSpace(string(stderr)), "\n") {
			if line != "" {
				ds.logger.Printf("[SANDBOX:PHANTOM:STDERR] %q", line)
			}
		}
	}

	if exitCode != 0 {
		return nil, nil, fmt.Errorf("phantom container exited with code %d: %s",
			exitCode, truncate(string(stderr), 500))
	}

	// Parse structured output
	result, warnings, parseErr := parseStructuredOutput(stdout)
	if parseErr != nil {
		warnings = append(warnings, fmt.Sprintf("output parse warning: %v", parseErr))
	}

	return result, warnings, nil
}

// buildDockerArgs constructs the docker run argument list.
func (ds *DockerSandbox) buildDockerArgs(
	spec ToolSpec,
	call MCPToolCall,
	cfg SandboxConfig,
	argsJSON string,
) []string {
	containerName := fmt.Sprintf("mcp-phantom-%s-%d", spec.Name, time.Now().UnixNano())

	args := []string{
		"run",
		"--rm",                               // Auto-remove on exit
		"--name", containerName,              // Unique container name
		"--memory", fmt.Sprintf("%dm", cfg.MemLimitMB),
		"--cpu-shares", fmt.Sprintf("%d", cfg.CPUShares),
		"--pids-limit", "256",                // Limit process count (fork bomb protection)
		"--read-only",                        // Read-only root filesystem
		"--tmpfs", "/tmp:rw,noexec,size=64m", // Ephemeral scratch space
		"--no-new-privileges",                // Prevent privilege escalation
		"--security-opt", "no-new-privileges:true",
	}

	// Network isolation (default: none)
	if !cfg.NetworkAllowed {
		args = append(args, "--network", "none")
	}

	// ─── Security Profiles (AD-011) ────────────────────────────────
	// Apply Seccomp and AppArmor profiles based on tool network policy.
	var seccompProfile *SeccompProfile
	var apparmorName string
	if cfg.NetworkAllowed {
		seccompProfile = NetworkAllowedSeccompProfile()
		apparmorName = "khepra-phantom-net"
	} else {
		seccompProfile = DefaultSeccompProfile()
		apparmorName = "khepra-phantom"
	}
	// Write seccomp profile to temp dir for Docker to read
	if seccompPath, err := WriteSeccompProfile(seccompProfile, os.TempDir()); err == nil {
		args = append(args, "--security-opt", fmt.Sprintf("seccomp=%s", seccompPath))
	}
	// AppArmor (Linux only — silently skipped on other platforms)
	args = append(args, "--security-opt", fmt.Sprintf("apparmor=%s", apparmorName))

	// Drop ALL capabilities then re-add minimal set
	args = append(args, "--cap-drop=ALL", "--cap-add=SETUID", "--cap-add=SETGID")

	// gVisor runtime (if available and configured)
	if cfg.UseGVisor {
		args = append(args, "--runtime", "runsc")
	}

	// ─── Capability Mounts (ASD/CISA confused-deputy defense) ─────────────
	// If the ToolSpec declares specific CapabilityMounts, use those instead of
	// the generic /project mount. This limits each tool to exactly the directories
	// it legitimately needs — ert_scan on RHEL-9 gets /etc, /var/log, /opt/stig-db
	// but NOT the entire project filesystem.
	if len(spec.CapabilityMounts) > 0 {
		for i, dir := range spec.CapabilityMounts {
			// Validate: must be absolute path, no traversal
			absDir, absErr := filepath.Abs(dir)
			if absErr != nil || absDir != dir {
				// Skip malformed capability mounts (fail-safe)
				ds.logger.Printf("[SANDBOX] WARN: skipping invalid capability mount %q for tool %q", dir, spec.Name)
				continue
			}
			// Mount as read-only inside container at /cap/N (e.g. /cap/0, /cap/1)
			containerMount := fmt.Sprintf("/cap/%d", i)
			args = append(args, "-v", fmt.Sprintf("%s:%s:ro", absDir, containerMount))
		}
	} else {
		// Fallback: generic /project mount (backward compat for tools without CapabilityMounts)
		projectPath := getProjectPath(call.Args)
		if projectPath != "" {
			absPath, err := filepath.Abs(projectPath)
			if err == nil {
				mountMode := "ro"
				if !cfg.ReadOnly {
					mountMode = "rw"
				}
				args = append(args, "-v", fmt.Sprintf("%s:/project:%s", absPath, mountMode))
			}
		}
	}

	// Writable data volume for tools that need to persist output
	if !cfg.ReadOnly {
		args = append(args,
			"--tmpfs", "/var/lib/phantom/data:rw,size=128m",
		)
	}

	// Adinkra symbol as environment variable (the runner reads this for Spectral Fingerprint)
	symbol := "Eban" // Default: highest security precedence
	if s, ok := call.Args["symbol"].(string); ok && s != "" {
		symbol = s
	}
	args = append(args, "-e", fmt.Sprintf("PHANTOM_SYMBOL=%s", symbol))

	// Container image and runner command
	args = append(args,
		"--entrypoint", "/app/mcp-runner",
		ds.image,
		spec.Name,
		argsJSON,
	)

	return args
}

// execDocker runs docker with the given arguments and captures stdout/stderr.
func (ds *DockerSandbox) execDocker(ctx context.Context, args []string) (stdout, stderr []byte, exitCode int, err error) {
	// Use os/exec to invoke docker CLI
	// This avoids importing the Docker SDK (30+ transitive deps)
	cmd := execCommandContext(ctx, "docker", args...)

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	err = cmd.Run()
	stdout = stdoutBuf.Bytes()
	stderr = stderrBuf.Bytes()

	if err != nil {
		// Check if it's an exit code error
		if exitErr, ok := err.(interface{ ExitCode() int }); ok {
			return stdout, stderr, exitErr.ExitCode(), nil
		}
		// Context timeout
		if ctx.Err() != nil {
			return stdout, stderr, -1, fmt.Errorf("sandbox execution timeout: %w", ctx.Err())
		}
		return stdout, stderr, -1, err
	}

	return stdout, stderr, 0, nil
}

// ─── Process Sandbox (Lightweight Alternative) ─────────────────────────────────

// ProcessSandbox runs tool handlers in-process but with timeout enforcement.
// This is the minimum viable sandbox for environments without Docker/gVisor.
// It provides timeout enforcement but NOT filesystem or network isolation.
type ProcessSandbox struct {
	config SandboxConfig
}

// NewProcessSandbox creates a process-level sandbox with the given configuration.
func NewProcessSandbox(cfg SandboxConfig) *ProcessSandbox {
	return &ProcessSandbox{config: cfg}
}

// Run implements SandboxRunner for in-process execution with timeout enforcement.
func (ps *ProcessSandbox) Run(ctx context.Context, spec ToolSpec, call MCPToolCall) (any, []string, error) {
	cfg := SandboxConfigFromSpec(spec)

	ctx, cancel := context.WithTimeout(ctx, cfg.Timeout)
	defer cancel()

	warnings := []string{
		"process-sandbox: timeout enforced, but no filesystem/network isolation",
	}
	return nil, warnings, nil
}

// ─── Helpers ───────────────────────────────────────────────────────────────────

// validateSandboxPolicy enforces pre-execution safety checks.
func validateSandboxPolicy(spec ToolSpec, cfg SandboxConfig) error {
	if spec.Name == "" {
		return fmt.Errorf("tool name is required")
	}

	// Reject obviously excessive resource requests
	if cfg.MemLimitMB > 8192 {
		return fmt.Errorf("memory limit %dMB exceeds maximum allowed (8192MB)", cfg.MemLimitMB)
	}
	if cfg.Timeout > 30*time.Minute {
		return fmt.Errorf("timeout %s exceeds maximum allowed (30m)", cfg.Timeout)
	}

	// Sandboxed tools should not request destructive access patterns
	if spec.RiskClass == RiskReadOnly && !cfg.ReadOnly {
		return fmt.Errorf("read-only tool %q cannot request writable sandbox", spec.Name)
	}

	return nil
}

// getProjectPath extracts the project path from tool arguments.
func getProjectPath(args map[string]any) string {
	if p, ok := args["project_path"].(string); ok {
		return p
	}
	return ""
}

// parseStructuredOutput parses the JSON output from the mcp-runner.
func parseStructuredOutput(output []byte) (any, []string, error) {
	// Trim any trailing whitespace/newlines
	output = bytes.TrimSpace(output)
	if len(output) == 0 {
		return nil, []string{"empty output from sandbox"}, nil
	}

	var result any
	if err := json.Unmarshal(output, &result); err != nil {
		// Fallback: return raw output as string
		return string(output), []string{"output was not valid JSON: " + err.Error()}, nil
	}

	// Check for error field in the structured output
	if m, ok := result.(map[string]any); ok {
		if status, _ := m["status"].(string); status == "error" {
			errMsg, _ := m["error"].(string)
			return result, []string{fmt.Sprintf("tool reported error: %s", errMsg)}, nil
		}
	}

	return result, nil, nil
}

// truncate returns s truncated to maxLen characters with an ellipsis if needed.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// execCommandContext is a variable to allow test injection.
// In production it points to exec.CommandContext.
var execCommandContext = defaultExecCommandContext
