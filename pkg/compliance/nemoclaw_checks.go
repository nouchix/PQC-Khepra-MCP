package compliance

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// =============================================================================
// NVIDIA NEMOCLAW / OPENSHELL COMPLIANCE CHECKS
//
// ASAF audit controls for NemoClaw deployments. NemoClaw enforces security
// across four OpenShell policy domains:
//
//   1. Filesystem  — restricts reads/writes to /sandbox and /tmp (locked)
//   2. Network     — declarative egress allowlist; blocks unauthorized outbound (hot-reload)
//   3. Process     — blocks privilege escalation and dangerous syscalls (locked)
//   4. Inference   — routes model API calls to controlled providers (hot-reload)
//
// Because NemoClaw is alpha software (as of March 2026), these checks are
// especially valuable: ADINKHEPRA certification provides the independent
// attestation that enterprise CISOs need before approving production workloads.
//
// Reference: https://docs.nvidia.com/nemoclaw/latest/
// =============================================================================

// NemoClawAuditResult captures the outcome of a single NemoClaw compliance check.
type NemoClawAuditResult struct {
	CheckID     string
	Domain      string // "filesystem" | "network" | "process" | "inference" | "credentials"
	Title       string
	Status      CheckStatus
	Detail      string
	Remediation string
}

// NemoClawAuditReport is the full compliance report for one NemoClaw deployment.
type NemoClawAuditReport struct {
	ConfigDir string
	Results   []NemoClawAuditResult
	PassCount int
	FailCount int
	Score     float64 // 0.0–1.0
}

// AuditNemoClawDeployment runs all NemoClaw compliance checks against the given
// config directory and returns a structured report ready for ADINKHEPRA signing.
func AuditNemoClawDeployment(configDir string) (*NemoClawAuditReport, error) {
	report := &NemoClawAuditReport{ConfigDir: configDir}

	checks := []func(string) NemoClawAuditResult{
		checkNemoClawBlueprintPresent,
		checkOpenShellPolicyPresent,
		checkFilesystemPolicyRestrictive,
		checkNetworkPolicyNoWildcard,
		checkProcessPolicyHardeningEnabled,
		checkInferencePolicyConfigured,
		checkNvidiaAPIKeyNotPlaintext,
		checkSandboxPathIsolation,
		checkHotReloadNetworkOnly,
	}

	for _, check := range checks {
		result := check(configDir)
		report.Results = append(report.Results, result)
		if result.Status == StatusPass {
			report.PassCount++
		} else {
			report.FailCount++
		}
	}

	total := report.PassCount + report.FailCount
	if total > 0 {
		report.Score = float64(report.PassCount) / float64(total)
	}

	return report, nil
}

// ─── Individual Checks ────────────────────────────────────────────────────────

// checkNemoClawBlueprintPresent verifies that blueprint.yaml is present.
// blueprint.yaml defines the inference profiles and sandbox parameters for the
// NemoClaw deployment. Its absence means the stack may be partially installed.
func checkNemoClawBlueprintPresent(dir string) NemoClawAuditResult {
	r := NemoClawAuditResult{
		CheckID: "NMC-001",
		Domain:  "inference",
		Title:   "NemoClaw blueprint.yaml present",
	}
	bpPath := filepath.Join(dir, "blueprint.yaml")
	info, err := os.Stat(bpPath)
	if err != nil || info.Size() == 0 {
		r.Status = StatusFail
		r.Detail = fmt.Sprintf("blueprint.yaml not found or empty at %s", bpPath)
		r.Remediation = "Run `nemoclaw onboard` to generate blueprint.yaml with inference profiles."
		return r
	}
	r.Status = StatusPass
	r.Detail = fmt.Sprintf("blueprint.yaml present (%d bytes)", info.Size())
	return r
}

// checkOpenShellPolicyPresent verifies that at least one OpenShell policy YAML
// file exists. A missing policy means OpenShell is not actively governing the sandbox.
func checkOpenShellPolicyPresent(dir string) NemoClawAuditResult {
	r := NemoClawAuditResult{
		CheckID: "NMC-002",
		Domain:  "filesystem",
		Title:   "OpenShell sandbox policy file present",
	}
	candidates := []string{"policy.yaml", "openshell-policy.yaml", "sandbox-policy.yaml"}
	for _, name := range candidates {
		path := filepath.Join(dir, name)
		if info, err := os.Stat(path); err == nil && info.Size() > 0 {
			r.Status = StatusPass
			r.Detail = fmt.Sprintf("Policy file found: %s (%d bytes)", path, info.Size())
			return r
		}
	}
	r.Status = StatusFail
	r.Detail = "No OpenShell policy file found in " + dir
	r.Remediation = "Run `openshell sandbox create --from openclaw` to generate a baseline policy."
	return r
}

// checkFilesystemPolicyRestrictive verifies the policy allows only /sandbox and
// /tmp — the two paths NemoClaw permits by default. A broader allow list risks
// agent access to host credentials and config files.
func checkFilesystemPolicyRestrictive(dir string) NemoClawAuditResult {
	r := NemoClawAuditResult{
		CheckID: "NMC-003",
		Domain:  "filesystem",
		Title:   "Filesystem policy restricted to /sandbox and /tmp",
	}
	content, err := readFirstPolicyFile(dir)
	if err != nil {
		r.Status = StatusError
		r.Detail = "Could not read policy file: " + err.Error()
		return r
	}

	dangerousPaths := []string{"/etc", "/home", "/root", "/var", "/usr", "/proc", "/sys"}
	for _, p := range dangerousPaths {
		if strings.Contains(content, p) {
			r.Status = StatusFail
			r.Detail = fmt.Sprintf("Policy file references potentially dangerous path: %s", p)
			r.Remediation = "Restrict filesystem allow list to /sandbox and /tmp only."
			return r
		}
	}

	// Check that at least /sandbox is mentioned.
	if !strings.Contains(content, "/sandbox") {
		r.Status = StatusFail
		r.Detail = "Policy file does not reference /sandbox — sandbox path isolation may be inactive."
		r.Remediation = "Ensure filesystem policy includes 'allow: [\"/sandbox\", \"/tmp\"]'."
		return r
	}

	r.Status = StatusPass
	r.Detail = "Filesystem policy appears restricted to /sandbox and /tmp."
	return r
}

// checkNetworkPolicyNoWildcard verifies that the network policy does not contain
// wildcard allow-all rules (e.g. "allow: *" or "destinations: ['*']"). A wildcard
// network policy defeats the purpose of OpenShell's egress control.
func checkNetworkPolicyNoWildcard(dir string) NemoClawAuditResult {
	r := NemoClawAuditResult{
		CheckID: "NMC-004",
		Domain:  "network",
		Title:   "Network egress policy has no wildcard allow-all rule",
	}
	content, err := readFirstPolicyFile(dir)
	if err != nil {
		r.Status = StatusError
		r.Detail = "Could not read policy file: " + err.Error()
		return r
	}

	wildcardPatterns := []string{"allow: \"*\"", "allow: '*'", "destinations: [\"*\"]",
		"destinations: ['*']", "allow_all: true", "egress: allow"}
	for _, pat := range wildcardPatterns {
		if strings.Contains(content, pat) {
			r.Status = StatusFail
			r.Detail = fmt.Sprintf("Wildcard network rule detected: %q", pat)
			r.Remediation = "Replace wildcard with explicit destination allowlist. " +
				"Only permit build.nvidia.com and required inference endpoints."
			return r
		}
	}

	r.Status = StatusPass
	r.Detail = "No wildcard network allow-all rule detected."
	return r
}

// checkProcessPolicyHardeningEnabled verifies that process hardening (syscall
// blocking, privilege escalation prevention) is referenced in the policy.
// These settings are locked at sandbox creation and cannot be changed at runtime.
func checkProcessPolicyHardeningEnabled(dir string) NemoClawAuditResult {
	r := NemoClawAuditResult{
		CheckID: "NMC-005",
		Domain:  "process",
		Title:   "Process hardening (syscall blocking / privilege escalation) configured",
	}
	content, err := readFirstPolicyFile(dir)
	if err != nil {
		r.Status = StatusError
		r.Detail = "Could not read policy file: " + err.Error()
		return r
	}

	hardeningSignals := []string{
		"privilege_escalation", "seccomp", "syscalls", "no_new_privileges",
		"process:", "drop_capabilities",
	}
	found := false
	for _, sig := range hardeningSignals {
		if strings.Contains(content, sig) {
			found = true
			break
		}
	}
	if !found {
		r.Status = StatusFail
		r.Detail = "No process hardening configuration found in policy."
		r.Remediation = "Add a process: section to your policy with 'no_new_privileges: true' " +
			"and seccomp profile. See: https://docs.nvidia.com/nemoclaw/latest/"
		return r
	}

	r.Status = StatusPass
	r.Detail = "Process hardening configuration present in policy."
	return r
}

// checkInferencePolicyConfigured verifies that an inference provider is defined
// in blueprint.yaml. An unconfigured inference policy may route requests to
// uncontrolled external APIs, leaking prompt data outside the OpenShell sandbox.
func checkInferencePolicyConfigured(dir string) NemoClawAuditResult {
	r := NemoClawAuditResult{
		CheckID: "NMC-006",
		Domain:  "inference",
		Title:   "Inference provider configured in blueprint.yaml",
	}
	bpPath := filepath.Join(dir, "blueprint.yaml")
	data, err := os.ReadFile(bpPath)
	if err != nil {
		r.Status = StatusFail
		r.Detail = "blueprint.yaml missing — inference policy cannot be verified."
		r.Remediation = "Run `nemoclaw onboard` and configure an inference profile."
		return r
	}
	content := string(data)
	inferenceSignals := []string{"nvidia-nim", "vllm", "inference:", "provider:", "nemotron"}
	for _, sig := range inferenceSignals {
		if strings.Contains(content, sig) {
			r.Status = StatusPass
			r.Detail = "Inference provider configuration found in blueprint.yaml."
			return r
		}
	}
	r.Status = StatusFail
	r.Detail = "No inference provider configuration found in blueprint.yaml."
	r.Remediation = "Run `openshell inference set --provider nvidia-nim --model nemotron-3-super-120b`."
	return r
}

// checkNvidiaAPIKeyNotPlaintext verifies that the NVIDIA API key is not stored
// as a plaintext environment variable in any config or .env file. NemoClaw
// requires an NVIDIA API key for build.nvidia.com inference; exposure of this
// key grants unrestricted access to NVIDIA's cloud model catalog.
func checkNvidiaAPIKeyNotPlaintext(dir string) NemoClawAuditResult {
	r := NemoClawAuditResult{
		CheckID: "NMC-007",
		Domain:  "credentials",
		Title:   "NVIDIA API key not stored in plaintext config",
	}

	// Check environment first.
	if val := os.Getenv("NVIDIA_API_KEY"); val != "" {
		r.Status = StatusFail
		r.Detail = "NVIDIA_API_KEY found as plaintext environment variable."
		r.Remediation = "Store the NVIDIA API key in a secrets manager (Vault, AWS Secrets Manager, " +
			"or ADINKHEPRA encrypted store) and inject it at runtime."
		return r
	}

	// Scan for .env files containing NVIDIA_API_KEY.
	foundIn := ""
	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || info.Size() > 1<<20 {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(line, "NVIDIA_API_KEY") && strings.Contains(line, "=") {
				// Only flag if the value side appears non-empty.
				parts := strings.SplitN(line, "=", 2)
				if len(parts) == 2 && strings.TrimSpace(parts[1]) != "" &&
					!strings.HasPrefix(strings.TrimSpace(parts[1]), "${") {
					foundIn = path
					return filepath.SkipAll
				}
			}
		}
		return nil
	})

	if foundIn != "" {
		r.Status = StatusFail
		r.Detail = fmt.Sprintf("NVIDIA_API_KEY found in plaintext file: %s", foundIn)
		r.Remediation = "Move the key to a secrets manager and reference it with ${NVIDIA_API_KEY}."
		return r
	}

	r.Status = StatusPass
	r.Detail = "NVIDIA_API_KEY not found in plaintext config files."
	return r
}

// checkSandboxPathIsolation verifies that the NemoClaw config directory itself is
// not world-readable (mode 0777 or 0755). The config dir may contain the YAML
// policy and blueprint, which should be operator-read-only.
func checkSandboxPathIsolation(dir string) NemoClawAuditResult {
	r := NemoClawAuditResult{
		CheckID: "NMC-008",
		Domain:  "filesystem",
		Title:   "NemoClaw config directory not world-readable",
	}
	info, err := os.Stat(dir)
	if err != nil {
		r.Status = StatusError
		r.Detail = "Cannot stat config directory: " + err.Error()
		return r
	}
	mode := info.Mode().Perm()
	if mode&0o004 != 0 { // world-readable bit
		r.Status = StatusFail
		r.Detail = fmt.Sprintf("Config directory %s is world-readable (mode %04o).", dir, mode)
		r.Remediation = "Run `chmod 700 " + dir + "` to restrict access to the owning user."
		return r
	}
	r.Status = StatusPass
	r.Detail = fmt.Sprintf("Config directory permissions: %04o (not world-readable).", mode)
	return r
}

// checkHotReloadNetworkOnly verifies that static policy sections (filesystem,
// process) are not marked as hot-reloadable. Only network and inference policies
// should be hot-reloadable; allowing runtime changes to filesystem or process
// policies can be exploited by a compromised agent to escape the sandbox.
func checkHotReloadNetworkOnly(dir string) NemoClawAuditResult {
	r := NemoClawAuditResult{
		CheckID: "NMC-009",
		Domain:  "process",
		Title:   "Static policy domains (filesystem/process) not marked hot-reloadable",
	}
	content, err := readFirstPolicyFile(dir)
	if err != nil {
		r.Status = StatusError
		r.Detail = "Could not read policy file: " + err.Error()
		return r
	}

	lines := strings.Split(content, "\n")
	inStaticDomain := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "filesystem:") || strings.HasPrefix(trimmed, "process:") {
			inStaticDomain = true
		}
		if inStaticDomain && (strings.HasPrefix(trimmed, "network:") || strings.HasPrefix(trimmed, "inference:")) {
			inStaticDomain = false
		}
		if inStaticDomain && strings.Contains(trimmed, "hot_reload: true") {
			r.Status = StatusFail
			r.Detail = "Static policy domain (filesystem or process) has 'hot_reload: true' — sandbox escape risk."
			r.Remediation = "Remove 'hot_reload: true' from filesystem and process policy sections. " +
				"Only network and inference sections should be hot-reloadable per NVIDIA OpenShell spec."
			return r
		}
	}

	r.Status = StatusPass
	r.Detail = "Static policy domains do not allow hot-reload."
	return r
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

// readFirstPolicyFile returns the content of the first OpenShell policy YAML found.
func readFirstPolicyFile(dir string) (string, error) {
	candidates := []string{
		"policy.yaml", "openshell-policy.yaml", "sandbox-policy.yaml", "nemoclaw.yaml",
	}
	for _, name := range candidates {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err == nil {
			return string(data), nil
		}
	}
	return "", fmt.Errorf("no OpenShell policy file found in %s", dir)
}

// NemoClawCheckIDs returns the full list of check IDs in this package, useful
// for registering them in the ASAF compliance engine or ADINKHEPRA audit log.
func NemoClawCheckIDs() []string {
	return []string{
		"NMC-001", "NMC-002", "NMC-003", "NMC-004", "NMC-005",
		"NMC-006", "NMC-007", "NMC-008", "NMC-009",
	}
}
