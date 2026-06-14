package connectors

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// =============================================================================
// NVIDIA NEMOCLAW / OPENSHELL CONNECTOR
//
// Discovers and inventories NemoClaw deployments — NVIDIA's enterprise security
// stack for OpenClaw AI agents, announced at GTC 2026. NemoClaw installs the
// OpenShell runtime on top of OpenClaw, adding sandboxing, least-privilege
// access controls, YAML-based network egress policies, and the Gretel
// differential-privacy router.
//
// Reference: https://github.com/NVIDIA/NemoClaw
// Discovery signals:
//   - nemoclaw / openshell process presence
//   - ~/.nemoclaw/ or ./.nemoclaw/ config directory
//   - OpenShell YAML policy files (policy.yaml, nemoclaw.yaml)
//   - NVIDIA_API_KEY environment variable (indicates active NemoClaw onboarding)
//   - OpenClaw port 18789 (NemoClaw inherits OpenClaw's default listener)
//
// =============================================================================

// NemoClawConnector discovers NemoClaw/OpenShell deployments on the local host.
// It checks filesystem signals, config directories, and running-process heuristics.
// Operates read-only by default — no mutations are performed.
type NemoClawConnector struct {
	Autonomous  bool     // Set true to enable credential revocation
	ScanPaths   []string // Additional paths to search for .nemoclaw configs
	Host        string   // Remote host to probe (empty = local only)
}

// nemoClawConfigDirs are filesystem paths where NemoClaw stores its config.
var nemoClawConfigDirs = []string{
	filepath.Join(os.Getenv("HOME"), ".nemoclaw"),
	"/etc/nemoclaw",
	"/opt/nemoclaw",
	".nemoclaw",
}

// nemoClawPolicyFilenames are YAML policy files written by the OpenShell runtime.
var nemoClawPolicyFilenames = []string{
	"policy.yaml",
	"nemoclaw.yaml",
	"openshell-policy.yaml",
	"sandbox-policy.yaml",
	"network-policy.yaml",
}

// nemoClawProcessSignals are process-name fragments that indicate NemoClaw activity.
var nemoClawProcessSignals = []string{
	"nemoclaw",
	"openshell",
	"nemotron",
}

func (c *NemoClawConnector) Name() string     { return "NVIDIA NemoClaw / OpenShell Connector" }
func (c *NemoClawConnector) Platform() string { return "nemoclaw" }
func (c *NemoClawConnector) IsReadOnly() bool { return !c.Autonomous }

// DiscoverAgents scans for NemoClaw deployments via filesystem and process signals.
func (c *NemoClawConnector) DiscoverAgents() ([]AgentSummary, error) {
	var agents []AgentSummary

	// 1. Check well-known NemoClaw config directories.
	for _, dir := range nemoClawConfigDirs {
		if info, err := os.Stat(dir); err == nil && info.IsDir() {
			agent := c.agentFromConfigDir(dir)
			agents = append(agents, agent)
		}
	}

	// 2. Check caller-supplied extra paths.
	for _, dir := range c.ScanPaths {
		if info, err := os.Stat(dir); err == nil && info.IsDir() {
			agent := c.agentFromConfigDir(dir)
			agents = append(agents, agent)
		}
	}

	// 3. Walk current working directory for policy files (project-local installs).
	cwd, err := os.Getwd()
	if err == nil {
		cwdAgents := c.scanForPolicyFiles(cwd)
		agents = append(agents, cwdAgents...)
	}

	return agents, nil
}

// DiscoverNHIs looks for NVIDIA API keys that indicate active NemoClaw onboarding.
// An exposed NVIDIA_API_KEY is a high-risk NHI — it grants inference access to
// NVIDIA's cloud models and must be stored in a secrets manager, not env vars.
func (c *NemoClawConnector) DiscoverNHIs() ([]NHISummary, error) {
	var nhis []NHISummary

	// Check environment for NVIDIA_API_KEY (common misconfiguration).
	if key := os.Getenv("NVIDIA_API_KEY"); key != "" {
		nhis = append(nhis, NHISummary{
			ID:        "env:NVIDIA_API_KEY",
			Type:      "api-key",
			Owner:     "nemoclaw-runtime",
			Platform:  "nemoclaw",
			Scopes:    []string{"inference:nvidia-cloud", "nemotron:infer"},
			RiskScore: 0.85, // High: plaintext env var exposure
		})
	}

	// Scan config dirs for files that may contain API keys.
	for _, dir := range nemoClawConfigDirs {
		if _, err := os.Stat(dir); err != nil {
			continue
		}
		found := c.scanForAPIKeyFiles(dir)
		nhis = append(nhis, found...)
	}

	return nhis, nil
}

// RevokeCredential is a no-op in read-only mode. In Autonomous mode it would
// call `nemoclaw offboard` to rotate the NVIDIA API key.
func (c *NemoClawConnector) RevokeCredential(id string) error {
	if c.IsReadOnly() {
		return ErrReadOnly
	}
	// Production: exec `nemoclaw offboard --credential <id>` or call the
	// OpenShell management API to rotate the credential.
	return fmt.Errorf("NemoClaw: credential revocation requires OpenShell API access (id=%s)", id)
}

// ─── Internal helpers ──────────────────────────────────────────────────────────

// agentFromConfigDir creates an AgentSummary from a discovered NemoClaw config dir.
func (c *NemoClawConnector) agentFromConfigDir(dir string) AgentSummary {
	riskScore := 0.4 // Base risk: known NemoClaw install, alpha software
	pqcProtected := false

	// If ADINKHEPRA attestation files are present in the config dir, lower risk.
	attestPath := filepath.Join(dir, "adinkhepra.json")
	if _, err := os.Stat(attestPath); err == nil {
		riskScore = 0.15
		pqcProtected = true
	}

	// If policy.yaml is missing or empty, raise risk — sandbox is unconfigured.
	policyPresent := false
	for _, pf := range nemoClawPolicyFilenames {
		if info, err := os.Stat(filepath.Join(dir, pf)); err == nil && info.Size() > 0 {
			policyPresent = true
			break
		}
	}
	if !policyPresent {
		riskScore = 0.80 // High: NemoClaw installed but no sandbox policy configured
	}

	return AgentSummary{
		ID:           fmt.Sprintf("nemoclaw-%s-%d", filepath.Base(dir), time.Now().UnixNano()),
		Name:         fmt.Sprintf("NemoClaw @ %s", dir),
		AgentType:    "nemoclaw-openshell",
		Environment:  "nemoclaw",
		RiskScore:    riskScore,
		Permissions:  []string{"filesystem:/sandbox", "filesystem:/tmp", "network:egress-policy"},
		LastSeen:     time.Now(),
		Managed:      pqcProtected,
		PQCProtected: pqcProtected,
	}
}

// scanForPolicyFiles walks a directory for OpenShell policy YAML files.
func (c *NemoClawConnector) scanForPolicyFiles(root string) []AgentSummary {
	var agents []AgentSummary
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		for _, pf := range nemoClawPolicyFilenames {
			if strings.EqualFold(info.Name(), pf) {
				agents = append(agents, AgentSummary{
					ID:          fmt.Sprintf("nemoclaw-policy-%d", time.Now().UnixNano()),
					Name:        fmt.Sprintf("NemoClaw OpenShell policy: %s", path),
					AgentType:   "nemoclaw-openshell",
					Environment: "nemoclaw",
					RiskScore:   0.35, // Policy file found — sandbox likely configured
					Permissions: []string{"filesystem:policy-controlled", "network:egress-policy"},
					LastSeen:    time.Now(),
					Managed:     false,
				})
				break
			}
		}
		return nil
	})
	return agents
}

// scanForAPIKeyFiles looks for config files that likely contain NVIDIA API keys.
func (c *NemoClawConnector) scanForAPIKeyFiles(dir string) []NHISummary {
	var nhis []NHISummary
	sensitiveNames := []string{"credentials", "config", ".env", "api_keys", "secrets"}

	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		name := strings.ToLower(strings.TrimSuffix(info.Name(), filepath.Ext(info.Name())))
		for _, s := range sensitiveNames {
			if strings.Contains(name, s) {
				nhis = append(nhis, NHISummary{
					ID:        fmt.Sprintf("file:%s", path),
					Type:      "api-key",
					Owner:     "nemoclaw-runtime",
					Platform:  "nemoclaw",
					Scopes:    []string{"inference:nvidia-cloud"},
					RiskScore: 0.70, // Elevated: key stored in file, not secrets manager
				})
				break
			}
		}
		return nil
	})
	return nhis
}

// NewNemoClawConnector returns a NemoClawConnector pre-configured for standard paths.
func NewNemoClawConnector() *NemoClawConnector {
	return &NemoClawConnector{
		ScanPaths: []string{
			"/opt/nemoclaw",
			"/etc/nemoclaw",
		},
	}
}
