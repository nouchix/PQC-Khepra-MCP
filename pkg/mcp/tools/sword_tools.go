// Package tools — Pentesting + Recon suite handler functions.
//
// Registration: add to cmd/khepra-mcp/main.go via executor.RegisterFunc().
//
// Tools exposed:
//   - HandleEnumerateHost    : Full system + network intelligence collection
//   - HandleFingerprintDevice: Hardware device fingerprinting
//   - HandlePortScan         : TCP/service scanner
//   - HandleVulnScan         : Multi-ecosystem vulnerability scanner
//   - HandleSecretScan       : Detect exposed secrets and API keys
//   - HandleContainerScan    : Dockerfile/container security analysis
//   - HandleComplianceScan   : CIS/STIG/NIST baseline compliance check
//   - HandlePacketAnalyze    : Analyze Wireshark/tshark JSON capture
//   - HandleAttackGraph      : Generate MITRE ATT&CK attack graph
package tools

import (
	"context"
	"fmt"

	"github.com/nouchix/PQC-Khepra-MCP/pkg/dag"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/enumerate"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/fingerprint"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/graph"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/lorentz"
	mcp "github.com/nouchix/PQC-Khepra-MCP/pkg/mcp"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/packet"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/scanner"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/scanners"
)

// HandleEnumerateHost performs full host enumeration — collects comprehensive
// system and network intelligence. Maps to MITRE ATT&CK T1082, T1049, T1016.
// All findings DAG-attested with ML-DSA-65.
func HandleEnumerateHost(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	result := map[string]any{
		"collected_at": lorentz.StampNow(),
	}
	var warnings []string

	netIntel, err := enumerate.CollectNetworkIntelligence()
	if err != nil {
		warnings = append(warnings, fmt.Sprintf("network intel: %v", err))
	} else {
		result["network"] = netIntel
	}

	store := getKASAStore()
	node := dag.Node{
		Action: "enumerate_host",
		Symbol: "OwoForoAdobe",
		Time:   lorentz.StampNow(),
		PQC: map[string]string{
			"agent":       "Enumerate-v1",
			"mitre_t1082": "System Info Discovery",
			"mitre_t1046": "Network Service Discovery",
		},
	}
	store.Add(&node, []string{}) //nolint:errcheck

	return result, warnings, nil
}

// HandleFingerprintDevice collects a hardware fingerprint of the current device.
// Captures: MAC addresses, CPU signature, disk serials, BIOS serial, TPM info.
// Generates a composite hardware hash for device identity binding.
func HandleFingerprintDevice(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	fp, err := fingerprint.CollectDeviceFingerprint()
	if err != nil {
		return nil, []string{fmt.Sprintf("fingerprint: %v", err)}, nil
	}

	store := getKASAStore()
	node := dag.Node{
		Action: "fingerprint_device",
		Symbol: "Nkyinkyim",
		Time:   lorentz.StampNow(),
		PQC: map[string]string{
			"agent": "DeviceFingerprint-v1",
		},
	}
	store.Add(&node, []string{}) //nolint:errcheck

	return fp, nil, nil
}

// HandlePortScan runs a TCP port and service scanner against a target host.
// Identifies open ports, banner-grabs services, and records the crawl artifact.
// Maps to MITRE ATT&CK T1046 (Network Service Discovery).
func HandlePortScan(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	if gate := GateForTool("port_scan"); gate != nil {
		return gate, nil, nil
	}
	target, _ := call.Args["target"].(string)
	if target == "" {
		return nil, nil, fmt.Errorf("port_scan: target is required")
	}

	s := scanner.New()
	results, err := s.Run(target)
	if err != nil {
		return nil, nil, fmt.Errorf("port_scan: %w", err)
	}

	store := getKASAStore()
	node := dag.Node{
		Action: "port_scan",
		Symbol: "OwoForoAdobe",
		Time:   lorentz.StampNow(),
		PQC: map[string]string{
			"target":     target,
			"open_ports": fmt.Sprintf("%d", len(results)),
			"agent":      "Scanner-v1",
			"mitre":      "T1046",
		},
	}
	store.Add(&node, []string{}) //nolint:errcheck

	return map[string]any{
		"target":       target,
		"open_ports":   len(results),
		"results":      results,
		"dag_attested": true,
		"scanned_at":   lorentz.StampNow(),
	}, nil, nil
}

// HandleVulnScan runs the built-in multi-ecosystem vulnerability scanner.
// Scans: Go modules, NPM, Python, container manifests, config files.
// Returns: CVE IDs, CVSS scores, affected packages, and fix versions.
func HandleVulnScan(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	if gate := GateForTool("vuln_scan"); gate != nil {
		return gate, nil, nil
	}
	targetDir, _ := call.Args["target_dir"].(string)
	if targetDir == "" {
		targetDir = "."
	}

	results, err := scanners.RunBuiltInVulnerabilityScan(targetDir)
	if err != nil {
		return nil, []string{fmt.Sprintf("vuln_scan: %v", err)}, nil
	}

	store := getKASAStore()
	node := dag.Node{
		Action: "vuln_scan",
		Symbol: "Dwennimmen",
		Time:   lorentz.StampNow(),
		PQC: map[string]string{
			"target": targetDir,
			"count":  fmt.Sprintf("%d", len(results)),
			"agent":  "BuiltInVulnScanner-v1",
		},
	}
	store.Add(&node, []string{}) //nolint:errcheck

	return map[string]any{
		"findings":     results,
		"count":        len(results),
		"scanned_dir":  targetDir,
		"dag_attested": true,
		"scanned_at":   lorentz.StampNow(),
	}, nil, nil
}

// HandleSecretScan detects exposed secrets, API keys, and credentials.
// Uses entropy analysis + pattern matching for AWS keys, GitHub tokens,
// private keys, JWT secrets, database passwords, and more.
func HandleSecretScan(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	if gate := GateForTool("secret_scan"); gate != nil {
		return gate, nil, nil
	}
	targetDir, _ := call.Args["target_dir"].(string)
	if targetDir == "" {
		targetDir = "."
	}

	results, err := scanners.RunBuiltInSecretScan(targetDir)
	if err != nil {
		return nil, []string{fmt.Sprintf("secret_scan: %v", err)}, nil
	}

	return map[string]any{
		"findings":    results,
		"count":       len(results),
		"scanned_dir": targetDir,
		"scanned_at":  lorentz.StampNow(),
	}, nil, nil
}

// HandleContainerScan analyzes Dockerfile and container manifests for
// security misconfigurations and base image vulnerabilities.
func HandleContainerScan(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	if gate := GateForTool("container_scan"); gate != nil {
		return gate, nil, nil
	}
	imagePath, _ := call.Args["target_dir"].(string)
	if imagePath == "" {
		imagePath = "."
	}

	findings, err := scanners.RunBuiltInContainerScan(imagePath)
	if err != nil {
		return nil, []string{fmt.Sprintf("container_scan: %v", err)}, nil
	}

	return map[string]any{
		"findings":    findings,
		"scanned_dir": imagePath,
		"scanned_at":  lorentz.StampNow(),
	}, nil, nil
}

// HandleComplianceScan runs built-in compliance checks against CIS, STIG, and NIST baselines.
// Returns pass/fail per control with remediation guidance.
func HandleComplianceScan(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	if gate := GateForTool("compliance_scan"); gate != nil {
		return gate, nil, nil
	}
	framework, _ := call.Args["framework"].(string)
	if framework == "" {
		framework = "ALL"
	}

	results, err := scanners.RunBuiltInComplianceScan(framework)
	if err != nil {
		return nil, []string{fmt.Sprintf("compliance_scan: %v", err)}, nil
	}

	store := getKASAStore()
	node := dag.Node{
		Action: "compliance_scan",
		Symbol: "Eban",
		Time:   lorentz.StampNow(),
		PQC: map[string]string{
			"framework": framework,
			"agent":     "BuiltInComplianceScanner-v1",
		},
	}
	store.Add(&node, []string{}) //nolint:errcheck

	return results, nil, nil
}

// HandlePacketAnalyze analyzes a Wireshark/tshark JSON packet capture file.
// Extracts: protocol distribution, suspicious connections, DNS queries,
// HTTP methods, potential C2 patterns.
func HandlePacketAnalyze(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	if gate := GateForTool("packet_analyze"); gate != nil {
		return gate, nil, nil
	}
	captureFile, _ := call.Args["capture_file"].(string)
	if captureFile == "" {
		return nil, nil, fmt.Errorf("packet_analyze: capture_file is required")
	}

	result, err := packet.AnalyzeWiresharkJSON(captureFile)
	if err != nil {
		return nil, nil, fmt.Errorf("packet_analyze: %w", err)
	}

	return result, nil, nil
}

// HandleAttackGraph generates an attack graph from agent inventory and NHI records.
// Models lateral movement paths, privilege escalation vectors, and blast radius.
// Returns a structured graph with per-path risk scores.
func HandleAttackGraph(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	if gate := GateForTool("attack_graph"); gate != nil {
		return gate, nil, nil
	}
	// Build attack graph from current NHI inventory (no external agents needed)
	nhiTracker := getNHI()
	nhiRecords, err := nhiTracker.Inventory()
	if err != nil {
		return nil, []string{fmt.Sprintf("attack_graph: nhi inventory: %v", err)}, nil
	}

	attackGraph := graph.BuildAttackGraph(nil, nhiRecords)
	graphJSON, err := attackGraph.ToJSON()
	if err != nil {
		return nil, nil, fmt.Errorf("attack_graph: %w", err)
	}

	store := getKASAStore()
	node := dag.Node{
		Action: "attack_graph",
		Symbol: "Dwennimmen",
		Time:   lorentz.StampNow(),
		PQC: map[string]string{
			"nodes": fmt.Sprintf("%d", len(attackGraph.NodeList())),
			"agent": "AttackGraph-v1",
		},
	}
	store.Add(&node, []string{}) //nolint:errcheck

	return map[string]any{
		"graph":        string(graphJSON),
		"node_count":   len(attackGraph.NodeList()),
		"nhi_records":  len(nhiRecords),
		"high_risk":    len(attackGraph.HighRiskPaths()),
		"generated_at": lorentz.StampNow(),
	}, nil, nil
}
