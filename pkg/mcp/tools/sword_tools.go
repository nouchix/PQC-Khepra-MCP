// Package tools — Pentesting + Recon suite tools.
//
// Tools exposed:
//   - enumerate_host     : Full system + network intelligence collection
//   - fingerprint_device : Hardware device fingerprinting (CPU, BIOS, TPM, MAC)
//   - port_scan          : TCP/service scanner
//   - vuln_scan          : Built-in vulnerability scanner (Go, NPM, Python, containers)
//   - secret_scan        : Detect exposed secrets and API keys
//   - container_scan     : Dockerfile security analysis
//   - compliance_scan    : CIS/STIG/NIST baseline compliance check
//   - packet_analyze     : Analyze Wireshark/tshark JSON capture
//   - attack_graph       : Generate MITRE ATT&CK attack graph
//   - network_topology   : Build network topology model
package tools

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/nouchix/PQC-Khepra-MCP/pkg/dag"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/enumerate"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/fingerprint"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/graph"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/lorentz"
	mcp "github.com/nouchix/PQC-Khepra-MCP/pkg/mcp"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/network"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/packet"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/scanner"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/scanners"
)

// ── Tool: enumerate_host ──────────────────────────────────────────────────────

func init() {
	RegisterTool(mcp.Tool{
		Name: "enumerate_host",
		Description: "Full host enumeration — collects comprehensive system and network intelligence. " +
			"System: processes, services, users, cron jobs, installed software, kernel modules, startup items. " +
			"Network: listening ports, interfaces, routes, DNS servers, OS fingerprint. " +
			"Maps to MITRE ATT&CK T1082 (System Info Discovery), T1049 (Network Connections), T1016 (Network Config). " +
			"All findings DAG-attested with ML-DSA-65.",
		InputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"include_network": {
					"type": "boolean",
					"description": "Include network intelligence collection (default: true)",
					"default": true
				},
				"include_system": {
					"type": "boolean",
					"description": "Include system intelligence collection (default: true)",
					"default": true
				}
			}
		}`),
		Handler: handleEnumerateHost,
	})
}

func handleEnumerateHost(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	inclNet := true
	inclSys := true
	if v, ok := call.Args["include_network"].(bool); ok {
		inclNet = v
	}
	if v, ok := call.Args["include_system"].(bool); ok {
		inclSys = v
	}

	result := map[string]any{
		"collected_at": lorentz.StampNow(),
	}
	var warnings []string

	if inclNet {
		netIntel, err := enumerate.CollectNetworkIntelligence(ctx)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("network intel: %v", err))
		} else {
			result["network"] = netIntel
		}
	}

	if inclSys {
		sysIntel, err := enumerate.CollectSystemIntelligence(ctx)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("system intel: %v", err))
		} else {
			result["system"] = sysIntel
		}
	}

	store := getKASAStore()
	node := dag.Node{
		Action: "enumerate_host",
		Symbol: "OwoForoAdobe",
		Time:   lorentz.StampNow(),
		PQC: map[string]string{
			"agent":          "Enumerate-v1",
			"include_net":    fmt.Sprintf("%v", inclNet),
			"include_system": fmt.Sprintf("%v", inclSys),
		},
	}
	store.Add(&node, []string{}) //nolint:errcheck

	return result, warnings, nil
}

// ── Tool: fingerprint_device ──────────────────────────────────────────────────

func init() {
	RegisterTool(mcp.Tool{
		Name: "fingerprint_device",
		Description: "Collect a hardware fingerprint of the current device. " +
			"Captures: MAC addresses, CPU signature, disk serials, BIOS serial, motherboard ID, TPM info. " +
			"Generates a composite hardware hash for device identity binding. " +
			"Used for zero-trust device attestation and supply chain integrity verification.",
		InputSchema: json.RawMessage(`{"type":"object","properties":{}}`),
		Handler:     handleFingerprintDevice,
	})
}

func handleFingerprintDevice(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	fp, err := fingerprint.CollectDeviceFingerprint(ctx)
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

// ── Tool: port_scan ───────────────────────────────────────────────────────────

func init() {
	RegisterTool(mcp.Tool{
		Name: "port_scan",
		Description: "Run a TCP port and service scanner against a target host. " +
			"Identifies open ports, banner-grabs services, and signs the crawl artifact with ML-DSA-65. " +
			"Maps to MITRE ATT&CK T1046 (Network Service Discovery).",
		InputSchema: json.RawMessage(`{
			"type": "object",
			"required": ["target"],
			"properties": {
				"target": {
					"type": "string",
					"description": "Target IP or hostname"
				}
			}
		}`),
		Handler: handlePortScan,
	})
}

func handlePortScan(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
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
		"target":      target,
		"open_ports":  len(results),
		"results":     results,
		"dag_attested": true,
		"scanned_at":  lorentz.StampNow(),
	}, nil, nil
}

// ── Tool: vuln_scan ───────────────────────────────────────────────────────────

func init() {
	RegisterTool(mcp.Tool{
		Name: "vuln_scan",
		Description: "Run the built-in multi-ecosystem vulnerability scanner. " +
			"Scans: Go modules (go.sum), NPM (package-lock.json), Python (requirements.txt), " +
			"container manifests, and security-sensitive configuration files. " +
			"Returns: CVE IDs, CVSS scores, affected packages, and fix versions.",
		InputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"target_dir": {
					"type": "string",
					"description": "Directory to scan (default: current directory)",
					"default": "."
				}
			}
		}`),
		Handler: handleVulnScan,
	})
}

func handleVulnScan(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	targetDir, _ := call.Args["target_dir"].(string)
	if targetDir == "" {
		targetDir = "."
	}

	results, err := scanners.RunBuiltInVulnerabilityScan(ctx, targetDir)
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

// ── Tool: secret_scan ─────────────────────────────────────────────────────────

func init() {
	RegisterTool(mcp.Tool{
		Name: "secret_scan",
		Description: "Detect exposed secrets, API keys, and credentials in source code and config files. " +
			"Uses entropy analysis + pattern matching for: AWS keys, GitHub tokens, " +
			"private keys, JWT secrets, database passwords, and more.",
		InputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"target_dir": {
					"type": "string",
					"description": "Directory to scan (default: current directory)",
					"default": "."
				}
			}
		}`),
		Handler: handleSecretScan,
	})
}

func handleSecretScan(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	targetDir, _ := call.Args["target_dir"].(string)
	if targetDir == "" {
		targetDir = "."
	}

	results, err := scanners.RunBuiltInSecretScan(ctx, targetDir)
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

// ── Tool: container_scan ──────────────────────────────────────────────────────

func init() {
	RegisterTool(mcp.Tool{
		Name:        "container_scan",
		Description: "Analyze Dockerfile and container manifests for security misconfigurations and base image vulnerabilities.",
		InputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"target_dir": {
					"type": "string",
					"description": "Directory containing Dockerfiles (default: current directory)",
					"default": "."
				}
			}
		}`),
		Handler: handleContainerScan,
	})
}

func handleContainerScan(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	targetDir, _ := call.Args["target_dir"].(string)
	if targetDir == "" {
		targetDir = "."
	}

	results, err := scanners.RunBuiltInContainerScan(ctx, targetDir)
	if err != nil {
		return nil, []string{fmt.Sprintf("container_scan: %v", err)}, nil
	}

	return map[string]any{
		"findings":    results,
		"count":       len(results),
		"scanned_dir": targetDir,
		"scanned_at":  lorentz.StampNow(),
	}, nil, nil
}

// ── Tool: compliance_scan ─────────────────────────────────────────────────────

func init() {
	RegisterTool(mcp.Tool{
		Name: "compliance_scan",
		Description: "Run built-in compliance checks against CIS, STIG, and NIST baselines. " +
			"Checks: cramfs disabled, bootloader permissions, unique UIDs, account management. " +
			"Returns pass/fail per control with remediation guidance.",
		InputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"framework": {
					"type": "string",
					"enum": ["CIS", "STIG", "NIST", "ALL"],
					"description": "Compliance framework to check against (default: ALL)",
					"default": "ALL"
				}
			}
		}`),
		Handler: handleComplianceScan,
	})
}

func handleComplianceScan(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	framework, _ := call.Args["framework"].(string)
	if framework == "" {
		framework = "ALL"
	}

	results, err := scanners.RunBuiltInComplianceScan(ctx, framework)
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

// ── Tool: packet_analyze ──────────────────────────────────────────────────────

func init() {
	RegisterTool(mcp.Tool{
		Name: "packet_analyze",
		Description: "Analyze a Wireshark/tshark JSON packet capture file. " +
			"Extracts: protocol distribution, suspicious connections, DNS queries, " +
			"HTTP methods, potential C2 patterns. Returns structured analysis report.",
		InputSchema: json.RawMessage(`{
			"type": "object",
			"required": ["capture_file"],
			"properties": {
				"capture_file": {
					"type": "string",
					"description": "Path to Wireshark JSON export (tshark -T json output)"
				}
			}
		}`),
		Handler: handlePacketAnalyze,
	})
}

func handlePacketAnalyze(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
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

// ── Tool: attack_graph ────────────────────────────────────────────────────────

func init() {
	RegisterTool(mcp.Tool{
		Name: "attack_graph",
		Description: "Generate an attack graph from a network topology. " +
			"Models lateral movement paths, privilege escalation vectors, " +
			"and blast radius for each exposed service. " +
			"Returns a Mermaid-compatible graph and per-path risk scores.",
		InputSchema: json.RawMessage(`{
			"type": "object",
			"properties": {
				"target_subnet": {
					"type": "string",
					"description": "Target subnet to model (e.g. 192.168.1.0/24)",
					"default": "127.0.0.1/32"
				}
			}
		}`),
		Handler: handleAttackGraph,
	})
}

func handleAttackGraph(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	subnet, _ := call.Args["target_subnet"].(string)
	if subnet == "" {
		subnet = "127.0.0.1/32"
	}

	topology := network.NewNetworkTopology(subnet)
	attackGraph, err := graph.BuildAttackGraph(ctx, topology)
	if err != nil {
		return nil, nil, fmt.Errorf("attack_graph: %w", err)
	}

	store := getKASAStore()
	node := dag.Node{
		Action: "attack_graph",
		Symbol: "Dwennimmen",
		Time:   lorentz.StampNow(),
		PQC: map[string]string{
			"subnet": subnet,
			"agent":  "AttackGraph-v1",
		},
	}
	store.Add(&node, []string{}) //nolint:errcheck

	return attackGraph, nil, nil
}
