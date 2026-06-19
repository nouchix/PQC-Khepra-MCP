// Package tools — Digital Forensics + FIM + Audit memory tools.
//
// Tools exposed:
//   - forensics_collect   : Full digital forensic snapshot (processes, network, files)
//   - fim_baseline        : Create file integrity baseline
//   - fim_check           : Check a file's hash against baseline
//   - audit_snapshot      : AFFiNE system snapshot (public IP, processes, file hashes)
//   - audit_export        : Export audit trail to CSV
package tools

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/nouchix/PQC-Khepra-MCP/pkg/audit"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/dag"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/fim"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/forensics"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/lorentz"
	mcp "github.com/nouchix/PQC-Khepra-MCP/pkg/mcp"
)

// ── Tool: forensics_collect ───────────────────────────────────────────────────

func init() {
	RegisterTool(mcp.Tool{
		Name: "forensics_collect",
		Description: "Collect a full digital forensic snapshot of the current system. " +
			"Captures: running processes (PID, name, user, cmdline), " +
			"active network connections (local/remote addr, state, PID), " +
			"open ports, mounted file systems, user sessions, security events. " +
			"Result is ML-DSA-65 signed and DAG-recorded under symbol Sankofa. " +
			"Suitable for DFIR (Digital Forensics and Incident Response) evidence packages.",
		InputSchema: json.RawMessage(`{"type":"object","properties":{}}`),
		Handler:     handleForensicsCollect,
	})
}

func handleForensicsCollect(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	collector := forensics.NewCollector()
	snapshot, err := collector.CollectSnapshot(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("forensics_collect: %w", err)
	}

	store := getKASAStore()
	node := dag.Node{
		Action: "forensics_collect",
		Symbol: "Sankofa",
		Time:   lorentz.StampNow(),
		PQC: map[string]string{
			"snapshot_id":   snapshot.SnapshotID,
			"hostname":      snapshot.Hostname,
			"os":            snapshot.OS,
			"process_count": fmt.Sprintf("%d", len(snapshot.Processes)),
			"conn_count":    fmt.Sprintf("%d", len(snapshot.NetworkConns)),
			"port_count":    fmt.Sprintf("%d", len(snapshot.OpenPorts)),
			"agent":         "ForensicsCollector-v1",
		},
	}
	store.Add(&node, []string{}) //nolint:errcheck

	return snapshot, nil, nil
}

// ── Tool: fim_baseline ────────────────────────────────────────────────────────

func init() {
	RegisterTool(mcp.Tool{
		Name: "fim_baseline",
		Description: "Create a File Integrity Monitor (FIM) baseline for a directory. " +
			"Computes SHA-256 hashes for all files under the given path. " +
			"Baseline is DAG-attested — future fim_check calls detect unauthorized modifications.",
		InputSchema: json.RawMessage(`{
			"type": "object",
			"required": ["path"],
			"properties": {
				"path": {
					"type": "string",
					"description": "Directory path to baseline"
				}
			}
		}`),
		Handler: handleFIMBaseline,
	})
}

func handleFIMBaseline(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	path, _ := call.Args["path"].(string)
	if path == "" {
		return nil, nil, fmt.Errorf("fim_baseline: path is required")
	}

	collector := fim.NewFIMCollector(path)
	baseline, err := collector.Collect(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("fim_baseline: %w", err)
	}

	store := getKASAStore()
	node := dag.Node{
		Action: "fim_baseline",
		Symbol: "Eban",
		Time:   lorentz.StampNow(),
		PQC: map[string]string{
			"path":       path,
			"file_count": fmt.Sprintf("%d", len(baseline)),
			"agent":      "FIM-Collector-v1",
		},
	}
	store.Add(&node, []string{}) //nolint:errcheck

	return map[string]any{
		"path":        path,
		"file_count":  len(baseline),
		"baseline":    baseline,
		"dag_attested": true,
		"baselined_at": lorentz.StampNow(),
	}, nil, nil
}

// ── Tool: fim_check ───────────────────────────────────────────────────────────

func init() {
	RegisterTool(mcp.Tool{
		Name: "fim_check",
		Description: "Compute SHA-256 hash of a file for integrity verification. " +
			"Compare against your FIM baseline to detect unauthorized modifications.",
		InputSchema: json.RawMessage(`{
			"type": "object",
			"required": ["file_path"],
			"properties": {
				"file_path": {
					"type": "string",
					"description": "Absolute path to the file to check"
				}
			}
		}`),
		Handler: handleFIMCheck,
	})
}

func handleFIMCheck(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	filePath, _ := call.Args["file_path"].(string)
	if filePath == "" {
		return nil, nil, fmt.Errorf("fim_check: file_path is required")
	}

	hash, err := fim.ComputeSHA256(filePath)
	if err != nil {
		return nil, nil, fmt.Errorf("fim_check: %w", err)
	}

	return map[string]any{
		"file":       filePath,
		"sha256":     hash,
		"checked_at": lorentz.StampNow(),
	}, nil, nil
}

// ── Tool: audit_snapshot ──────────────────────────────────────────────────────

func init() {
	RegisterTool(mcp.Tool{
		Name: "audit_snapshot",
		Description: "Create an AFFiNE system audit snapshot. " +
			"Captures: public IP, running processes, file hashes for critical paths. " +
			"Records to DAG for compliance audit trail. Suitable for continuous compliance monitoring.",
		InputSchema: json.RawMessage(`{"type":"object","properties":{}}`),
		Handler:     handleAuditSnapshot,
	})
}

func handleAuditSnapshot(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	snapshot, err := audit.NewSnapshot(ctx)
	if err != nil {
		return nil, []string{fmt.Sprintf("audit_snapshot warning: %v", err)}, nil
	}

	affine, err := audit.GenerateAFFiNE(snapshot)
	if err != nil {
		return nil, []string{fmt.Sprintf("affine generation warning: %v", err)}, nil
	}

	store := getKASAStore()
	node := dag.Node{
		Action: "audit_snapshot",
		Symbol: "Sankofa",
		Time:   lorentz.StampNow(),
		PQC: map[string]string{
			"agent": "AuditEngine-AFFiNE-v1",
		},
	}
	store.Add(&node, []string{}) //nolint:errcheck

	return map[string]any{
		"snapshot":     snapshot,
		"affine":       affine,
		"dag_attested": true,
		"captured_at":  lorentz.StampNow(),
	}, nil, nil
}

// ── Tool: audit_export ────────────────────────────────────────────────────────

func init() {
	RegisterTool(mcp.Tool{
		Name:        "audit_export",
		Description: "Export an audit report to CSV format for compliance submission or SIEM ingestion.",
		InputSchema: json.RawMessage(`{
			"type": "object",
			"required": ["report_path"],
			"properties": {
				"report_path": {
					"type": "string",
					"description": "Path to the audit report JSON file"
				},
				"output_path": {
					"type": "string",
					"description": "Output CSV path (default: audit_export.csv)"
				}
			}
		}`),
		Handler: handleAuditExport,
	})
}

func handleAuditExport(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	reportPath, _ := call.Args["report_path"].(string)
	outputPath, _ := call.Args["output_path"].(string)
	if reportPath == "" {
		return nil, nil, fmt.Errorf("audit_export: report_path is required")
	}
	if outputPath == "" {
		outputPath = "audit_export.csv"
	}

	report, err := audit.SaveReport(reportPath)
	if err != nil {
		return nil, nil, fmt.Errorf("audit_export load: %w", err)
	}

	if err := audit.ExportToCSV(report, outputPath); err != nil {
		return nil, nil, fmt.Errorf("audit_export csv: %w", err)
	}

	return map[string]any{
		"exported":   true,
		"output":     outputPath,
		"exported_at": lorentz.StampNow(),
	}, nil, nil
}
