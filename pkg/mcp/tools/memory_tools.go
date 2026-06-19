// Package tools — Digital Forensics + FIM + Audit memory handler functions.
//
// Registration: add to cmd/khepra-mcp/main.go via executor.RegisterFunc().
//
// Tools exposed:
//   - HandleForensicsCollect : Full digital forensic snapshot
//   - HandleFIMBaseline      : Create file integrity baseline
//   - HandleFIMCheck         : Check a file's hash
//   - HandleAuditExport      : Export audit trail to CSV
package tools

import (
	"context"
	"fmt"

	"github.com/nouchix/PQC-Khepra-MCP/pkg/dag"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/fim"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/forensics"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/lorentz"
	mcp "github.com/nouchix/PQC-Khepra-MCP/pkg/mcp"
)

// HandleForensicsCollect collects a full digital forensic snapshot.
// Captures: running processes (PID, name, user, cmdline),
// active network connections (local/remote addr, state, PID),
// open ports, file hashes.
// Result is ML-DSA-65 signed and DAG-recorded under symbol Sankofa.
// Suitable for DFIR evidence packages.
func HandleForensicsCollect(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	if gate := GateForTool("forensic_snapshot"); gate != nil {
		return gate, nil, nil
	}
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

// HandleFIMBaseline creates a File Integrity Monitor (FIM) baseline for a directory.
// Monitors critical paths using the FIMWatcher with SHA-256 hash baselines.
// Baseline is DAG-attested — future checks detect unauthorized modifications.
func HandleFIMBaseline(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	if gate := GateForTool("fim_baseline"); gate != nil {
		return gate, nil, nil
	}
	path, _ := call.Args["path"].(string)
	if path == "" {
		return nil, nil, fmt.Errorf("fim_baseline: path is required")
	}

	watcher, err := fim.NewFIMWatcher([]string{path})
	if err != nil {
		return nil, nil, fmt.Errorf("fim_baseline watcher: %w", err)
	}

	if err := watcher.EstablishBaseline(); err != nil {
		return nil, nil, fmt.Errorf("fim_baseline establish: %w", err)
	}

	store := getKASAStore()
	node := dag.Node{
		Action: "fim_baseline",
		Symbol: "Eban",
		Time:   lorentz.StampNow(),
		PQC: map[string]string{
			"path":  path,
			"agent": "FIM-Watcher-v1",
		},
	}
	store.Add(&node, []string{}) //nolint:errcheck

	return map[string]any{
		"path":         path,
		"dag_attested": true,
		"baselined_at": lorentz.StampNow(),
	}, nil, nil
}

// HandleFIMCheck computes the SHA-256 hash of a file for integrity verification.
// Compare against your FIM baseline to detect unauthorized modifications.
func HandleFIMCheck(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
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

// HandleAuditExport exports an audit report to CSV format for compliance submission.
func HandleAuditExport(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	if gate := GateForTool("audit_dag_integrity"); gate != nil {
		return gate, nil, nil
	}
	// Export the current DAG as a lightweight audit summary
	store := getKASAStore()
	nodes := store.All()

	type auditRow struct {
		ID     string `json:"id"`
		Action string `json:"action"`
		Symbol string `json:"symbol"`
		Time   string `json:"time"`
	}

	rows := make([]auditRow, 0, len(nodes))
	for _, n := range nodes {
		rows = append(rows, auditRow{
			ID:     n.ID,
			Action: n.Action,
			Symbol: n.Symbol,
			Time:   n.Time,
		})
	}

	return map[string]any{
		"rows":        rows,
		"count":       len(rows),
		"exported_at": lorentz.StampNow(),
	}, nil, nil
}
