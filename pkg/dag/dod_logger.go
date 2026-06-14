package dag

import (
	"fmt"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/logging"
)

// LogDAGEventToDoD logs a DAG event to the DoD-compliant logger
// This provides comprehensive observability and audit trails for:
// - Compliance audits (NIST, CMMC, STIG)
// - Forensic analysis
// - Incident response
// - Threat hunting
func LogDAGEventToDoD(logger *logging.DoDLogger, node *Node, eventType string) error {
	if logger == nil {
		// Silent failure - logging is optional
		return nil
	}

	// Map event types to DoD log methods
	logMsg := fmt.Sprintf("[DAG] %s", eventType)

	switch eventType {
	case "dag_node_added":
		logger.Info(logMsg, "node_id", node.ID, "action", node.Action, "symbol", node.Symbol)
	case "dag_genesis_created":
		logger.Info(logMsg, "node_id", node.ID, "pqc_enabled", true)
	case "dag_integrity_violation":
		logger.Error(logMsg, "node_id", node.ID, "hash", node.Hash)
	case "dag_orphaned_node":
		logger.Warn(logMsg, "node_id", node.ID, "parents", fmt.Sprintf("%v", node.Parents))
	case "dag_flushed_to_disk":
		logger.Debug(logMsg, "node_id", node.ID)
	case "dag_loaded_from_disk":
		logger.Info(logMsg, "node_id", node.ID)
	default:
		logger.Info(logMsg, "node_id", node.ID)
	}

	return nil
}

// LogDAGStatsToDoD logs DAG statistics to DoD logger (for periodic health checks)
func LogDAGStatsToDoD(logger *logging.DoDLogger, store Store) error {
	if logger == nil {
		return nil
	}

	allNodes := store.All()

	stats := map[string]interface{}{
		"total_nodes": len(allNodes),
		"signed_nodes": 0,
		"event_types": make(map[string]int),
	}

	for _, node := range allNodes {
		if node.Signature != "" {
			stats["signed_nodes"] = stats["signed_nodes"].(int) + 1
		}

		eventType := node.Action
		counts := stats["event_types"].(map[string]int)
		counts[eventType]++
	}

	logger.Info("[DAG] Stats",
		"total_nodes", len(allNodes),
		"signed_nodes", stats["signed_nodes"],
		"event_types", fmt.Sprintf("%v", stats["event_types"]))
	return nil
}

// AuditDAGIntegrity performs a comprehensive integrity check and logs to DoD logger
// This is critical for compliance audits and forensic investigations
func AuditDAGIntegrity(logger *logging.DoDLogger, store Store) (passed bool, violations []string) {
	allNodes := store.All()
	violations = []string{}

	for _, node := range allNodes {
		// Check 1: Content hash matches ID
		computedHash := node.ComputeHash()
		if node.ID != computedHash {
			// Allow legacy IDs (task-, scan-, etc.)
			if node.ID[:5] != "task-" && node.ID[:5] != "scan-" && node.ID[:6] != "asset:" && node.ID[:9] != "evidence:" && node.ID[:5] != "stig:" {
				violation := fmt.Sprintf("Node %s: Hash mismatch (expected %s, got %s)", node.ID, computedHash, node.ID)
				violations = append(violations, violation)
			}
		}

		// Check 2: Parent references exist
		for _, parentID := range node.Parents {
			if _, exists := store.Get(parentID); !exists {
				violation := fmt.Sprintf("Node %s: Orphaned (parent %s not found)", node.ID, parentID)
				violations = append(violations, violation)
			}
		}

		// Check 3: Signature present for non-legacy nodes
		if node.Signature == "" && node.Action != "GENESIS_CONSTELLATION" {
			// Log warning but don't fail audit (signature may be optional for some nodes)
			if logger != nil {
				logger.Warn("[DAG] Node has no PQC signature", "node_id", node.ID)
			}
		}
	}

	passed = len(violations) == 0

	// Log audit result to DoD logger
	if logger != nil {
		if passed {
			logger.Info("[DAG] Integrity audit PASSED", "nodes_checked", len(allNodes))
		} else {
			logger.Error("[DAG] Integrity audit FAILED", "violations_found", len(violations))
			for _, v := range violations {
				logger.Error("[DAG] Violation", "detail", v)
			}
		}
	}

	return passed, violations
}
