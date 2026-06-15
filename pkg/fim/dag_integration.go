package fim

import (
	"fmt"
	"time"

	"github.com/nouchix/PQC-Khepra-MCP/pkg/dag"
)

// GenerateDAGNode creates a DAG node from a FIM event.
// Node fields: ID=fim:{type}:{path}:{unix}, Action="fim_violation", Symbol="integrity", Time=RFC3339.
func (event *FIMEvent) GenerateDAGNode(hostname string) *dag.Node {
	nodeID := fmt.Sprintf("fim:%s:%s:%d", event.EventType, event.FilePath, event.Timestamp.Unix())

	node := &dag.Node{
		ID:     nodeID,
		Action: "fim_violation",
		Symbol: "integrity",
		Time:   event.Timestamp.Format(time.RFC3339),
	}

	// Link to parent nodes (after refactoring is complete)
	// parents := []string{fmt.Sprintf("asset:host:%s", hostname)}
	// if event.STIGControl != "" {
	// 	parents = append(parents, fmt.Sprintf("stig:control:%s", event.STIGControl))
	// }
	// node.Parents = parents

	return node
}

// FIMCollector collects FIM events and generates DAG nodes
type FIMCollector struct {
	watcher  *FIMWatcher
	dag      *dag.Memory
	hostname string
	stopCh   chan struct{}
}

// NewFIMCollector creates a new FIM event collector
func NewFIMCollector(watcher *FIMWatcher, dagInstance *dag.Memory, hostname string) *FIMCollector {
	return &FIMCollector{
		watcher:  watcher,
		dag:      dagInstance,
		hostname: hostname,
		stopCh:   make(chan struct{}),
	}
}

// Start begins collecting FIM events and adding them to the DAG
func (fc *FIMCollector) Start() {
	go fc.collectLoop()
}

// collectLoop processes FIM events and generates DAG nodes
func (fc *FIMCollector) collectLoop() {
	for {
		select {
		case event := <-fc.watcher.Events():
			node := event.GenerateDAGNode(fc.hostname)

			// Add node to DAG
			if err := fc.dag.Add(node, nil); err != nil {
				// Log error but don't stop
				fmt.Printf("[FIM] Failed to add DAG node: %v\n", err)
			}

			// Generate alert for CRITICAL events
			if event.Severity == "CRITICAL" {
				fc.generateAlert(event)
			}

		case err := <-fc.watcher.Errors():
			// Log error
			fmt.Printf("[FIM] Watcher error: %v\n", err)

		case <-fc.stopCh:
			return
		}
	}
}

// generateAlert creates an alert for critical FIM events
func (fc *FIMCollector) generateAlert(event FIMEvent) {
	alert := map[string]interface{}{
		"alert_type":   "FIM_VIOLATION",
		"severity":     event.Severity,
		"file_path":    event.FilePath,
		"event_type":   event.EventType,
		"timestamp":    event.Timestamp,
		"stig_control": event.STIGControl,
		"message":      fmt.Sprintf("CRITICAL: %s on %s", event.Description, event.FilePath),
	}

	// In production, this would send to SIEM/alerting system
	fmt.Printf("[ALERT] %v\n", alert)
}

// Stop halts the FIM collector
func (fc *FIMCollector) Stop() {
	close(fc.stopCh)
}

// GetRecentViolations returns FIM violations from the DAG within a time window
func (fc *FIMCollector) GetRecentViolations(since time.Duration) ([]*dag.Node, error) {
	cutoff := time.Now().Add(-since)

	var violations []*dag.Node

	// Query DAG for FIM violation nodes using dag.Memory.All().
	if fc.dag != nil {
		for _, node := range fc.dag.All() {
			// Parse time string to compare
			nodeTime, err := time.Parse(time.RFC3339, node.Time)
			if err != nil {
				continue
			}

			if node.Action == "fim_violation" && nodeTime.After(cutoff) {
				violations = append(violations, node)
			}
		}
	}

	return violations, nil
}
