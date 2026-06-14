package compliance

import (
	"fmt"
	"log"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/dag"
)

// Engine orchestrates compliance checks
type Engine struct {
	Manager *Manager
	store   dag.Store
	Checks  []NativeCheck // Built-in platform checks
}

// NewEngine creates a new Compliance Engine
func NewEngine(store dag.Store, scanner ScannerInterface) *Engine {
	e := &Engine{
		Manager: NewManager(store, scanner),
		store:   store,
		Checks:  []NativeCheck{},
	}

	// Load platform-specific checks (defined in checks_windows.go / checks_linux.go)
	e.loadPlatformChecks()

	return e
}

// EvaluateCompliance runs a check across all controls in the SSP
func (e *Engine) EvaluateCompliance(privKey []byte) (string, error) {
	ssp := e.Manager.SSP
	totalControls := 110 // CMMC Level 2
	implemented := 0
	failed := 0

	report := "CMMC Level 2 Compliance Report:\n"

	// Iterate over known controls (mocked list for MVP, usually this iterates over a loaded standard)
	// For this MVP, we iterate over controls present in the SSP
	for _, ctrl := range ssp.Controls {
		// If scanner is available, try to audit real-time status
		if e.Manager.scanner != nil {
			passed, err := e.Manager.AuditControl(ctrl.ControlID, privKey)
			if err != nil {
				log.Printf("Error auditing control %s: %v", ctrl.ControlID, err)
			}
			if !passed {
				failed++
			} else {
				implemented++
			}
		} else {
			// Manual/Static check
			if ctrl.Status == "IMPLEMENTED" {
				implemented++
			}
		}
	}

	score := float64(implemented) / float64(totalControls) * 100
	report += fmt.Sprintf("Score: %.2f%% (%d/%d Controls Implemented)\n", score, implemented, totalControls)
	report += fmt.Sprintf("Critical Failures: %d\n", failed)

	if score < 100 {
		report += "Status: NON-COMPLIANT. Remediation Required."
	} else {
		report += "Status: COMPLIANT. Ready for C3PAO Assessment."
	}

	return report, nil
}

// AutoRemediate attempts to fix failed controls
func (e *Engine) AutoRemediate(privKey []byte) (string, error) {
	if e.Manager.scanner == nil {
		return "Scanner interface not available for remediation.", nil
	}

	fixed := 0
	for _, ctrl := range e.Manager.SSP.Controls {
		if ctrl.Status == "FAILED_SCAN" {
			success, msg, _ := e.Manager.scanner.RemediateControl(ctrl.ControlID)
			if success {
				e.Manager.UpdateControl(ctrl.ControlID, "AUTO_REMEDIATED", msg, privKey)
				fixed++
			}
		}
	}
	return fmt.Sprintf("Auto-Remediation Complete. Fixed %d controls.", fixed), nil
}
