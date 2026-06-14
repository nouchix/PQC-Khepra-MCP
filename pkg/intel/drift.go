package intel

import (
	"fmt"
	"strings"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/audit"
)

// DriftReport encapsulates the differences between two states
type DriftReport struct {
	HasDrift         bool     `json:"has_drift"`
	AddedPorts       []string `json:"added_ports,omitempty"`
	RemovedPorts     []string `json:"removed_ports,omitempty"`
	AddedProcesses   []string `json:"added_processes,omitempty"`
	RemovedProcesses []string `json:"removed_processes,omitempty"`
	ChangedFiles     []string `json:"changed_files,omitempty"`
	PQCKeyMismatch   bool     `json:"pqc_key_mismatch,omitempty"`
}

// DriftEngine handles comparison logic
type DriftEngine struct{}

// NewDriftEngine creates a ready-to-use engine
func NewDriftEngine() *DriftEngine {
	return &DriftEngine{}
}

// Compare calculates drift between a "Golden" baseline and the current "Reality"
func (e *DriftEngine) Compare(baseline, current *audit.AuditSnapshot) *DriftReport {
	report := &DriftReport{}

	// 1. Verify Identity (PQC)
	if baseline.PQCSignature != nil && current.PQCSignature != nil {
		if baseline.PQCSignature.PublicKey != current.PQCSignature.PublicKey {
			report.PQCKeyMismatch = true
			report.HasDrift = true
		}
	}

	e.checkNetworkDrift(baseline, current, report)
	e.checkProcessDrift(baseline, current, report)
	e.checkFileManifestDrift(baseline, current, report)

	return report
}

func (e *DriftEngine) checkNetworkDrift(baseline, current *audit.AuditSnapshot, report *DriftReport) {
	basePorts := make(map[string]bool)
	for _, p := range baseline.Network.Ports {
		basePorts[fmt.Sprintf("%d/%s", p.Port, p.Protocol)] = true
	}
	currPorts := make(map[string]bool)
	for _, p := range current.Network.Ports {
		currPorts[fmt.Sprintf("%d/%s", p.Port, p.Protocol)] = true
	}

	for k := range currPorts {
		if !basePorts[k] {
			report.AddedPorts = append(report.AddedPorts, k)
			report.HasDrift = true
		}
	}
	for k := range basePorts {
		if !currPorts[k] {
			report.RemovedPorts = append(report.RemovedPorts, k)
			report.HasDrift = true
		}
	}
}

func (e *DriftEngine) checkProcessDrift(baseline, current *audit.AuditSnapshot, report *DriftReport) {
	baseProcs := make(map[string]bool)
	for _, p := range baseline.System.Processes {
		baseProcs[p.Name] = true
	}
	currProcs := make(map[string]bool)
	for _, p := range current.System.Processes {
		currProcs[p.Name] = true
	}

	for k := range currProcs {
		if !baseProcs[k] {
			report.AddedProcesses = append(report.AddedProcesses, k)
			report.HasDrift = true
		}
	}
	for k := range baseProcs {
		if !currProcs[k] {
			report.RemovedProcesses = append(report.RemovedProcesses, k)
			report.HasDrift = true
		}
	}
}

func (e *DriftEngine) checkFileManifestDrift(baseline, current *audit.AuditSnapshot, report *DriftReport) {
	baseFiles := make(map[string]string)
	for _, f := range baseline.Manifests {
		baseFiles[f.Path] = f.Checksum
	}

	for _, f := range current.Manifests {
		baseHash, exists := baseFiles[f.Path]
		if exists && baseHash != f.Checksum {
			report.ChangedFiles = append(report.ChangedFiles, fmt.Sprintf("%s (Modified)", f.Path))
			report.HasDrift = true
		}
	}
}

// String returns a human-readable summary
func (r *DriftReport) String() string {
	if !r.HasDrift {
		return "SYSTEM INTEGRITY VERIFIED. NO DRIFT DETECTED."
	}
	var sb strings.Builder
	sb.WriteString("DRIFT DETECTED:\n")
	if len(r.AddedPorts) > 0 {
		sb.WriteString(fmt.Sprintf(" [WARN] New Open Ports: %v\n", r.AddedPorts))
	}
	if len(r.AddedProcesses) > 0 {
		sb.WriteString(fmt.Sprintf(" [WARN] New Processes: %v\n", r.AddedProcesses))
	}
	if len(r.ChangedFiles) > 0 {
		sb.WriteString(fmt.Sprintf(" [CRITICAL] File Tampering: %v\n", r.ChangedFiles))
	}
	if r.PQCKeyMismatch {
		sb.WriteString(" [FATAL] PQC IDENTITY MISMATCH! HOST KEY CHANGED.\n")
	}
	return sb.String()
}
