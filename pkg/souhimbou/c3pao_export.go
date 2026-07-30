package souhimbou

// c3pao_export.go — GenerateC3PAOPackage: Surface 3 of the KHEPRA C3PAO evidence system.
//
// Exposes the 13-artifact C3PAO evidence package from the SouHimBou AI Core Agent.
// Reads flight frames from the embedded Recorder, KASA anomaly scores from the
// KASA engine, and maps them to CMMC findings via pkg/evidence.
//
// Usage:
//
//	pkg, err := agent.GenerateC3PAOPackage(souhimbou.C3PAOExportConfig{
//	    OutputDir:     "./evidence",
//	    ExtraFindings: kasaFindings,
//	})
//
// IP: SOUHIMBOU DOH KONE LLC, exclusively licensed to SecRed Knowledge Inc.
// Patent: USPTO #73565085 (KHEPRA Protocol)

import (
	"fmt"

	"github.com/nouchix/PQC-Khepra-MCP/pkg/dag"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/evidence"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/flight"
)

// C3PAOExportConfig controls what GenerateC3PAOPackage generates.
type C3PAOExportConfig struct {
	// OutputDir is where the ZIP will be written (default: ".").
	OutputDir string

	// ExtraFindings are CMMC findings from the KASA threat detector.
	ExtraFindings []evidence.Finding

	// ESPs are External Service Providers from the Sonar scan.
	ESPs []evidence.ESP
}

// GenerateC3PAOPackage generates a full C3PAO 13-artifact evidence ZIP from
// the SouHimBou agent's operational history.
//
// It:
//  1. Reads the Flight Recorder's NDJSON log (artifact 06)
//  2. Synthesizes CMMC findings from control mappings in flight frames
//  3. Appends ExtraFindings from the KASA threat detector
//  4. Calls pkg/evidence.Build() for the 13-artifact ZIP
//  5. Records the export event in the immutable DAG
//
// The resulting ZIP can be opened by a C3PAO assessor as the complete
// Examine + Test evidence package for CMMC Level 2.
func (a *Agent) GenerateC3PAOPackage(cfg C3PAOExportConfig) (*evidence.C3PAOPackage, error) {
	if a.orch == nil || a.orch.Flight == nil {
		return nil, fmt.Errorf("souhimbou: flight recorder not initialised")
	}
	if cfg.OutputDir == "" {
		cfg.OutputDir = "."
	}

	target := fmt.Sprintf("souhimbou-ai://%s", a.cfg.AgentID)

	// Delegate to flight.ExportEvidencePackage (Surface 3 core)
	pkg, err := a.orch.Flight.ExportEvidencePackage(flight.ExportConfig{
		Target:        target,
		OutputDir:     cfg.OutputDir,
		ExtraFindings: cfg.ExtraFindings,
		ESPs:          cfg.ESPs,
	})
	if err != nil {
		return nil, fmt.Errorf("souhimbou: c3pao export: %w", err)
	}

	// Record the evidence export in the DAG as a signed audit node
	if a.orch.DAG != nil {
		n := &dag.Node{
			Action: "C3PAO_EVIDENCE_EXPORT",
			Symbol: string(SymbolNkyinkyim),
			Time:   pkg.Generated.Format("2006-01-02T15:04:05Z"),
			PQC: map[string]string{
				"package_id":   pkg.PackageID,
				"sprs_score":   fmt.Sprintf("%d", pkg.SPRS.Score),
				"zip_path":     pkg.ZipPath,
				"manifest_sig": pkg.ManifestSignature,
			},
		}
		a.orch.DAG.Add(n, nil) //nolint:errcheck
	}

	return pkg, nil
}
