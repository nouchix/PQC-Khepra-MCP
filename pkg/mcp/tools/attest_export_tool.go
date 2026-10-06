package tools

// attest_export_tool.go — MCP handler for attest_export.
//
// Generates the full C3PAO 13-artifact evidence package ZIP from scan findings.
// This is Surface 2 of the KHEPRA evidence system: PQC-Khepra-MCP.
//
// Tool name: attest_export
// Parameters:
//   - target        (string): system target identifier
//   - output_dir    (string, optional): output directory (default: ".")
//   - findings_json (string, optional): JSON array of evidence.Finding structs
//
// Finding sources (priority order):
//  1. findings_json parameter
//  2. ~/.khepra/last_scan.json (written by ert_scan)
//  No findings is an error: a package is never built from example data.
//
// Returns AttestExportResponse with zip_path, sprs_score, manifest_signature.
//
// IP: SOUHIMBOU DOH KONE LLC, exclusively licensed to SecRed Knowledge Inc.
// Patent: U.S. App. No. 63/942,886 (KHEPRA Protocol)

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/nouchix/PQC-Khepra-MCP/pkg/evidence"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/mcp"
)

// AttestExportResponse is the structured JSON output of attest_export.
type AttestExportResponse struct {
	ZipPath          string  `json:"zip_path"`
	SPRSScore        int     `json:"sprs_score"`
	SPRSDeduction    int     `json:"sprs_deduction"`
	ArtifactCount    int     `json:"artifact_count"`
	FindingsCount    int     `json:"findings_count"`
	TotalExposureUSD float64 `json:"total_exposure_usd"`
	ManifestSig      string  `json:"manifest_signature"`
	GeneratedAt      string  `json:"generated_at"`
	Target           string  `json:"target"`
	Framework        string  `json:"framework"`
}

// HandleAttestExport is the MCP handler for attest_export.
func HandleAttestExport(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	target, _ := call.Args["target"].(string)
	if target == "" {
		target = "unknown"
	}
	outputDir, _ := call.Args["output_dir"].(string)
	if outputDir == "" {
		outputDir = "."
	}
	findingsJSONArg, _ := call.Args["findings_json"].(string)

	// Source 1: findings_json parameter
	var findings []evidence.Finding
	if findingsJSONArg != "" {
		if err := json.Unmarshal([]byte(findingsJSONArg), &findings); err != nil {
			return nil, nil, fmt.Errorf("attest_export: invalid findings_json: %w", err)
		}
	}

	// Source 2: last scan file fallback (~/.khepra/last_scan.json)
	if len(findings) == 0 {
		home, _ := os.UserHomeDir()
		scanFile := filepath.Join(home, ".khepra", "last_scan.json")
		if data, err := os.ReadFile(scanFile); err == nil {
			var lastScan struct {
				Findings []evidence.Finding `json:"findings"`
				Target   string             `json:"target"`
			}
			if jsonErr := json.Unmarshal(data, &lastScan); jsonErr == nil && len(lastScan.Findings) > 0 {
				findings = lastScan.Findings
				if target == "unknown" && lastScan.Target != "" {
					target = lastScan.Target
				}
			}
		}
	}

	// No real findings: there is nothing to attest. (A package must never be
	// built from example findings and labelled with the caller's target.)
	if len(findings) == 0 {
		return nil, nil, fmt.Errorf("attest_export: no findings — supply findings or run a scan first (~/.khepra/last_scan.json)")
	}

	// Build the 13-artifact C3PAO evidence ZIP
	pkg, err := evidence.Build(evidence.BuildConfig{
		Findings:  findings,
		Target:    target,
		OutputDir: outputDir,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("attest_export: build failed: %w", err)
	}

	resp := &AttestExportResponse{
		ZipPath:          pkg.ZipPath,
		SPRSScore:        pkg.SPRS.Score,
		SPRSDeduction:    pkg.SPRS.Deduction,
		ArtifactCount:    pkg.ArtifactCount,
		FindingsCount:    len(pkg.Findings),
		TotalExposureUSD: pkg.TotalExposure,
		ManifestSig:      pkg.ManifestSignature,
		GeneratedAt:      pkg.Generated.UTC().Format(time.RFC3339),
		Target:           pkg.Target,
		Framework:        pkg.Framework,
	}
	return resp, []string{
		fmt.Sprintf("C3PAO evidence package: %s", pkg.ZipPath),
		fmt.Sprintf("SPRS Score: %d / 110 (%s) — -%d points", pkg.SPRS.Score, pkg.SPRS.PassFail, pkg.SPRS.Deduction),
		fmt.Sprintf("%d artifacts | %d findings | $%.0f exposure | manifest: %s", pkg.ArtifactCount, len(pkg.Findings), pkg.TotalExposure, manifestSigLabel(pkg.ManifestSignature)),
		"Unzip and open 12-dag-viewer.html for visual DAG evidence",
	}, nil
}

// manifestSigLabel states whether the package manifest is signed.
func manifestSigLabel(sig string) string {
	if strings.HasPrefix(sig, "ML-DSA-87:") {
		return "ML-DSA-87 signed"
	}
	return "UNSIGNED (no signing key configured)"
}
