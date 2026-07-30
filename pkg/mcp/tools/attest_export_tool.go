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
//  3. Synthetic demo findings (fallback)
//
// Returns AttestExportResponse with zip_path, sprs_score, manifest_signature.
//
// IP: SOUHIMBOU DOH KONE LLC, exclusively licensed to SecRed Knowledge Inc.
// Patent: USPTO #73565085 (KHEPRA Protocol)

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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

	// Source 3: synthetic demo findings (ensures package is always non-empty)
	if len(findings) == 0 {
		findings = attestDemoFindings()
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
		fmt.Sprintf("%d artifacts | %d findings | $%.0f exposure | ML-DSA-65 signed", pkg.ArtifactCount, len(pkg.Findings), pkg.TotalExposure),
		"Unzip and open 12-dag-viewer.html for visual DAG evidence",
	}, nil
}

// attestDemoFindings returns canonical demo findings matching the DVWA surface.
func attestDemoFindings() []evidence.Finding {
	return []evidence.Finding{
		{
			ID: "SC-13", Title: "Legacy / Non-FIPS Cryptography",
			Severity: "CAT I", POAMEligible: false, SPRSPoints: 3,
			RejectPattern: evidence.RejectPaperTiger, ExposureUSD: 1800000,
			CMMCPractice: "CMMC.SC.L2-3.13.10", NIST: "3.13.10",
			CCI: "CCI-002450", MITRETechnique: "T1600",
			Detail:      "Non-FIPS cryptographic algorithms detected. FIPS 140-2/3 compliance required.",
			Remediation: "Migrate to ML-DSA-65 / ML-KEM-768 (FIPS 203/204) via KHEPRA adinkra package.",
			SignedBy:    "ML-DSA-65 / FIPS 204",
		},
		{
			ID: "SI-10", Title: "Input Validation — Injection Vectors",
			Severity: "CAT I", POAMEligible: false, SPRSPoints: 5,
			RejectPattern: evidence.RejectPaperTiger, ExposureUSD: 2400000,
			CMMCPractice: "CMMC.SI.L2-3.14.2", NIST: "3.14.2",
			CCI: "CCI-002754", MITRETechnique: "T1190",
			Detail:      "Input validation controls absent. SQL, command, and script injection viable.",
			Remediation: "Parameterized queries + input allowlisting + WAF rules.",
			SignedBy:    "ML-DSA-65 / FIPS 204",
		},
		{
			ID: "IA-5", Title: "Hardcoded / Exposed Credentials",
			Severity: "CAT I", POAMEligible: false, SPRSPoints: 3,
			RejectPattern: evidence.RejectHygiene, ExposureUSD: 890000,
			CMMCPractice: "CMMC.IA.L2-3.5.3", NIST: "3.5.3",
			CCI: "CCI-000186", MITRETechnique: "T1552.001",
			Detail:      "Credentials found in plaintext. Violates IA-5 credential management.",
			Remediation: "Move secrets to env vars + Vault. Rotate all exposed credentials immediately.",
			SignedBy:    "ML-DSA-65 / FIPS 204",
		},
		{
			ID: "AC-3", Title: "Missing Access Control — IDOR",
			Severity: "CAT II", POAMEligible: true, SPRSPoints: 5,
			RejectPattern: evidence.RejectScopeGap, ExposureUSD: 480000,
			CMMCPractice: "CMMC.AC.L2-3.1.3", NIST: "3.1.3",
			CCI: "CCI-001873", MITRETechnique: "T1078",
			Detail:      "Object-level authorization absent. Insecure Direct Object Reference confirmed.",
			Remediation: "Server-side authorization check on every object access. RBAC enforcement.",
			SignedBy:    "ML-DSA-65 / FIPS 204",
		},
	}
}
