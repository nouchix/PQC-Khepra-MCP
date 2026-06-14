package tools

// Package tools — ert_packages.go
//
// MCP in-process tool wrappers for the four ERT CLI Packages (A–D).
// These expose the same logic as cmd/adinkhepra/* but as structured JSON
// suitable for AI tool consumption, with no ANSI terminal output.
//
// Tools registered here:
//   - ert_readiness   (Package A — Mission Assurance Modeling)
//   - ert_architect   (Package B — Supply Chain Hunter)
//   - ert_crypto      (Package C — PQC Attestation)
//   - ert_godfather   (Package D — Causal Risk Attestation)

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/compliance/nist80171"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/dag"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/ea"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/mcp"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/sca"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/vuln"
)

// ─────────────────────────────────────────────────────────────────────────────
// Package A — ert_readiness (Mission Assurance Modeling)
// ─────────────────────────────────────────────────────────────────────────────

// ReadinessResponse is the structured JSON output of ert_readiness.
type ReadinessResponse struct {
	ProjectPath      string                       `json:"project_path"`
	AlignmentScore   int                          `json:"alignment_score"`
	RiskLevel        string                       `json:"risk_level"`
	ComplianceSummary nist80171.ComplianceSummary `json:"compliance_summary"`
	FailedControls   []ControlGap                 `json:"failed_controls"`
	SCAPenalty       int                          `json:"sca_penalty"`
	Roadmap          []RoadmapItem                `json:"roadmap"`
	ScannedAt        string                       `json:"scanned_at"`
}

// ControlGap describes a NIST 800-171 control failure.
type ControlGap struct {
	ControlID   string `json:"control_id"`
	Title       string `json:"title"`
	Family      string `json:"family"`
	Finding     string `json:"finding"`
	Remediation string `json:"remediation"`
}

// RoadmapItem is a prioritized remediation action.
type RoadmapItem struct {
	Priority string `json:"priority"`
	Action   string `json:"action"`
	Control  string `json:"control"`
}

// HandleERTReadiness is the MCP handler for ert_readiness.
func HandleERTReadiness(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	projectPath, _ := call.Args["project_path"].(string)
	if projectPath == "" {
		projectPath = "."
	}
	absPath, err := filepath.Abs(projectPath)
	if err != nil {
		return nil, nil, fmt.Errorf("ert_readiness: invalid path: %w", err)
	}

	// NIST 800-171 assessment
	v := nist80171.NewValidator()
	controlResults := v.ValidateACFamily()

	summary := nist80171.ComplianceSummary{
		TotalControls:   len(controlResults),
		BaselineVersion: "Rev 2",
	}
	var gaps []ControlGap
	for _, r := range controlResults {
		switch r.Status {
		case "PASS":
			summary.Passed++
		case "FAIL":
			summary.Failed++
			gaps = append(gaps, ControlGap{
				ControlID:   r.ControlID,
				Title:       r.Title,
				Family:      r.Family,
				Finding:     r.Finding,
				Remediation: r.Remediation,
			})
		case "MANUAL_REVIEW":
			summary.ManualReview++
		case "NOT_APPLICABLE":
			summary.NotApplicable++
		}
	}
	if summary.TotalControls > 0 {
		partial := float64(summary.Passed) + float64(summary.ManualReview)*0.5
		summary.Score = partial / float64(summary.TotalControls) * 100.0
	}

	// SCA risk penalty
	scaPenalty := 0
	var warnings []string
	if scaBinaryAvailable("syft") && scaBinaryAvailable("grype") {
		feedMgr := vuln.NewIntelFeedManager()
		pipeline := sca.NewPipeline(feedMgr)
		scanCtx, cancel := context.WithTimeout(ctx, 3*time.Minute)
		defer cancel()
		if result, err := pipeline.ScanAndEnrich(scanCtx, absPath); err == nil {
			for _, f := range result.Findings {
				if f.InCISAKEV {
					scaPenalty += 3
				} else {
					switch strings.ToUpper(f.Severity) {
					case "CRITICAL":
						scaPenalty += 3
					case "HIGH":
						scaPenalty += 2
					case "MEDIUM":
						scaPenalty += 1
					}
				}
				if scaPenalty >= 20 {
					break
				}
			}
			if scaPenalty > 20 {
				scaPenalty = 20
			}
			if result.HighRiskCount > 0 {
				warnings = append(warnings, fmt.Sprintf("%d high-risk supply chain vulnerabilities — apply SCA penalty -%d pts", result.HighRiskCount, scaPenalty))
			}
		}
	}

	// Alignment score
	base := int(summary.Score * 0.8)
	bonus := 0
	if summary.Passed > 0 {
		bonus += 10
	}
	if summary.TotalControls > 0 && float64(summary.Failed)/float64(summary.TotalControls) < 0.05 {
		bonus += 10
	}
	score := base + bonus - scaPenalty
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	roadmap := buildRoadmap(summary, score)

	if summary.Failed > 0 {
		warnings = append(warnings, fmt.Sprintf("%d NIST 800-171 control failures", summary.Failed))
	}

	return &ReadinessResponse{
		ProjectPath:       absPath,
		AlignmentScore:    score,
		RiskLevel:         executiveRiskLevel(score),
		ComplianceSummary: summary,
		FailedControls:    gaps,
		SCAPenalty:        scaPenalty,
		Roadmap:           roadmap,
		ScannedAt:         time.Now().UTC().Format(time.RFC3339),
	}, warnings, nil
}

func executiveRiskLevel(score int) string {
	switch {
	case score < 40:
		return "CRITICAL"
	case score < 60:
		return "HIGH"
	case score < 80:
		return "MODERATE"
	default:
		return "LOW"
	}
}

func buildRoadmap(summary nist80171.ComplianceSummary, score int) []RoadmapItem {
	items := []RoadmapItem{}
	if summary.Failed > 0 {
		items = append(items, RoadmapItem{
			Priority: "URGENT",
			Action:   fmt.Sprintf("Remediate %d failing NIST 800-171 controls", summary.Failed),
			Control:  "CMMC Level 2 prerequisite",
		})
	}
	if summary.ManualReview > 0 {
		items = append(items, RoadmapItem{
			Priority: "HIGH",
			Action:   fmt.Sprintf("Complete attestation for %d manual-review controls", summary.ManualReview),
			Control:  "DFARS 252.204-7012",
		})
	}
	if score < 70 {
		items = append(items, RoadmapItem{
			Priority: "STRATEGIC",
			Action:   "Deploy STIG Validation Pipeline",
			Control:  "NIST 800-171 3.11.2",
		})
	}
	items = append(items, RoadmapItem{
		Priority: "STRATEGIC",
		Action:   "PQC Migration — ML-KEM-768 + ML-DSA-65",
		Control:  "NIST 800-171 3.13.10",
	})
	items = append(items, RoadmapItem{
		Priority: "FOUNDATIONAL",
		Action:   "Continuous Compliance Monitoring (AdinKhepra Agent)",
		Control:  "CMMC AC.2.006, CM.2.061",
	})
	return items
}

// ─────────────────────────────────────────────────────────────────────────────
// Package B — ert_architect (Supply Chain Hunter)
// ─────────────────────────────────────────────────────────────────────────────

// ArchitectResponse is the structured JSON output of ert_architect.
type ArchitectResponse struct {
	ProjectPath        string              `json:"project_path"`
	SBOMComponents     int                 `json:"sbom_components"`
	TotalFindings      int                 `json:"total_findings"`
	HighRiskCount      int                 `json:"high_risk_count"`
	CISAKEVCount       int                 `json:"cisa_kev_count"`
	Findings           []SupplyChainFinding `json:"findings"`
	ScannerMeta        sca.ScannerMetadata  `json:"scanner_meta"`
	FallbackMode       bool                `json:"fallback_mode"`
	Duration           string              `json:"duration"`
	ScannedAt          string              `json:"scanned_at"`
}

// SupplyChainFinding is an MCP-safe projection of sca.EnrichedFinding.
type SupplyChainFinding struct {
	Component       string   `json:"component"`
	Version         string   `json:"version"`
	CVEID           string   `json:"cve_id"`
	Severity        string   `json:"severity"`
	CVSSv3          float64  `json:"cvss_v3"`
	EPSSScore       float64  `json:"epss_score"`
	EPSSPercentile  float64  `json:"epss_percentile"`
	InCISAKEV       bool     `json:"in_cisa_kev"`
	InTheWild       bool     `json:"in_the_wild"`
	PoCAvailable    bool     `json:"poc_available"`
	MITRETechniques []string `json:"mitre_techniques,omitempty"`
	NIST171Controls []string `json:"nist_171_controls,omitempty"`
	RiskScore       float64  `json:"risk_score"`
}

// HandleERTArchitect is the MCP handler for ert_architect.
func HandleERTArchitect(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	projectPath, _ := call.Args["project_path"].(string)
	if projectPath == "" {
		projectPath = "."
	}
	absPath, err := filepath.Abs(projectPath)
	if err != nil {
		return nil, nil, fmt.Errorf("ert_architect: invalid path: %w", err)
	}

	var warnings []string
	fallback := false

	if !scaBinaryAvailable("syft") || !scaBinaryAvailable("grype") {
		fallback = true
		warnings = append(warnings, "syft or grype not in PATH — returning empty SBOM. Install for full SCA coverage.")
		return &ArchitectResponse{
			ProjectPath:  absPath,
			FallbackMode: true,
			ScannedAt:    time.Now().UTC().Format(time.RFC3339),
		}, warnings, nil
	}

	feedMgr := vuln.NewIntelFeedManager()
	pipeline := sca.NewPipeline(feedMgr)

	docsDir := filepath.Join(absPath, "docs")
	pipeline.LoadComplianceData(docsDir)

	scanCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	result, err := pipeline.ScanAndEnrich(scanCtx, absPath)
	if err != nil {
		return nil, nil, fmt.Errorf("ert_architect: SCA pipeline failed: %w", err)
	}

	// Sort by risk score descending
	sort.Slice(result.Findings, func(i, j int) bool {
		return result.Findings[i].RiskScore() > result.Findings[j].RiskScore()
	})

	// Cap at 50 findings for MCP response size limits
	displayLimit := 50
	if len(result.Findings) < displayLimit {
		displayLimit = len(result.Findings)
	}

	kevCount := 0
	mFindings := make([]SupplyChainFinding, 0, displayLimit)
	for _, f := range result.Findings[:displayLimit] {
		if f.InCISAKEV {
			kevCount++
		}
		mFindings = append(mFindings, SupplyChainFinding{
			Component:       f.Component,
			Version:         f.Version,
			CVEID:           f.CVEID,
			Severity:        f.Severity,
			CVSSv3:          f.CVSSv3Score,
			EPSSScore:       f.EPSSScore,
			EPSSPercentile:  f.EPSSPercentile,
			InCISAKEV:       f.InCISAKEV,
			InTheWild:       f.InTheWild,
			PoCAvailable:    f.PoCAvailable,
			MITRETechniques: f.MITRETechniques,
			NIST171Controls: f.NIST171Controls,
			RiskScore:       f.RiskScore(),
		})
	}

	if result.HighRiskCount > 0 {
		warnings = append(warnings, fmt.Sprintf("%d HIGH/CRITICAL supply chain vulnerabilities — immediate remediation required", result.HighRiskCount))
	}
	if kevCount > 0 {
		warnings = append(warnings, fmt.Sprintf("%d CISA KEV findings — actively exploited in the wild", kevCount))
	}

	return &ArchitectResponse{
		ProjectPath:    absPath,
		SBOMComponents: result.SBOMComponentCount,
		TotalFindings:  result.TotalCount,
		HighRiskCount:  result.HighRiskCount,
		CISAKEVCount:   kevCount,
		Findings:       mFindings,
		ScannerMeta:    result.ScannerMeta,
		FallbackMode:   fallback,
		Duration:       result.Duration.Round(time.Millisecond).String(),
		ScannedAt:      time.Now().UTC().Format(time.RFC3339),
	}, warnings, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Package C — ert_crypto (PQC Attestation)
// ─────────────────────────────────────────────────────────────────────────────

// CryptoResponse is the structured JSON output of ert_crypto.
type CryptoResponse struct {
	ProjectPath      string            `json:"project_path"`
	SourceScan       CryptoSourceScan  `json:"source_scan"`
	SBOMCryptoLibs   []SBOMCryptoEntry `json:"sbom_crypto_libs"`
	WeakPrimitives   []WeakPrimEntry   `json:"weak_primitives"`
	PQCMigrationPath []string          `json:"pqc_migration_path"`
	QuantumRisk      string            `json:"quantum_risk_summary"`
	ScannedAt        string            `json:"scanned_at"`
}

// CryptoSourceScan contains source-level primitive counts.
type CryptoSourceScan struct {
	RSARefs       int  `json:"rsa_refs"`
	ECDSARefs     int  `json:"ecdsa_refs"`
	AESRefs       int  `json:"aes_refs"`
	SHARefs       int  `json:"sha_refs"`
	KyberRefs     int  `json:"kyber_refs"`
	DilithiumRefs int  `json:"dilithium_refs"`
	HasLegacy     bool `json:"has_legacy"`
	HasPQC        bool `json:"has_pqc"`
}

// SBOMCryptoEntry is a crypto-relevant SBOM component.
type SBOMCryptoEntry struct {
	Name       string `json:"name"`
	Version    string `json:"version"`
	Ecosystem  string `json:"ecosystem"`
	PQCCapable bool   `json:"pqc_capable"`
	Weak       bool   `json:"weak"`
	Note       string `json:"note"`
}

// WeakPrimEntry is a detected weak cryptographic primitive.
type WeakPrimEntry struct {
	Pattern  string `json:"pattern"`
	File     string `json:"file"`
	Line     int    `json:"line"`
	Severity string `json:"severity"`
	Reason   string `json:"reason"`
}

// HandleERTCrypto is the MCP handler for ert_crypto.
func HandleERTCrypto(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	projectPath, _ := call.Args["project_path"].(string)
	if projectPath == "" {
		projectPath = "."
	}
	absPath, err := filepath.Abs(projectPath)
	if err != nil {
		return nil, nil, fmt.Errorf("ert_crypto: invalid path: %w", err)
	}

	var warnings []string

	// Source-level scan (string matching in .go files)
	source := scanCryptoSource(absPath)

	// SBOM-level scan (conditional on tools)
	var sbomLibs []SBOMCryptoEntry
	if scaBinaryAvailable("syft") && scaBinaryAvailable("grype") {
		sbomLibs = scanSBOMForCryptoLibs(ctx, absPath)
	} else {
		warnings = append(warnings, "syft+grype not in PATH — SBOM crypto library inventory skipped")
	}

	// Weak primitive detection
	weak := detectCryptoWeakness(absPath)

	// Migration path
	migrationPath := []string{
		"RSA → ML-KEM-768 (NIST FIPS 203)",
		"ECDSA → ML-DSA-65 (NIST FIPS 204)",
		"SHA-1 → SHA-3-256 (NIST FIPS 202)",
		"DES/3DES → AES-256-GCM",
		"RC4 → ChaCha20-Poly1305",
	}

	// Quantum risk summary
	riskSummary := buildQuantumRiskSummary(source, sbomLibs)

	if len(weak) > 0 {
		warnings = append(warnings, fmt.Sprintf("%d weak cryptographic primitives detected — immediate remediation required", len(weak)))
	}
	if source.HasLegacy && !source.HasPQC {
		warnings = append(warnings, "Legacy public-key crypto (RSA/ECDSA) found with no PQC migration in progress")
	}

	return &CryptoResponse{
		ProjectPath:      absPath,
		SourceScan:       source,
		SBOMCryptoLibs:   sbomLibs,
		WeakPrimitives:   weak,
		PQCMigrationPath: migrationPath,
		QuantumRisk:      riskSummary,
		ScannedAt:        time.Now().UTC().Format(time.RFC3339),
	}, warnings, nil
}

// scanCryptoSource counts crypto primitive references in Go source files.
func scanCryptoSource(dir string) CryptoSourceScan {
	var s CryptoSourceScan
	filepath.Walk(dir, func(path string, info osFileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".go") ||
			strings.Contains(path, "/vendor/") || strings.Contains(path, "\\vendor\\") {
			return nil
		}
		data, err := osReadFile(path)
		if err != nil {
			return nil
		}
		c := string(data)
		s.RSARefs += strings.Count(c, "rsa.")
		s.ECDSARefs += strings.Count(c, "ecdsa.") + strings.Count(c, "ecdh.")
		s.AESRefs += strings.Count(c, "aes.")
		s.SHARefs += strings.Count(c, "sha256") + strings.Count(c, "sha512")
		s.KyberRefs += strings.Count(c, "kyber") + strings.Count(c, "Kyber") +
			strings.Count(c, "mlkem") + strings.Count(c, "MLKEM")
		s.DilithiumRefs += strings.Count(c, "dilithium") + strings.Count(c, "Dilithium") +
			strings.Count(c, "mldsa") + strings.Count(c, "MLDSA")
		return nil
	})
	s.HasLegacy = s.RSARefs > 0 || s.ECDSARefs > 0
	s.HasPQC = s.KyberRefs > 0 || s.DilithiumRefs > 0
	return s
}

// cryptoLibPatternsMCP maps library name patterns to PQC/weak classification.
var cryptoLibPatternsMCP = []struct {
	Pattern    string
	PQCCapable bool
	Weak       bool
	Note       string
}{
	{"liboqs", true, false, "Open Quantum Safe — NIST PQC reference implementation"},
	{"kyber", true, false, "ML-KEM-768 key encapsulation (NIST FIPS 203)"},
	{"dilithium", true, false, "ML-DSA-65 digital signatures (NIST FIPS 204)"},
	{"mlkem", true, false, "ML-KEM standardized KEM"},
	{"mldsa", true, false, "ML-DSA standardized signature"},
	{"sphincs", true, false, "SLH-DSA hash-based signatures (NIST FIPS 205)"},
	{"rsa", false, true, "RSA — quantum-vulnerable via Shor's algorithm"},
	{"ecdsa", false, true, "ECDSA — quantum-vulnerable via Shor's algorithm"},
	{"ecdh", false, true, "ECDH — quantum-vulnerable key exchange"},
	{"des", false, true, "DES/3DES — deprecated, broken brute-force resistance"},
	{"rc4", false, true, "RC4 — cryptographically broken stream cipher"},
	{"md5", false, true, "MD5 — collision-broken hash function"},
	{"sha1", false, true, "SHA-1 — collision-broken, NIST deprecated"},
	{"aes", false, false, "AES-256 is Grover-resistant at 256-bit key length"},
	{"openssl", false, false, "OpenSSL — assess version and default configs"},
}

// weakPatternsMCP maps source patterns to severity + reason.
var weakPatternsMCP = []struct {
	Pattern  string
	Severity string
	Reason   string
}{
	{"md5.New()", "CRITICAL", "MD5 collision-broken — use SHA-256"},
	{"sha1.New()", "HIGH", "SHA-1 collision-broken — use SHA-256"},
	{"des.NewCipher(", "CRITICAL", "DES is insecure — use AES-256-GCM"},
	{"des.NewTripleDESCipher(", "HIGH", "3DES 64-bit block — migrate to AES-256"},
	{"rc4.NewCipher(", "CRITICAL", "RC4 cryptographically broken"},
	{"blowfish.NewCipher(", "HIGH", "Blowfish 64-bit block — use AES-256"},
	{"rsa.GenerateKey(", "MEDIUM", "RSA key ≥4096 for post-quantum transition buffer"},
	{"ecdsa.GenerateKey(elliptic.P224", "HIGH", "P-224 below minimum — use P-384 or ML-DSA"},
}

// scanSBOMForCryptoLibs uses the SCA pipeline to find crypto-relevant components.
func scanSBOMForCryptoLibs(ctx context.Context, dir string) []SBOMCryptoEntry {
	feedMgr := vuln.NewIntelFeedManager()
	pipeline := sca.NewPipeline(feedMgr)
	scanCtx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	result, err := pipeline.ScanAndEnrich(scanCtx, dir)
	if err != nil {
		return nil
	}

	seen := make(map[string]bool)
	var libs []SBOMCryptoEntry
	for _, f := range result.Findings {
		name := strings.ToLower(f.Component)
		for _, p := range cryptoLibPatternsMCP {
			key := f.Component + f.Version
			if strings.Contains(name, p.Pattern) && !seen[key] {
				seen[key] = true
				libs = append(libs, SBOMCryptoEntry{
					Name:       f.Component,
					Version:    f.Version,
					Ecosystem:  f.Ecosystem,
					PQCCapable: p.PQCCapable,
					Weak:       p.Weak,
					Note:       p.Note,
				})
				break
			}
		}
	}
	sort.Slice(libs, func(i, j int) bool {
		if libs[i].Weak != libs[j].Weak {
			return libs[i].Weak
		}
		return libs[i].Name < libs[j].Name
	})
	return libs
}

// detectCryptoWeakness scans Go source for weak crypto patterns with file:line.
func detectCryptoWeakness(dir string) []WeakPrimEntry {
	var found []WeakPrimEntry
	filepath.Walk(dir, func(path string, info osFileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".go") ||
			strings.Contains(path, "/vendor/") || strings.Contains(path, "\\vendor\\") {
			return nil
		}
		data, err := osReadFile(path)
		if err != nil {
			return nil
		}
		lines := strings.Split(string(data), "\n")
		for lineNum, line := range lines {
			for _, d := range weakPatternsMCP {
				if strings.Contains(line, d.Pattern) {
					shortPath := filepath.Base(filepath.Dir(path)) + "/" + filepath.Base(path)
					found = append(found, WeakPrimEntry{
						Pattern:  d.Pattern,
						File:     shortPath,
						Line:     lineNum + 1,
						Severity: d.Severity,
						Reason:   d.Reason,
					})
				}
			}
		}
		return nil
	})
	sort.Slice(found, func(i, j int) bool {
		return severityRankMCP(found[i].Severity) > severityRankMCP(found[j].Severity)
	})
	return found
}

func buildQuantumRiskSummary(s CryptoSourceScan, libs []SBOMCryptoEntry) string {
	weakSBOM := 0
	for _, l := range libs {
		if l.Weak {
			weakSBOM++
		}
	}
	if !s.HasLegacy && weakSBOM == 0 && !s.HasPQC {
		return "No public-key crypto detected in source scan. Run with syft+grype for SBOM-level inventory."
	}
	if s.HasPQC && !s.HasLegacy {
		return "PQC algorithms detected. No legacy public-key crypto found. CNSA 2.0 transition in progress."
	}
	if s.HasLegacy || weakSBOM > 0 {
		return "QUANTUM-VULNERABLE: RSA/ECDSA detected. Vulnerable to Shor's algorithm when cryptographically-relevant quantum computers (CRQCs) reach scale (CNSA 2.0 scenario window: 2030–2040+). Begin ML-KEM-768 + ML-DSA-65 migration immediately per NSA CNSA 2.0."
	}
	return "Classical crypto only — no PQC detected. Review CNSA 2.0 migration requirements."
}

func severityRankMCP(sev string) int {
	switch strings.ToUpper(sev) {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	default:
		return 0
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Package D — ert_godfather (Causal Risk Attestation)
// ─────────────────────────────────────────────────────────────────────────────

// GodfatherResponse is the structured JSON output of ert_godfather.
type GodfatherResponse struct {
	ProjectPath    string           `json:"project_path"`
	OverallScore   float64          `json:"overall_score"`
	RiskLevel      string           `json:"risk_level"`
	TotalFindings  int              `json:"total_findings"`
	CriticalCount  int              `json:"critical_count"`
	HighCount      int              `json:"high_count"`
	CISAKEVCount   int              `json:"cisa_kev_count"`
	DollarImpact   float64          `json:"dollar_impact_estimate"`
	CausalChain    []CausalLink     `json:"causal_chain"`
	Interventions  []Intervention   `json:"interventions"`
	Capabilities   []string         `json:"capabilities_executed"`
	DAGNodeID      string           `json:"dag_node_id,omitempty"`
	ScannedAt      string           `json:"scanned_at"`
}

// CausalLink is one step in the causal chain.
type CausalLink struct {
	Step      int    `json:"step"`
	Connector string `json:"connector"` // "BUT", "AND", "THEREFORE", "BECAUSE"
	Statement string `json:"statement"`
	Evidence  string `json:"evidence,omitempty"`
}

// Intervention is a board-level recommended action.
type Intervention struct {
	Priority string `json:"priority"`
	Action   string `json:"action"`
	Impact   string `json:"impact"`
}

// HandleERTGodfather is the MCP handler for ert_godfather.
func HandleERTGodfather(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	projectPath, _ := call.Args["project_path"].(string)
	if projectPath == "" {
		projectPath = "."
	}
	absPath, err := filepath.Abs(projectPath)
	if err != nil {
		return nil, nil, fmt.Errorf("ert_godfather: invalid path: %w", err)
	}

	// Build security context
	sec := ea.NewSecurityContext(absPath)
	sec.HasCUI = true
	sec.Frameworks = []string{"cmmc", "nist-800-53", "stig"}

	// ── Source-level crypto enrichment ─────────────────────────────────────────
	// Run a fast source scan to set LegacyCryptoFound so the KernelRouter's
	// PQC agent fires on real evidence, not static flags.
	cryptoScan := scanCryptoSource(absPath)
	sec.LegacyCryptoFound = cryptoScan.HasLegacy

	// Run KernelRouter — register all capabilities that the classifier may select
	// for a CUI target. Missing agents cause Route() to return an error.
	dagStore := dag.NewMemory()
	router := ea.NewKernelRouter(dagStore)
	router.Register(&godfatherSTIGAgent{})
	router.Register(&godfatherPQCAgent{})
	router.Register(&godfatherNetworkAgent{})
	router.Register(&godfatherFIMAgent{})  // FIM fires for HasCUI targets

	// Add SBOM agent only if SCA tools available
	if scaBinaryAvailable("syft") && scaBinaryAvailable("grype") {
		router.Register(&godfatherSBOMAgent{})
		sec.UnpatchedCVEs = 1 // trigger SBOM capability
	}

	var routeWarnings []string
	results, routeErr := router.Route(ctx, sec)
	if routeErr != nil {
		routeWarnings = append(routeWarnings, fmt.Sprintf("KernelRouter partial: %v", routeErr))
	}

	// Aggregate
	var totalScore float64
	totalFindings, critical, high, kevCount := 0, 0, 0, 0
	dollarImpact := 0.0
	caps := []string{}

	for _, r := range results {
		if r == nil {
			continue
		}
		caps = append(caps, r.Capability)
		totalFindings += r.FindingCount
		totalScore += r.RiskScore
		for _, f := range r.Findings {
			switch f.Severity {
			case "CRITICAL":
				critical++
				dollarImpact += 4_200_000
			case "HIGH":
				high++
				dollarImpact += 1_500_000
			case "MEDIUM":
				dollarImpact += 250_000
			}
		}
		if kev, ok := r.Metadata["cisa_kev_count"].(int); ok {
			kevCount += kev
		}
	}
	if len(results) > 0 {
		totalScore /= float64(len(results))
	}
	if dollarImpact > 50_000_000 {
		dollarImpact = 50_000_000
	}

	// Causal chain
	chain := buildGodfatherCausalChain(results, critical, kevCount)
	interventions := buildGodfatherInterventions(results, critical, high, kevCount)

	// DAG attestation
	dagNodeID := attestGodfatherMCP(dagStore, sec, totalScore, totalFindings)

	var warnings []string
	warnings = append(warnings, routeWarnings...)
	if critical > 0 {
		warnings = append(warnings, fmt.Sprintf("%d CRITICAL findings — executive action required", critical))
	}
	if kevCount > 0 {
		warnings = append(warnings, fmt.Sprintf("%d CISA KEV — actively exploited, immediate patch", kevCount))
	}

	return &GodfatherResponse{
		ProjectPath:   absPath,
		OverallScore:  totalScore,
		RiskLevel:     executiveRiskLevel(int(totalScore)),
		TotalFindings: totalFindings,
		CriticalCount: critical,
		HighCount:     high,
		CISAKEVCount:  kevCount,
		DollarImpact:  dollarImpact,
		CausalChain:   chain,
		Interventions: interventions,
		Capabilities:  caps,
		DAGNodeID:     dagNodeID,
		ScannedAt:     time.Now().UTC().Format(time.RFC3339),
	}, warnings, nil
}

// ── Godfather KernelAgents (lightweight in-process versions) ─────────────────

type godfatherSTIGAgent struct{}

func (a *godfatherSTIGAgent) Capability() ea.Capability { return ea.CapSTIG }
func (a *godfatherSTIGAgent) Name() string              { return "mcp-nist-800-171" }
func (a *godfatherSTIGAgent) Execute(_ context.Context, _ *ea.SecurityContext) (*ea.AgentResult, error) {
	v := nist80171.NewValidator()
	results := v.ValidateACFamily()
	var findings []ea.Finding
	score := 0.0
	for _, r := range results {
		if r.Status == "FAIL" {
			findings = append(findings, ea.Finding{
				ID: r.ControlID, Severity: "HIGH",
				Title: r.Title, Control: "NIST 800-171 " + r.ControlID,
				Remediation: r.Remediation, DiscoveredAt: time.Now(),
			})
			score += 10.0
		}
	}
	if score > 100 {
		score = 100
	}
	return &ea.AgentResult{
		AgentName: a.Name(), Capability: ea.CapSTIG.String(),
		StartedAt: time.Now(), CompletedAt: time.Now(),
		FindingCount: len(findings), RiskScore: score, Findings: findings,
		Metadata: map[string]interface{}{"controls_checked": len(results)},
	}, nil
}

type godfatherPQCAgent struct{}

func (a *godfatherPQCAgent) Capability() ea.Capability { return ea.CapPQC }
func (a *godfatherPQCAgent) Name() string              { return "mcp-pqc-analyzer" }
func (a *godfatherPQCAgent) Execute(_ context.Context, sec *ea.SecurityContext) (*ea.AgentResult, error) {
	var findings []ea.Finding
	score := 20.0
	if sec.LegacyCryptoFound {
		findings = append(findings, ea.Finding{
			ID: "PQC-001", Severity: "HIGH",
			Title:       "Legacy crypto detected (RSA/ECDSA)",
			Control:     "NIST 800-171 3.13.10",
			Remediation: "Migrate to ML-KEM-768 + ML-DSA-65 (NIST FIPS 203/204)",
			DiscoveredAt: time.Now(),
		})
		score += 30.0
	}
	return &ea.AgentResult{
		AgentName: a.Name(), Capability: ea.CapPQC.String(),
		StartedAt: time.Now(), CompletedAt: time.Now(),
		FindingCount: len(findings), RiskScore: score, Findings: findings,
	}, nil
}

type godfatherNetworkAgent struct{}

func (a *godfatherNetworkAgent) Capability() ea.Capability { return ea.CapNetwork }
func (a *godfatherNetworkAgent) Name() string              { return "mcp-network-boundary" }
func (a *godfatherNetworkAgent) Execute(_ context.Context, _ *ea.SecurityContext) (*ea.AgentResult, error) {
	return &ea.AgentResult{
		AgentName: a.Name(), Capability: ea.CapNetwork.String(),
		StartedAt: time.Now(), CompletedAt: time.Now(),
		FindingCount: 1, RiskScore: 15.0,
		Findings: []ea.Finding{{
			ID: "NET-001", Severity: "MEDIUM",
			Title:        "Network boundary assessment required",
			Control:      "NIST 800-171 3.13.1",
			Remediation:  "Run khepra_network_scan to enumerate and validate all listening services",
			DiscoveredAt: time.Now(),
		}},
	}, nil
}

type godfatherSBOMAgent struct{}

func (a *godfatherSBOMAgent) Capability() ea.Capability { return ea.CapSBOM }
func (a *godfatherSBOMAgent) Name() string              { return "mcp-sbom-cve" }
func (a *godfatherSBOMAgent) Execute(ctx context.Context, sec *ea.SecurityContext) (*ea.AgentResult, error) {
	feedMgr := vuln.NewIntelFeedManager()
	pipeline := sca.NewPipeline(feedMgr)
	scanCtx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	result, err := pipeline.ScanAndEnrich(scanCtx, sec.Target)
	if err != nil {
		return &ea.AgentResult{AgentName: a.Name(), Capability: ea.CapSBOM.String()}, nil
	}
	var findings []ea.Finding
	kevCount := 0
	score := 0.0
	for _, f := range result.Findings {
		if !f.IsHighRisk() {
			continue
		}
		sev := "HIGH"
		if strings.ToUpper(f.Severity) == "CRITICAL" || f.InCISAKEV {
			sev = "CRITICAL"
		}
		if f.InCISAKEV {
			kevCount++
		}
		findings = append(findings, ea.Finding{
			ID: f.CVEID, Severity: sev,
			Title:        fmt.Sprintf("%s@%s — %s (CVSS %.1f)", f.Component, f.Version, f.CVEID, f.CVSSv3Score),
			Control:      strings.Join(f.NIST171Controls, ", "),
			Remediation:  fmt.Sprintf("Update %s. EPSS: %.1f%%", f.Component, f.EPSSScore*100),
			DiscoveredAt: time.Now(),
		})
		score += f.RiskScore()
	}
	if len(findings) > 0 {
		score /= float64(len(findings))
	}
	return &ea.AgentResult{
		AgentName: a.Name(), Capability: ea.CapSBOM.String(),
		StartedAt: time.Now(), CompletedAt: time.Now(),
		FindingCount: len(findings), RiskScore: score, Findings: findings,
		Metadata: map[string]interface{}{"cisa_kev_count": kevCount},
	}, nil
}

type godfatherFIMAgent struct{}

func (a *godfatherFIMAgent) Capability() ea.Capability { return ea.CapFIM }
func (a *godfatherFIMAgent) Name() string              { return "mcp-fim-integrity" }
func (a *godfatherFIMAgent) Execute(_ context.Context, _ *ea.SecurityContext) (*ea.AgentResult, error) {
	// FIM passthrough for MCP context: recommend deployment of a file integrity
	// monitoring solution. Full FIM scan requires the khepra-daemon agent.
	return &ea.AgentResult{
		AgentName: a.Name(), Capability: ea.CapFIM.String(),
		StartedAt: time.Now(), CompletedAt: time.Now(),
		FindingCount: 1, RiskScore: 10.0,
		Findings: []ea.Finding{{
			ID: "FIM-001", Severity: "MEDIUM",
			Title:        "File integrity monitoring not verified",
			Control:      "NIST 800-171 3.14.1 / CMMC SI.2.216",
			Remediation:  "Deploy khepra-daemon with FIM mode enabled for continuous file integrity attestation",
			DiscoveredAt: time.Now(),
		}},
	}, nil
}

// ── Causal chain + interventions builders ────────────────────────────────────

func buildGodfatherCausalChain(results []*ea.AgentResult, critical, kevCount int) []CausalLink {
	chain := []CausalLink{}
	step := 1

	for _, r := range results {
		if r == nil || r.FindingCount == 0 {
			continue
		}
		switch r.Capability {
		case ea.CapSTIG.String():
			chain = append(chain, CausalLink{
				Step: step, Connector: "BECAUSE",
				Statement: fmt.Sprintf("%d NIST 800-171 control failures block CMMC Level 2 certification", r.FindingCount),
			})
			step++
		case ea.CapSBOM.String():
			if kevCount > 0 {
				chain = append(chain, CausalLink{
					Step: step, Connector: "AND",
					Statement: fmt.Sprintf("%d CISA KEV vulnerabilities actively exploited in supply chain", kevCount),
					Evidence:  "CISA Known Exploited Vulnerabilities catalog",
				})
				step++
			}
		case ea.CapPQC.String():
			chain = append(chain, CausalLink{
				Step: step, Connector: "AND",
				Statement: "Legacy RSA/ECDSA detected — quantum-vulnerable under CNSA 2.0 transition scenarios",
				Evidence:  "NSA CNSA 2.0 / NIST SP 800-131A Rev 3",
			})
			step++
		}
	}

	if critical > 0 {
		chain = append(chain, CausalLink{
			Step: step, Connector: "THEREFORE",
			Statement: fmt.Sprintf("Organization faces elevated breach probability with %d CRITICAL findings requiring immediate action", critical),
		})
	}
	return chain
}

func buildGodfatherInterventions(results []*ea.AgentResult, critical, high, kevCount int) []Intervention {
	ivs := []Intervention{}
	if kevCount > 0 {
		ivs = append(ivs, Intervention{
			Priority: "URGENT",
			Action:   fmt.Sprintf("Patch %d CISA KEV vulnerabilities", kevCount),
			Impact:   "Eliminates actively exploited breach vectors",
		})
	}
	if critical > 0 || high > 0 {
		ivs = append(ivs, Intervention{
			Priority: "URGENT",
			Action:   fmt.Sprintf("Remediate %d CRITICAL / %d HIGH findings", critical, high),
			Impact:   fmt.Sprintf("Reduces breach probability by ~%.0f%%", float64(critical+high)*4.0),
		})
	}
	for _, r := range results {
		if r == nil || r.Capability != ea.CapSTIG.String() || r.FindingCount == 0 {
			continue
		}
		ivs = append(ivs, Intervention{
			Priority: "HIGH",
			Action:   fmt.Sprintf("Remediate %d NIST 800-171 control failures", r.FindingCount),
			Impact:   "Achieves CMMC Level 2 — prerequisite for DoD contract renewal",
		})
	}
	ivs = append(ivs, Intervention{
		Priority: "STRATEGIC",
		Action:   "PQC Migration — ML-KEM-768 + ML-DSA-65 (NIST FIPS 203/204)",
		Impact:   "Future-proofs compliance evidence before CNSA 2.0 mandatory window",
	})
	ivs = append(ivs, Intervention{
		Priority: "FOUNDATIONAL",
		Action:   "Continuous Compliance Monitoring (AdinKhepra Agent)",
		Impact:   "Real-time drift detection + DAG-anchored evidence trail",
	})
	return ivs
}

func attestGodfatherMCP(dagStore dag.Store, sec *ea.SecurityContext, score float64, findings int) string {
	n := &dag.Node{
		Action: "mcp_godfather_synthesis",
		Symbol: "Eban",
		Time:   time.Now().UTC().Format(time.RFC3339Nano),
		PQC: map[string]string{
			"target":   sec.Target,
			"score":    fmt.Sprintf("%.2f", score),
			"findings": fmt.Sprintf("%d", findings),
		},
	}
	if err := dagStore.Add(n, nil); err != nil {
		return ""
	}
	return n.ID
}

// ─────────────────────────────────────────────────────────────────────────────
// OS abstraction helpers (injectable for testing)
// ─────────────────────────────────────────────────────────────────────────────

// osFileInfo is an alias for os.FileInfo, allowing test mocking without
// affecting production code paths.
type osFileInfo = os.FileInfo

// osReadFile wraps os.ReadFile so that tests can substitute a mock implementation.
func osReadFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}
