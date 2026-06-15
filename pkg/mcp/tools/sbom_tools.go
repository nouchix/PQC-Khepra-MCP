package tools

// sbom_tools.go — MCP handlers for sbom_generate and threat_model.
//
// Tools:
//   sbom_generate  — Generate a CycloneDX/SPDX-style SBOM. Uses Syft when available;
//                    falls back to source-level filesystem walk (always works, zero deps).
//                    Annotates components with PQC readiness flags.
//
//   threat_model   — STRIDE threat model for a project. Maps threats to NIST 800-53 Rev5
//                    and CMMC controls. Provides MITRE ATT&CK technique mappings.
//                    100% offline — no external API calls.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/nouchix/PQC-Khepra-MCP/pkg/mcp"
)

// ─── sbom_generate ────────────────────────────────────────────────────────────

// SBOMGenerateResponse is the structured JSON output of sbom_generate.
type SBOMGenerateResponse struct {
	ProjectPath     string          `json:"project_path"`
	SBOMFormat      string          `json:"format"`
	SpecVersion     string          `json:"spec_version"`
	GeneratedAt     string          `json:"generated_at"`
	TotalComponents int             `json:"total_components"`
	PQCCapable      int             `json:"pqc_capable_components"`
	WeakCrypto      int             `json:"weak_crypto_components"`
	Components      []SBOMComponent `json:"components"`
	SourceMode      string          `json:"source_mode"` // "syft" | "filesystem_walk"
	Warnings        []string        `json:"warnings,omitempty"`
}

// SBOMComponent represents one inventory item.
type SBOMComponent struct {
	Name        string `json:"name"`
	Version     string `json:"version,omitempty"`
	Type        string `json:"type"` // library, application, framework, container
	Ecosystem   string `json:"ecosystem,omitempty"`
	Language    string `json:"language,omitempty"`
	PQCCapable  bool   `json:"pqc_capable"`
	WeakCrypto  bool   `json:"weak_crypto"`
	CryptoNote  string `json:"crypto_note,omitempty"`
	LicenseExpr string `json:"license,omitempty"`
	PURL        string `json:"purl,omitempty"`
}

// HandleSBOMGenerate generates a Software Bill of Materials for the target project.
// Uses Syft when in PATH for rich CycloneDX output; falls back to source walk.
func HandleSBOMGenerate(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	projectPath, _ := call.Args["project_path"].(string)
	if projectPath == "" {
		projectPath = "."
	}
	outputFormat, _ := call.Args["output_format"].(string)
	if outputFormat == "" {
		outputFormat = "cyclonedx-json"
	}
	absPath, err := filepath.Abs(projectPath)
	if err != nil {
		return nil, nil, fmt.Errorf("sbom_generate: invalid path: %w", err)
	}

	var warnings []string
	var components []SBOMComponent
	sourceMode := "filesystem_walk"

	// ── Try Syft first ────────────────────────────────────────────────────────
	if syftPath, err := exec.LookPath("syft"); err == nil {
		components, warnings, sourceMode = runSyftSBOM(ctx, syftPath, absPath, outputFormat, warnings)
	}

	// ── Fallback: filesystem walk ─────────────────────────────────────────────
	if len(components) == 0 {
		sourceMode = "filesystem_walk"
		components = walkFilesystemForComponents(absPath)
		warnings = append(warnings, "syft not in PATH — using source filesystem walk. Install syft for full CycloneDX SBOM with dependency graph.")
	}

	// ── PQC annotation pass ───────────────────────────────────────────────────
	pqcCapable, weakCrypto := 0, 0
	for i := range components {
		annotatePQCStatus(&components[i])
		if components[i].PQCCapable {
			pqcCapable++
		}
		if components[i].WeakCrypto {
			weakCrypto++
		}
	}

	// Sort by name for deterministic output
	sort.Slice(components, func(i, j int) bool {
		return components[i].Name < components[j].Name
	})

	if weakCrypto > 0 {
		warnings = append(warnings, fmt.Sprintf("%d component(s) use quantum-vulnerable cryptography — run ert_crypto for detailed analysis", weakCrypto))
	}
	if pqcCapable > 0 {
		warnings = append(warnings, fmt.Sprintf("%d PQC-capable component(s) detected — verify FIPS 203/204/205 compliance", pqcCapable))
	}

	return &SBOMGenerateResponse{
		ProjectPath:     absPath,
		SBOMFormat:      outputFormat,
		SpecVersion:     "1.4",
		GeneratedAt:     time.Now().UTC().Format(time.RFC3339),
		TotalComponents: len(components),
		PQCCapable:      pqcCapable,
		WeakCrypto:      weakCrypto,
		Components:      components,
		SourceMode:      sourceMode,
	}, warnings, nil
}

// runSyftSBOM invokes syft to generate a structured component list.
func runSyftSBOM(ctx context.Context, syftPath, projectPath, format string, warnings []string) ([]SBOMComponent, []string, string) {
	// Map MCP format name to syft output format
	syftFormat := "cyclonedx-json"
	if strings.Contains(format, "spdx") {
		syftFormat = "spdx-json"
	}

	scanCtx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()

	out, err := exec.CommandContext(scanCtx, syftPath, "scan", projectPath,
		"--output", syftFormat,
		"--quiet",
	).Output()
	if err != nil {
		warnings = append(warnings, fmt.Sprintf("syft scan failed (%v) — falling back to filesystem walk", err))
		return nil, warnings, "filesystem_walk"
	}

	// Parse CycloneDX JSON
	components := parseCycloneDXJSON(out)
	if len(components) == 0 {
		warnings = append(warnings, "syft returned no components — check project structure")
	}
	return components, warnings, "syft"
}

// parseCycloneDXJSON extracts components from CycloneDX JSON output.
func parseCycloneDXJSON(data []byte) []SBOMComponent {
	var cdx struct {
		Components []struct {
			Name     string `json:"name"`
			Version  string `json:"version"`
			Type     string `json:"type"`
			PURL     string `json:"purl"`
			Licenses []struct {
				License struct {
					ID string `json:"id"`
				} `json:"license"`
			} `json:"licenses"`
		} `json:"components"`
	}
	if err := json.Unmarshal(data, &cdx); err != nil {
		return nil
	}
	var out []SBOMComponent
	for _, c := range cdx.Components {
		license := ""
		if len(c.Licenses) > 0 {
			license = c.Licenses[0].License.ID
		}
		ecosystem := ""
		if c.PURL != "" {
			// e.g. pkg:golang/github.com/foo/bar@v1.0.0
			parts := strings.SplitN(c.PURL, "/", 2)
			if len(parts) > 0 {
				ecosystem = strings.TrimPrefix(parts[0], "pkg:")
			}
		}
		out = append(out, SBOMComponent{
			Name:        c.Name,
			Version:     c.Version,
			Type:        c.Type,
			Ecosystem:   ecosystem,
			PURL:        c.PURL,
			LicenseExpr: license,
		})
	}
	return out
}

// walkFilesystemForComponents provides a fallback SBOM using language runtime detection.
func walkFilesystemForComponents(dir string) []SBOMComponent {
	var components []SBOMComponent
	seen := make(map[string]bool)

	// Detect Go modules
	goModPath := filepath.Join(dir, "go.mod")
	if data, err := os.ReadFile(goModPath); err == nil {
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "require") || line == "" || strings.HasPrefix(line, "//") {
				continue
			}
			parts := strings.Fields(line)
			if len(parts) >= 2 && !strings.HasPrefix(parts[0], ")") {
				name := parts[0]
				version := parts[1]
				key := name + "@" + version
				if !seen[key] {
					seen[key] = true
					components = append(components, SBOMComponent{
						Name:      name,
						Version:   version,
						Type:      "library",
						Ecosystem: "golang",
						Language:  "Go",
						PURL:      fmt.Sprintf("pkg:golang/%s@%s", name, version),
					})
				}
			}
		}
	}

	// Detect Python packages (requirements.txt)
	reqPath := filepath.Join(dir, "requirements.txt")
	if data, err := os.ReadFile(reqPath); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			parts := strings.FieldsFunc(line, func(r rune) bool { return r == '=' || r == '>' || r == '<' || r == '~' })
			name := strings.TrimSpace(parts[0])
			version := ""
			if len(parts) > 1 {
				version = strings.TrimSpace(parts[len(parts)-1])
			}
			key := name + "@" + version
			if !seen[key] {
				seen[key] = true
				components = append(components, SBOMComponent{
					Name:      name,
					Version:   version,
					Type:      "library",
					Ecosystem: "pypi",
					Language:  "Python",
					PURL:      fmt.Sprintf("pkg:pypi/%s@%s", strings.ToLower(name), version),
				})
			}
		}
	}

	// Detect Node packages (package.json)
	pkgJSONPath := filepath.Join(dir, "package.json")
	if data, err := os.ReadFile(pkgJSONPath); err == nil {
		var pkg struct {
			Name         string            `json:"name"`
			Version      string            `json:"version"`
			Dependencies map[string]string `json:"dependencies"`
			DevDeps      map[string]string `json:"devDependencies"`
		}
		if json.Unmarshal(data, &pkg) == nil {
			for name, ver := range pkg.Dependencies {
				key := name + "@" + ver
				if !seen[key] {
					seen[key] = true
					components = append(components, SBOMComponent{
						Name:      name,
						Version:   strings.TrimPrefix(ver, "^"),
						Type:      "library",
						Ecosystem: "npm",
						Language:  "JavaScript",
						PURL:      fmt.Sprintf("pkg:npm/%s@%s", name, strings.TrimPrefix(ver, "^")),
					})
				}
			}
		}
	}

	// Detect Dockerfiles
	if _, err := os.Stat(filepath.Join(dir, "Dockerfile")); err == nil {
		components = append(components, SBOMComponent{
			Name:     filepath.Base(dir) + " (container)",
			Type:     "container",
			Language: "Dockerfile",
		})
	}

	return components
}

// pqcCryptoAnnotations maps component name substrings to PQC/crypto flags.
var pqcCryptoAnnotations = []struct {
	Pattern    string
	PQCCapable bool
	WeakCrypto bool
	Note       string
}{
	{"circl", true, false, "Cloudflare CIRCL — ML-DSA-65 / ML-KEM-768 (NIST FIPS 203/204)"},
	{"liboqs", true, false, "Open Quantum Safe — NIST PQC reference implementation"},
	{"kyber", true, false, "ML-KEM key encapsulation (NIST FIPS 203)"},
	{"dilithium", true, false, "ML-DSA digital signatures (NIST FIPS 204)"},
	{"sphincs", true, false, "SLH-DSA hash-based signatures (NIST FIPS 205)"},
	{"mlkem", true, false, "ML-KEM (NIST FIPS 203 standardized)"},
	{"mldsa", true, false, "ML-DSA (NIST FIPS 204 standardized)"},
	{"openssl", false, false, "OpenSSL — verify TLS 1.3 and PQC extension support"},
	{"cryptography", false, false, "Python cryptography lib — verify PQC provider loaded"},
	{"pycryptodome", false, true, "PyCryptodome — limited PQC support; assess usage"},
	{"des", false, true, "DES/3DES — deprecated, quantum-vulnerable"},
	{"rc4", false, true, "RC4 — cryptographically broken stream cipher"},
	{"md5", false, true, "MD5 — collision-broken, not quantum-resistant"},
}

// annotatePQCStatus sets PQCCapable / WeakCrypto flags based on name pattern matching.
func annotatePQCStatus(c *SBOMComponent) {
	lower := strings.ToLower(c.Name)
	for _, a := range pqcCryptoAnnotations {
		if strings.Contains(lower, a.Pattern) {
			c.PQCCapable = a.PQCCapable
			c.WeakCrypto = a.WeakCrypto
			c.CryptoNote = a.Note
			return
		}
	}
}

// ─── threat_model ─────────────────────────────────────────────────────────────

// ThreatModelResponse is the structured JSON output of threat_model.
type ThreatModelResponse struct {
	ProjectPath      string           `json:"project_path"`
	Methodology      string           `json:"methodology"`
	Scope            string           `json:"scope"`
	TotalThreats     int              `json:"total_threats"`
	CriticalThreats  int              `json:"critical_threats"`
	HighThreats      int              `json:"high_threats"`
	Threats          []STRIDEThreat   `json:"threats"`
	MITREMatrix      []MITRETechEntry `json:"mitre_attck_techniques"`
	NISTPolicies     []string         `json:"nist_800_53_controls"`
	CMMCDomains      []string         `json:"cmmc_domains"`
	ExecutiveSummary string           `json:"executive_summary"`
	AssessedAt       string           `json:"assessed_at"`
}

// STRIDEThreat represents a single STRIDE-classified threat.
type STRIDEThreat struct {
	ID           string   `json:"id"`
	Category     string   `json:"stride_category"` // S, T, R, I, D, E
	Title        string   `json:"title"`
	Description  string   `json:"description"`
	Likelihood   string   `json:"likelihood"` // Critical, High, Medium, Low
	Impact       string   `json:"impact"`
	Risk         string   `json:"risk"` // Critical, High, Medium, Low
	NIST53       []string `json:"nist_800_53_controls"`
	CMMC         []string `json:"cmmc_practices"`
	Mitigations  []string `json:"mitigations"`
	MITRETactics []string `json:"mitre_tactics,omitempty"`
}

// MITRETechEntry maps a MITRE ATT&CK technique to this project's threat profile.
type MITRETechEntry struct {
	TechID     string `json:"technique_id"`
	Name       string `json:"name"`
	Tactic     string `json:"tactic"`
	Relevance  string `json:"relevance"`
	Mitigation string `json:"mitigation_nist"`
}

// HandleThreatModel performs a STRIDE threat analysis on the target project.
// Fully offline — analyzes project structure, asset type, and detected technologies
// to generate a contextual threat model with NIST 800-53 and CMMC control mappings.
func HandleThreatModel(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	projectPath, _ := call.Args["project_path"].(string)
	if projectPath == "" {
		projectPath = "."
	}
	scope, _ := call.Args["scope"].(string)
	if scope == "" {
		scope = "application"
	}
	absPath, err := filepath.Abs(projectPath)
	if err != nil {
		return nil, nil, fmt.Errorf("threat_model: invalid path: %w", err)
	}

	// ── Detect project characteristics ────────────────────────────────────────
	profile := detectProjectProfile(absPath)

	// ── Build STRIDE threat catalog ───────────────────────────────────────────
	threats := buildSTRIDEThreatCatalog(profile, scope)

	// ── Count by severity ─────────────────────────────────────────────────────
	critical, high := 0, 0
	for _, t := range threats {
		switch t.Risk {
		case "Critical":
			critical++
		case "High":
			high++
		}
	}

	// ── Aggregate NIST controls ───────────────────────────────────────────────
	nistSeen := make(map[string]bool)
	var nistControls []string
	cmmcSeen := make(map[string]bool)
	var cmmcDomains []string
	for _, t := range threats {
		for _, n := range t.NIST53 {
			if !nistSeen[n] {
				nistSeen[n] = true
				nistControls = append(nistControls, n)
			}
		}
		for _, c := range t.CMMC {
			if !cmmcSeen[c] {
				cmmcSeen[c] = true
				cmmcDomains = append(cmmcDomains, c)
			}
		}
	}
	sort.Strings(nistControls)
	sort.Strings(cmmcDomains)

	// ── MITRE ATT&CK mapping ──────────────────────────────────────────────────
	mitreMatrix := buildMITREMatrix(profile)

	// ── Executive summary ─────────────────────────────────────────────────────
	summary := buildThreatModelSummary(critical, high, len(threats), profile)

	var warnings []string
	if critical > 0 {
		warnings = append(warnings, fmt.Sprintf("%d CRITICAL threats identified — immediate architecture review required", critical))
	}
	if profile.HasLegacyCrypto && !profile.HasPQC {
		warnings = append(warnings, "Quantum threat: RSA/ECDSA detected without PQC migration — 'harvest now, decrypt later' attack applies")
	}

	return &ThreatModelResponse{
		ProjectPath:      absPath,
		Methodology:      "STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege)",
		Scope:            scope,
		TotalThreats:     len(threats),
		CriticalThreats:  critical,
		HighThreats:      high,
		Threats:          threats,
		MITREMatrix:      mitreMatrix,
		NISTPolicies:     nistControls,
		CMMCDomains:      cmmcDomains,
		ExecutiveSummary: summary,
		AssessedAt:       time.Now().UTC().Format(time.RFC3339),
	}, warnings, nil
}

// projectProfile holds detected technology characteristics.
type projectProfile struct {
	HasGoCode       bool
	HasPythonCode   bool
	HasNodeCode     bool
	HasDocker       bool
	HasTLS          bool
	HasAuth         bool
	HasDatabase     bool
	HasAPI          bool
	HasGRPC         bool
	HasCLI          bool
	HasWebUI        bool
	HasLegacyCrypto bool
	HasPQC          bool
	HasMCPServer    bool
	HasAIAgent      bool
	ModuleName      string
}

// detectProjectProfile scans directory structure to build a technology profile.
func detectProjectProfile(dir string) projectProfile {
	var p projectProfile

	// Check file existence
	checks := map[string]*bool{
		"Dockerfile":         &p.HasDocker,
		"docker-compose.yml": &p.HasDocker,
		"go.mod":             &p.HasGoCode,
		"requirements.txt":   &p.HasPythonCode,
		"package.json":       &p.HasNodeCode,
		".mcp.json":          &p.HasMCPServer,
		"server.json":        &p.HasMCPServer,
	}
	for file, flag := range checks {
		if _, err := os.Stat(filepath.Join(dir, file)); err == nil {
			*flag = true
		}
	}

	// Source content checks — walk source files and concat lowercased content for detection.
	// Limited to first 256KB to keep latency under 50ms on large trees.
	lower := scanSourceText(dir, 256*1024)

	p.HasTLS = strings.Contains(lower, "tls.") || strings.Contains(lower, "crypto/tls")
	p.HasAuth = strings.Contains(lower, "auth") || strings.Contains(lower, "jwt") || strings.Contains(lower, "oauth")
	p.HasDatabase = strings.Contains(lower, "sqlite") || strings.Contains(lower, "postgres") || strings.Contains(lower, "mysql") || strings.Contains(lower, "database")
	p.HasAPI = strings.Contains(lower, "http.listenandserve") || strings.Contains(lower, "gin.") || strings.Contains(lower, "router.") || strings.Contains(lower, "fastapi")
	p.HasGRPC = strings.Contains(lower, "grpc.") || strings.Contains(lower, "google.golang.org/grpc")
	p.HasCLI = strings.Contains(lower, "cobra.") || strings.Contains(lower, "os.args") || strings.Contains(lower, "flag.parse")
	p.HasWebUI = strings.Contains(lower, "<html") || strings.Contains(lower, "react") || strings.Contains(lower, "vue")
	p.HasLegacyCrypto = strings.Contains(lower, "rsa.") || strings.Contains(lower, "ecdsa.") || strings.Contains(lower, "ecdh.")
	p.HasPQC = strings.Contains(lower, "dilithium") || strings.Contains(lower, "kyber") || strings.Contains(lower, "mlkem") || strings.Contains(lower, "mldsa")
	p.HasAIAgent = strings.Contains(lower, "openai") || strings.Contains(lower, "anthropic") || strings.Contains(lower, "langchain") || strings.Contains(lower, "mcp")

	return p
}

// scanSourceText walks dir and returns a lowercased concatenation of source file
// content up to maxBytes total. Skips vendor/, node_modules/, .git/, and binary files.
func scanSourceText(dir string, maxBytes int) string {
	var sb strings.Builder
	skipDirs := map[string]bool{"vendor": true, "node_modules": true, ".git": true, ".next": true, "dist": true}
	sourceExts := map[string]bool{".go": true, ".py": true, ".js": true, ".ts": true, ".yaml": true, ".yml": true, ".json": true, ".mod": true}

	_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || sb.Len() >= maxBytes {
			return filepath.SkipAll
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !sourceExts[filepath.Ext(d.Name())] {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		remaining := maxBytes - sb.Len()
		if len(data) > remaining {
			data = data[:remaining]
		}
		sb.WriteString(strings.ToLower(string(data)))
		return nil
	})
	return sb.String()
}

// strideCategory constants.
const (
	strideS = "S — Spoofing"
	strideT = "T — Tampering"
	strideR = "R — Repudiation"
	strideI = "I — Information Disclosure"
	strideD = "D — Denial of Service"
	strideE = "E — Elevation of Privilege"
)

// buildSTRIDEThreatCatalog generates a contextual STRIDE threat list based on project profile.
func buildSTRIDEThreatCatalog(p projectProfile, scope string) []STRIDEThreat {
	var threats []STRIDEThreat
	id := 0
	nextID := func() string {
		id++
		return fmt.Sprintf("TM-%03d", id)
	}

	// ── Spoofing Threats ──────────────────────────────────────────────────────
	if p.HasAuth || p.HasAPI {
		threats = append(threats, STRIDEThreat{
			ID: nextID(), Category: strideS,
			Title:       "Agent/User Identity Spoofing",
			Description: "An adversary impersonates a legitimate user, agent, or service to gain unauthorized access. In AI/MCP environments, prompt injection may spoof agent identity.",
			Likelihood:  "High", Impact: "High", Risk: "High",
			NIST53: []string{"IA-2", "IA-3", "IA-5", "AC-2"},
			CMMC:   []string{"IA.L2-3.5.1", "IA.L2-3.5.3"},
			Mitigations: []string{
				"Enforce ML-DSA-65 signed credential tokens per ACP spec",
				"Mutual TLS with PQC certificate for service-to-service auth",
				"Implement per-invocation HMAC tokens (ASD/CISA ephemeral credentials)",
			},
			MITRETactics: []string{"T1078", "T1539"},
		})
	}

	if p.HasMCPServer || p.HasAIAgent {
		threats = append(threats, STRIDEThreat{
			ID: nextID(), Category: strideS,
			Title:       "MCP Tool Spoofing / Prompt Injection Identity Hijack",
			Description: "Adversary crafts malicious tool responses or prompt payloads that cause the AI agent to act as if it has different permissions (OWASP ASI-01 / ASI-02).",
			Likelihood:  "High", Impact: "Critical", Risk: "Critical",
			NIST53: []string{"SI-10", "AC-17", "IA-9"},
			CMMC:   []string{"SI.L2-3.14.2", "AC.L2-3.1.14"},
			Mitigations: []string{
				"Signed tool manifests with schema hash pinning (manifest.json)",
				"Output pipeline injection scanning (NSA CSI MCP mandate p.12-13)",
				"Scope taxonomy allow-list validation on all tool args",
			},
			MITRETactics: []string{"T1059.008", "T1562"},
		})
	}

	if p.HasLegacyCrypto && !p.HasPQC {
		threats = append(threats, STRIDEThreat{
			ID: nextID(), Category: strideS,
			Title:       "Quantum Authentication Break (Harvest Now, Decrypt Later)",
			Description: "RSA/ECDSA authentication credentials captured today can be cracked by cryptographically-relevant quantum computers (CRQCs) expected by 2030-2035 per CNSA 2.0 timeline.",
			Likelihood:  "Medium", Impact: "Critical", Risk: "Critical",
			NIST53: []string{"SC-13", "SC-28", "IA-5"},
			CMMC:   []string{"SC.L2-3.13.10", "IA.L2-3.5.7"},
			Mitigations: []string{
				"Migrate authentication to ML-DSA-65 (NIST FIPS 204)",
				"Implement hybrid X25519+ML-KEM-768 for TLS key exchange",
				"Begin CNSA 2.0 migration planning — NSS deadline: 2030",
			},
			MITRETactics: []string{"T1600"},
		})
	}

	// ── Tampering Threats ─────────────────────────────────────────────────────
	if p.HasAPI || p.HasGRPC {
		threats = append(threats, STRIDEThreat{
			ID: nextID(), Category: strideT,
			Title:       "API Request Tampering / MITM",
			Description: "Network-level attacker intercepts and modifies API requests or gRPC calls in transit, altering parameters or injecting malicious payloads.",
			Likelihood:  "Medium", Impact: "High", Risk: "High",
			NIST53: []string{"SC-8", "SC-28", "SI-10"},
			CMMC:   []string{"SC.L2-3.13.8", "SI.L2-3.14.2"},
			Mitigations: []string{
				"Enforce TLS 1.3 minimum with PQC hybrid cipher suites",
				"PQC-signed request envelopes (Adinkhepra ML-DSA-65)",
				"HMAC per-invocation tokens tied to request parameters",
			},
			MITRETactics: []string{"T1557", "T1565"},
		})
	}

	if p.HasMCPServer {
		threats = append(threats, STRIDEThreat{
			ID: nextID(), Category: strideT,
			Title:       "MCP Tool Schema Tampering (Confused Deputy)",
			Description: "Adversary replaces or alters the signed tool manifest to change tool behavior, expose new permissions, or bypass security controls (ASD/CISA confused-deputy pattern).",
			Likelihood:  "Low", Impact: "Critical", Risk: "High",
			NIST53: []string{"CM-3", "CM-5", "SI-7"},
			CMMC:   []string{"CM.L2-3.4.5", "SI.L2-3.14.6"},
			Mitigations: []string{
				"ML-DSA-65 signed manifest.json with fail-closed verification at startup",
				"Schema hash pinning: each tool call verified against pinned SchemaHash",
				"Immutable manifest in read-only container filesystem",
			},
			MITRETactics: []string{"T1565.001"},
		})
	}

	// ── Repudiation Threats ───────────────────────────────────────────────────
	threats = append(threats, STRIDEThreat{
		ID: nextID(), Category: strideR,
		Title:       "Agent Action Repudiation",
		Description: "An AI agent or automated process denies having performed an action — no tamper-evident audit trail links the action to the agent's identity and session.",
		Likelihood:  "Medium", Impact: "High", Risk: "High",
		NIST53: []string{"AU-2", "AU-3", "AU-9", "AU-10"},
		CMMC:   []string{"AU.L2-3.3.1", "AU.L2-3.3.2"},
		Mitigations: []string{
			"ML-DSA-65 signed DAG audit chain — every tool call DAG-anchored",
			"Tamper-evident NDJSON signed audit log (DFARS 252.204-7012)",
			"Per-invocation signed tokens with agent_id + tool_name binding",
		},
		MITRETactics: []string{"T1562.002"},
	})

	// ── Information Disclosure Threats ────────────────────────────────────────
	if p.HasLegacyCrypto {
		threats = append(threats, STRIDEThreat{
			ID: nextID(), Category: strideI,
			Title:       "Sensitive Data Exposure via Weak Cryptography",
			Description: "RSA/ECDSA encrypted data is vulnerable to 'harvest now, decrypt later' attacks. Quantum adversaries store encrypted traffic today for decryption when CRQCs become available.",
			Likelihood:  "Medium", Impact: "Critical", Risk: "Critical",
			NIST53: []string{"SC-13", "SC-28", "SC-8"},
			CMMC:   []string{"SC.L2-3.13.10", "SC.L2-3.13.16"},
			Mitigations: []string{
				"Migrate to ML-KEM-768 for key encapsulation (NIST FIPS 203)",
				"Apply hybrid TLS: X25519+ML-KEM-768 (IETF draft-ietf-tls-hybrid-design)",
				"Prioritize data classification — encrypt highest-sensitivity data first",
			},
			MITRETactics: []string{"T1600", "T1040"},
		})
	}

	if p.HasMCPServer || p.HasAIAgent {
		threats = append(threats, STRIDEThreat{
			ID: nextID(), Category: strideI,
			Title:       "Prompt Injection Data Exfiltration (OWASP ASI-06)",
			Description: "Malicious content in tool outputs instructs the AI agent to exfiltrate sensitive context — conversation history, system prompts, or internal tool responses — to external endpoints.",
			Likelihood:  "High", Impact: "High", Risk: "High",
			NIST53: []string{"SI-3", "AC-4", "SC-7"},
			CMMC:   []string{"SI.L2-3.14.2", "AC.L2-3.1.3", "SC.L2-3.13.1"},
			Mitigations: []string{
				"Output pipeline injection scanning (non-fatal warning + logging)",
				"KHEPRA_MODE=sovereign blocks all outbound network calls",
				"Tool scope taxonomy allow-list prevents unexpected parameter access",
			},
			MITRETactics: []string{"T1567", "T1048"},
		})
	}

	// ── Denial of Service Threats ─────────────────────────────────────────────
	if p.HasAPI || p.HasMCPServer {
		threats = append(threats, STRIDEThreat{
			ID: nextID(), Category: strideD,
			Title:       "MCP Prompt Storm / Resource Exhaustion",
			Description: "An adversarial agent floods the MCP server with concurrent or looping tool calls, exhausting server resources (CPU, memory, file handles) or triggering expensive operations repeatedly.",
			Likelihood:  "Medium", Impact: "High", Risk: "High",
			NIST53: []string{"SC-5", "SI-17", "AC-10"},
			CMMC:   []string{"SC.L2-3.13.11", "AC.L2-3.1.10"},
			Mitigations: []string{
				"Per-agent concurrency cap (KHEPRA_MAX_CONCURRENT, default: 5)",
				"Rate limiter: 100 req/min per agent (configurable)",
				"Loop/mistake detection: exponential backoff on repeated identical calls",
				"Tool timeout enforcement: per-tool TimeoutMs in manifest",
			},
			MITRETactics: []string{"T1499", "T1498"},
		})
	}

	// ── Elevation of Privilege Threats ────────────────────────────────────────
	if p.HasMCPServer || p.HasAuth {
		threats = append(threats, STRIDEThreat{
			ID: nextID(), Category: strideE,
			Title:       "Tool Scope Escalation via Injection",
			Description: "Prompt injection or crafted tool arguments cause an agent to invoke tools with broader privileges than authorized — e.g., calling a destructive tool via parameters injected by malicious content.",
			Likelihood:  "High", Impact: "Critical", Risk: "Critical",
			NIST53: []string{"AC-3", "AC-6", "IA-9"},
			CMMC:   []string{"AC.L2-3.1.1", "AC.L2-3.1.2", "AC.L2-3.1.5"},
			Mitigations: []string{
				"RBAC scope taxonomy: every tool has a declared scope, checked at Step 4",
				"Destructive tool human-in-the-loop gate (godfather_approve pattern)",
				"Injection scanner on inbound args before any tool execution",
				"Signed invocation tokens binding agent_id + tool_name + target",
			},
			MITRETactics: []string{"T1068", "T1548"},
		})
	}

	if p.HasDatabase {
		threats = append(threats, STRIDEThreat{
			ID: nextID(), Category: strideE,
			Title:       "Database Privilege Escalation via SQL Injection",
			Description: "Unsanitized input passed to database queries allows attacker to escalate from read to write, or access data outside their authorized scope.",
			Likelihood:  "Medium", Impact: "High", Risk: "High",
			NIST53: []string{"SI-10", "AC-3", "AC-6"},
			CMMC:   []string{"SI.L2-3.14.2", "AC.L2-3.1.1"},
			Mitigations: []string{
				"Parameterized queries / prepared statements throughout",
				"Principle of least privilege for database service accounts",
				"Input validation at API boundary before database layer",
			},
			MITRETactics: []string{"T1190"},
		})
	}

	return threats
}

// buildMITREMatrix returns ATT&CK techniques relevant to the project profile.
func buildMITREMatrix(p projectProfile) []MITRETechEntry {
	var matrix []MITRETechEntry

	if p.HasAPI || p.HasAuth {
		matrix = append(matrix,
			MITRETechEntry{TechID: "T1078", Name: "Valid Accounts", Tactic: "Defense Evasion / Persistence", Relevance: "Compromised API credentials enable persistent access", Mitigation: "IA-2, IA-5 — PQC-signed credential tokens"},
			MITRETechEntry{TechID: "T1190", Name: "Exploit Public-Facing Application", Tactic: "Initial Access", Relevance: "Public API endpoints as entry point", Mitigation: "SI-10 — Input validation; RA-5 — Vulnerability scanning"},
		)
	}
	if p.HasMCPServer || p.HasAIAgent {
		matrix = append(matrix,
			MITRETechEntry{TechID: "T1059.008", Name: "AI/ML Prompt Injection", Tactic: "Execution", Relevance: "Malicious content in tool outputs hijacks agent execution", Mitigation: "SI-10 — Output filtering; SI-3 — Malicious code protection"},
			MITRETechEntry{TechID: "T1562", Name: "Impair Defenses", Tactic: "Defense Evasion", Relevance: "Agent manipulated to disable security controls", Mitigation: "AU-2 — Audit events; CM-3 — Change control"},
		)
	}
	if p.HasLegacyCrypto {
		matrix = append(matrix,
			MITRETechEntry{TechID: "T1600", Name: "Weaken Encryption", Tactic: "Defense Evasion", Relevance: "Quantum adversaries break RSA/ECDSA when CRQCs available", Mitigation: "SC-13 — PQC migration (FIPS 203/204/205)"},
			MITRETechEntry{TechID: "T1040", Name: "Network Sniffing (Harvest Now)", Tactic: "Credential Access", Relevance: "Encrypted traffic captured for future quantum decryption", Mitigation: "SC-8 — TLS 1.3 + ML-KEM-768 hybrid"},
		)
	}
	if p.HasDatabase {
		matrix = append(matrix,
			MITRETechEntry{TechID: "T1005", Name: "Data from Local System", Tactic: "Collection", Relevance: "Database files accessible if process runs with excess privileges", Mitigation: "AC-6 — Least privilege; SC-28 — Data at rest encryption"},
		)
	}

	return matrix
}

// buildThreatModelSummary creates an executive summary string.
func buildThreatModelSummary(critical, high, total int, p projectProfile) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("STRIDE threat model identified %d threats (%d Critical, %d High). ", total, critical, high))

	if critical > 0 {
		sb.WriteString("Critical findings require immediate architectural review. ")
	}
	if p.HasMCPServer {
		sb.WriteString("MCP server threat surface includes prompt injection (OWASP ASI-01), tool schema tampering, and agent impersonation — all addressed by KHEPRA's security chain. ")
	}
	if p.HasLegacyCrypto && !p.HasPQC {
		sb.WriteString("QUANTUM RISK: RSA/ECDSA usage without PQC migration creates a critical long-term exposure. Begin CNSA 2.0 migration immediately per NSM-10 timeline. ")
	} else if p.HasPQC {
		sb.WriteString("PQC algorithms detected — system is on the CNSA 2.0 migration path. Verify FIPS 203/204/205 compliance with pqc_stig. ")
	}
	sb.WriteString("Run ert_godfather for dollar-denominated risk quantification (FAIR model).")

	return sb.String()
}
