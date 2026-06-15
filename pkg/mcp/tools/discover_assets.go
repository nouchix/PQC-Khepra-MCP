package tools

// discover_assets.go — SouHimBou AI Step 01: Discover & Classify Assets.
//
// Automatically inventories an environment and identifies applicable STIGs
// based on asset type, OS, software stack, and runtime detected.
//
// Output: AssetInventory — consumed by Step 02 (Map Controls) and Step 03
// (Generate Evidence). Can be used standalone or chained into stig_check /
// cmmc_assess / ert_architect.
//
// 100% offline. No network calls. Reads filesystem + env only.

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/nouchix/PQC-Khepra-MCP/pkg/mcp"
)

// ─── Types ────────────────────────────────────────────────────────────────────

// AssetInventory is the output of discover_assets.
// It drives Step 02 (control mapping) and Step 03 (evidence generation).
type AssetInventory struct {
	// Scan metadata
	InventoryID  string    `json:"inventory_id"`
	ScannedAt    time.Time `json:"scanned_at"`
	ScanRoot     string    `json:"scan_root"`
	ScanDepth    int       `json:"scan_depth"`

	// Asset identity
	Hostname     string    `json:"hostname"`
	GOOS         string    `json:"goos"`           // runtime.GOOS
	GOARCH       string    `json:"goarch"`         // runtime.GOARCH
	OSRelease    *OSRelease `json:"os_release,omitempty"` // /etc/os-release

	// Detected asset types
	Assets       []DetectedAsset `json:"assets"`
	AssetCount   int             `json:"asset_count"`

	// Applicable STIG profiles (driven by asset detection)
	ApplicableSTIGs  []STIGProfile  `json:"applicable_stigs"`
	RecommendedLevel string         `json:"recommended_cmmc_level"` // "L1" | "L2" | "L3"

	// Software stack fingerprint
	LanguageRuntimes []LanguageRuntime `json:"language_runtimes,omitempty"`
	ContainerImages  []ContainerImage  `json:"container_images,omitempty"`
	Databases        []string          `json:"databases_detected,omitempty"`
	WebFrameworks    []string          `json:"web_frameworks_detected,omitempty"`

	// Risk indicators (feed into Step 02 control prioritization)
	RiskIndicators []RiskIndicator `json:"risk_indicators,omitempty"`

	// Step 02 handoff
	SuggestedTools []ToolSuggestion `json:"suggested_next_tools"`
}

// DetectedAsset represents a single classified asset.
type DetectedAsset struct {
	Type        AssetType `json:"type"`
	Name        string    `json:"name"`
	Path        string    `json:"path,omitempty"`
	Version     string    `json:"version,omitempty"`
	Confidence  string    `json:"confidence"` // "high" | "medium" | "low"
	Description string    `json:"description"`
}

// AssetType classifies the kind of asset detected.
type AssetType string

const (
	AssetTypeOS           AssetType = "operating_system"
	AssetTypeContainer    AssetType = "container_runtime"
	AssetTypeLanguage     AssetType = "language_runtime"
	AssetTypeDatabase     AssetType = "database"
	AssetTypeWebServer    AssetType = "web_server"
	AssetTypeCICD         AssetType = "cicd_pipeline"
	AssetTypeIaC          AssetType = "infrastructure_as_code"
	AssetTypeAIAgent      AssetType = "ai_agent"
	AssetTypeCrypto       AssetType = "cryptographic_library"
	AssetTypeSecretStore  AssetType = "secret_store"
	AssetTypeMCPServer    AssetType = "mcp_server"
)

// STIGProfile represents an applicable STIG for detected assets.
type STIGProfile struct {
	STIGID      string   `json:"stig_id"`
	Title       string   `json:"title"`
	Version     string   `json:"version"`
	Severity    string   `json:"severity"`    // "critical" | "high" | "medium"
	AppliesTo   []string `json:"applies_to"`  // asset names that triggered this
	CMMCDomains []string `json:"cmmc_domains"` // CMMC 2.0 domain coverage
	Priority    int      `json:"priority"`    // 1 = must-do, 2 = should-do, 3 = nice-to-have
}

// LanguageRuntime records a detected programming language/runtime.
type LanguageRuntime struct {
	Language  string `json:"language"`
	Version   string `json:"version,omitempty"`
	ConfigFile string `json:"config_file,omitempty"`
}

// ContainerImage records a detected container image reference.
type ContainerImage struct {
	Reference string `json:"reference"`
	Source    string `json:"source"` // "Dockerfile" | "docker-compose" | "k8s_manifest"
}

// RiskIndicator flags a specific risk finding during discovery.
type RiskIndicator struct {
	Severity    string `json:"severity"` // "critical" | "high" | "medium" | "low"
	Category    string `json:"category"`
	Description string `json:"description"`
	File        string `json:"file,omitempty"`
	Remediation string `json:"remediation"`
}

// ToolSuggestion recommends the next KHEPRA tool to run based on discovery.
type ToolSuggestion struct {
	Tool        string            `json:"tool"`
	Reason      string            `json:"reason"`
	Priority    int               `json:"priority"` // 1 = run first
	SuggestedArgs map[string]string `json:"suggested_args,omitempty"`
}

// OSRelease holds parsed /etc/os-release fields.
type OSRelease struct {
	ID         string `json:"id"`
	VersionID  string `json:"version_id"`
	PrettyName string `json:"pretty_name"`
}

// ─── Handler ─────────────────────────────────────────────────────────────────

// HandleDiscoverAssets implements the discover_assets MCP tool.
// SouHimBou AI Step 01: Discover & Classify Assets.
func HandleDiscoverAssets(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	projectPath, _ := call.Args["project_path"].(string)
	if projectPath == "" {
		projectPath = "."
	}
	depthArg, _ := call.Args["depth"].(float64)
	maxDepth := int(depthArg)
	if maxDepth <= 0 {
		maxDepth = 4
	}

	absPath, err := filepath.Abs(projectPath)
	if err != nil {
		return nil, nil, fmt.Errorf("discover_assets: invalid path: %w", err)
	}

	hostname, _ := os.Hostname()
	inv := &AssetInventory{
		InventoryID: generateInventoryID(),
		ScannedAt:   time.Now().UTC(),
		ScanRoot:    absPath,
		ScanDepth:   maxDepth,
		Hostname:    hostname,
		GOOS:        runtime.GOOS,
		GOARCH:      runtime.GOARCH,
	}

	// ── OS Detection ─────────────────────────────────────────────────────────
	detectOS(inv, absPath)

	// ── Filesystem Walk: classify assets ─────────────────────────────────────
	walkAssets(inv, absPath, maxDepth)

	// ── Language Runtime Detection ────────────────────────────────────────────
	detectLanguageRuntimes(inv, absPath)

	// ── Container Detection ───────────────────────────────────────────────────
	detectContainers(inv, absPath)

	// ── Secret / Credential Risk Scan ────────────────────────────────────────
	detectSecretRisks(inv, absPath)

	// ── MCP Server Detection ──────────────────────────────────────────────────
	detectMCPPresence(inv, absPath)

	// ── STIG Profile Matching ─────────────────────────────────────────────────
	matchSTIGProfiles(inv)

	// ── CMMC Level Recommendation ────────────────────────────────────────────
	inv.RecommendedLevel = recommendCMMCLevel(inv)

	// ── Next Tool Suggestions (Step 02 handoff) ───────────────────────────────
	inv.SuggestedTools = buildToolSuggestions(inv)

	inv.AssetCount = len(inv.Assets)

	var warnings []string
	if len(inv.RiskIndicators) > 0 {
		critCount := 0
		for _, r := range inv.RiskIndicators {
			if r.Severity == "critical" || r.Severity == "high" {
				critCount++
			}
		}
		if critCount > 0 {
			warnings = append(warnings, fmt.Sprintf("%d high/critical risk indicators detected — run ert_scan and stig_check immediately", critCount))
		}
	}
	if len(inv.ApplicableSTIGs) == 0 {
		warnings = append(warnings, "No STIG profiles matched — verify project_path contains a deployable system")
	}
	if inv.RecommendedLevel == "L2" || inv.RecommendedLevel == "L3" {
		warnings = append(warnings, fmt.Sprintf("CMMC %s indicators detected — CUI handling controls apply. Run cmmc_assess for full gap analysis.", inv.RecommendedLevel))
	}

	return inv, warnings, nil
}

// ─── Detection Functions ─────────────────────────────────────────────────────

func detectOS(inv *AssetInventory, root string) {
	// Runtime OS
	osName := runtime.GOOS
	osArch := runtime.GOARCH

	// Try to read /etc/os-release (Linux containers on Windows host will have this in project)
	osReleasePaths := []string{
		"/etc/os-release",
		filepath.Join(root, "etc", "os-release"),
		filepath.Join(root, ".devcontainer", "os-release"),
	}
	for _, p := range osReleasePaths {
		if rel := parseOSRelease(p); rel != nil {
			inv.OSRelease = rel
			inv.Assets = append(inv.Assets, DetectedAsset{
				Type:        AssetTypeOS,
				Name:        rel.PrettyName,
				Version:     rel.VersionID,
				Confidence:  "high",
				Description: fmt.Sprintf("Linux OS: %s %s (from %s)", rel.ID, rel.VersionID, p),
			})
			return
		}
	}

	// Fallback: host OS
	inv.Assets = append(inv.Assets, DetectedAsset{
		Type:        AssetTypeOS,
		Name:        osName,
		Version:     osArch,
		Confidence:  "high",
		Description: fmt.Sprintf("Host OS: %s/%s", osName, osArch),
	})
}

func parseOSRelease(path string) *OSRelease {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	rel := &OSRelease{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "ID=") {
			rel.ID = strings.Trim(strings.TrimPrefix(line, "ID="), "\"")
		} else if strings.HasPrefix(line, "VERSION_ID=") {
			rel.VersionID = strings.Trim(strings.TrimPrefix(line, "VERSION_ID="), "\"")
		} else if strings.HasPrefix(line, "PRETTY_NAME=") {
			rel.PrettyName = strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), "\"")
		}
	}
	if rel.ID == "" {
		return nil
	}
	return rel
}

// assetSignatures maps filename patterns to asset classifications.
var assetSignatures = []struct {
	pattern   string // substring match against filename
	assetType AssetType
	name      string
	desc      string
}{
	// Go
	{"go.mod", AssetTypeLanguage, "Go", "Go module definition"},
	// Python
	{"requirements.txt", AssetTypeLanguage, "Python", "Python dependency manifest"},
	{"pyproject.toml", AssetTypeLanguage, "Python", "Python project config"},
	{"setup.py", AssetTypeLanguage, "Python", "Python package setup"},
	// Node
	{"package.json", AssetTypeLanguage, "Node.js", "Node.js package manifest"},
	// Java
	{"pom.xml", AssetTypeLanguage, "Java/Maven", "Maven project descriptor"},
	{"build.gradle", AssetTypeLanguage, "Java/Gradle", "Gradle build script"},
	// Rust
	{"Cargo.toml", AssetTypeLanguage, "Rust", "Rust crate manifest"},
	// Container
	{"Dockerfile", AssetTypeContainer, "Docker", "Docker container definition"},
	{"docker-compose.yml", AssetTypeContainer, "Docker Compose", "Multi-container orchestration"},
	{"docker-compose.yaml", AssetTypeContainer, "Docker Compose", "Multi-container orchestration"},
	// Kubernetes
	{"deployment.yaml", AssetTypeContainer, "Kubernetes", "K8s deployment manifest"},
	{"deployment.yml", AssetTypeContainer, "Kubernetes", "K8s deployment manifest"},
	// IaC
	{"terraform", AssetTypeIaC, "Terraform", "Infrastructure as Code"},
	{"main.tf", AssetTypeIaC, "Terraform", "Terraform configuration"},
	{"ansible", AssetTypeIaC, "Ansible", "Configuration management"},
	// CI/CD
	{".github/workflows", AssetTypeCICD, "GitHub Actions", "CI/CD pipeline"},
	{".gitlab-ci.yml", AssetTypeCICD, "GitLab CI", "CI/CD pipeline"},
	{"Jenkinsfile", AssetTypeCICD, "Jenkins", "CI/CD pipeline"},
	// MCP
	{".mcp.json", AssetTypeMCPServer, "MCP Server", "Model Context Protocol server config"},
	{"mcp.json", AssetTypeMCPServer, "MCP Server", "Model Context Protocol server config"},
	// Secret stores
	{".env", AssetTypeSecretStore, "dotenv", "Environment variable file (secret risk)"},
	{"vault", AssetTypeSecretStore, "HashiCorp Vault", "Secret management"},
	{"secrets.yaml", AssetTypeSecretStore, "K8s Secret", "Kubernetes secret manifest"},
	// Databases
	{"postgres", AssetTypeDatabase, "PostgreSQL", "Relational database"},
	{"mysql", AssetTypeDatabase, "MySQL", "Relational database"},
	{"mongo", AssetTypeDatabase, "MongoDB", "Document database"},
	{"redis", AssetTypeDatabase, "Redis", "In-memory store"},
	{"supabase", AssetTypeDatabase, "Supabase", "Postgres-as-a-service"},
	// AI agents
	{"claude", AssetTypeAIAgent, "Claude", "Anthropic AI agent"},
	{"openai", AssetTypeAIAgent, "OpenAI", "OpenAI API integration"},
	{"langchain", AssetTypeAIAgent, "LangChain", "AI agent framework"},
	{"langgraph", AssetTypeAIAgent, "LangGraph", "AI agent framework"},
	// Crypto libraries
	{"openssl", AssetTypeCrypto, "OpenSSL", "Cryptographic library"},
	{"dilithium", AssetTypeCrypto, "Dilithium/ML-DSA", "Post-quantum cryptography"},
	{"kyber", AssetTypeCrypto, "Kyber/ML-KEM", "Post-quantum key encapsulation"},
}

func walkAssets(inv *AssetInventory, root string, maxDepth int) {
	seen := make(map[string]bool)

	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}

		// Depth limit
		rel, _ := filepath.Rel(root, path)
		depth := len(strings.Split(rel, string(filepath.Separator)))
		if depth > maxDepth {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}

		// Skip noise directories
		name := d.Name()
		if d.IsDir() {
			skip := []string{".git", "node_modules", "vendor", "__pycache__", ".venv", "dist", "build", ".next", "target"}
			for _, s := range skip {
				if name == s {
					return filepath.SkipDir
				}
			}
			return nil
		}

		lowerName := strings.ToLower(name)
		lowerPath := strings.ToLower(path)

		for _, sig := range assetSignatures {
			if strings.Contains(lowerName, strings.ToLower(sig.pattern)) ||
				strings.Contains(lowerPath, strings.ToLower(sig.pattern)) {
				key := string(sig.assetType) + ":" + sig.name
				if !seen[key] {
					seen[key] = true
					inv.Assets = append(inv.Assets, DetectedAsset{
						Type:        sig.assetType,
						Name:        sig.name,
						Path:        rel,
						Confidence:  "high",
						Description: sig.desc,
					})
				}
				break
			}
		}
		return nil
	})
}

func detectLanguageRuntimes(inv *AssetInventory, root string) {
	checks := []struct {
		file    string
		lang    string
		versionFile string
	}{
		{"go.mod", "Go", "go.mod"},
		{"requirements.txt", "Python", ""},
		{"pyproject.toml", "Python", "pyproject.toml"},
		{"package.json", "Node.js", "package.json"},
		{"pom.xml", "Java", "pom.xml"},
		{"Cargo.toml", "Rust", "Cargo.toml"},
	}

	seen := make(map[string]bool)
	for _, c := range checks {
		p := filepath.Join(root, c.file)
		if _, err := os.Stat(p); err == nil {
			if !seen[c.lang] {
				seen[c.lang] = true
				ver := extractVersion(p, c.lang)
				inv.LanguageRuntimes = append(inv.LanguageRuntimes, LanguageRuntime{
					Language:   c.lang,
					Version:    ver,
					ConfigFile: c.file,
				})
			}
		}
	}
}

func extractVersion(configFile, lang string) string {
	data, err := os.ReadFile(configFile)
	if err != nil {
		return ""
	}
	content := string(data)
	lines := strings.Split(content, "\n")

	switch lang {
	case "Go":
		for _, line := range lines {
			if strings.HasPrefix(strings.TrimSpace(line), "go ") {
				return strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "go "))
			}
		}
	case "Node.js":
		// Try parsing package.json for node engine field
		var pkg struct {
			Engines struct {
				Node string `json:"node"`
			} `json:"engines"`
			Version string `json:"version"`
		}
		if json.Unmarshal(data, &pkg) == nil && pkg.Engines.Node != "" {
			return pkg.Engines.Node
		}
	case "Rust":
		for _, line := range lines {
			if strings.HasPrefix(line, "edition") {
				parts := strings.SplitN(line, "=", 2)
				if len(parts) == 2 {
					return strings.Trim(strings.TrimSpace(parts[1]), "\"")
				}
			}
		}
	}
	return ""
}

func detectContainers(inv *AssetInventory, root string) {
	// Scan Dockerfiles for FROM directives
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if d.Name() == "Dockerfile" || strings.HasSuffix(d.Name(), ".dockerfile") {
			data, readErr := os.ReadFile(path)
			if readErr != nil {
				return nil
			}
			rel, _ := filepath.Rel(root, path)
			for _, line := range strings.Split(string(data), "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(strings.ToUpper(line), "FROM ") {
					image := strings.Fields(line)[1]
					inv.ContainerImages = append(inv.ContainerImages, ContainerImage{
						Reference: image,
						Source:    rel,
					})
				}
			}
		}
		return nil
	})
}

func detectSecretRisks(inv *AssetInventory, root string) {
	// Check for .env files without .gitignore protection
	envPath := filepath.Join(root, ".env")
	if _, err := os.Stat(envPath); err == nil {
		gitignorePath := filepath.Join(root, ".gitignore")
		protected := false
		if gi, err := os.ReadFile(gitignorePath); err == nil {
			protected = strings.Contains(string(gi), ".env")
		}
		if !protected {
			inv.RiskIndicators = append(inv.RiskIndicators, RiskIndicator{
				Severity:    "high",
				Category:    "secret_exposure",
				Description: ".env file present without .gitignore protection — credentials may be committed to version control",
				File:        ".env",
				Remediation: "Add .env to .gitignore immediately. Rotate any exposed credentials.",
			})
		}
	}

	// Check for hardcoded key patterns in Go files
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, ".py") && !strings.HasSuffix(path, ".js") {
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		content := strings.ToLower(string(data))
		dangerPatterns := []string{"password =", "secret =", "api_key =", "private_key =", "aws_access"}
		for _, pat := range dangerPatterns {
			if strings.Contains(content, pat) {
				rel, _ := filepath.Rel(root, path)
				inv.RiskIndicators = append(inv.RiskIndicators, RiskIndicator{
					Severity:    "critical",
					Category:    "hardcoded_credential",
					Description: fmt.Sprintf("Potential hardcoded credential pattern %q in %s", pat, rel),
					File:        rel,
					Remediation: "Move to environment variables or a secrets manager. Rotate the credential immediately.",
				})
				return nil // one finding per file is enough
			}
		}
		return nil
	})
}

func detectMCPPresence(inv *AssetInventory, root string) {
	mcpConfigs := []string{".mcp.json", "mcp.json", "claude_desktop_config.json"}
	for _, cfg := range mcpConfigs {
		p := filepath.Join(root, cfg)
		if _, err := os.Stat(p); err == nil {
			inv.Assets = append(inv.Assets, DetectedAsset{
				Type:        AssetTypeMCPServer,
				Name:        "MCP Configuration",
				Path:        cfg,
				Confidence:  "high",
				Description: "Model Context Protocol server configuration — KHEPRA security layer applicable",
			})
		}
	}
}

// ─── STIG Profile Matching ───────────────────────────────────────────────────

// stigLibrary maps asset detections to applicable STIG profiles.
var stigLibrary = []struct {
	triggers    []AssetType
	keywords    []string // asset names that trigger this
	profile     STIGProfile
}{
	{
		triggers: []AssetType{AssetTypeOS},
		keywords: []string{"rhel", "red hat", "9", "rocky", "alma"},
		profile: STIGProfile{
			STIGID:   "RHEL-09-STIG-V1R3",
			Title:    "Red Hat Enterprise Linux 9 STIG V1R3",
			Version:  "V1R3",
			Severity: "critical",
			CMMCDomains: []string{"AC", "AU", "CM", "IA", "SC", "SI"},
			Priority: 1,
		},
	},
	{
		triggers: []AssetType{AssetTypeContainer},
		keywords: []string{"docker", "container", "kubernetes"},
		profile: STIGProfile{
			STIGID:   "CONTAINER-STIG-V2R1",
			Title:    "Container Platform STIG V2R1",
			Version:  "V2R1",
			Severity: "high",
			CMMCDomains: []string{"CM", "SC", "SI"},
			Priority: 1,
		},
	},
	{
		triggers: []AssetType{AssetTypeCrypto, AssetTypeLanguage},
		keywords: []string{"openssl", "go", "python", "java"},
		profile: STIGProfile{
			STIGID:   "CNSA-2.0-PQC",
			Title:    "CNSA 2.0 Post-Quantum Cryptography Readiness",
			Version:  "2.0",
			Severity: "high",
			CMMCDomains: []string{"SC"},
			Priority: 1,
		},
	},
	{
		triggers: []AssetType{AssetTypeAIAgent, AssetTypeMCPServer},
		keywords: []string{"claude", "openai", "mcp", "agent"},
		profile: STIGProfile{
			STIGID:   "AI-AGENT-MCP-SEC-V1",
			Title:    "AI Agent / MCP Server Security Baseline (KHEPRA PQC-01-STIG)",
			Version:  "V1.0",
			Severity: "high",
			CMMCDomains: []string{"AC", "AU", "CM", "IA", "SI"},
			Priority: 1,
		},
	},
	{
		triggers: []AssetType{AssetTypeCICD},
		keywords: []string{"github actions", "gitlab ci", "jenkins"},
		profile: STIGProfile{
			STIGID:   "CICD-SUPPLY-CHAIN-V1",
			Title:    "CI/CD Pipeline Supply Chain Security",
			Version:  "V1.0",
			Severity: "high",
			CMMCDomains: []string{"CM", "SA", "SI"},
			Priority: 2,
		},
	},
	{
		triggers: []AssetType{AssetTypeDatabase},
		keywords: []string{"postgres", "mysql", "mongo", "supabase"},
		profile: STIGProfile{
			STIGID:   "DB-STIG-V2",
			Title:    "Database STIG (General) V2",
			Version:  "V2.0",
			Severity: "high",
			CMMCDomains: []string{"AC", "AU", "SC"},
			Priority: 2,
		},
	},
	{
		triggers: []AssetType{AssetTypeSecretStore},
		keywords: []string{".env", "vault", "secret"},
		profile: STIGProfile{
			STIGID:   "IAM-SECRET-MGMT-V1",
			Title:    "Identity & Access Management — Secret Handling Baseline",
			Version:  "V1.0",
			Severity: "high",
			CMMCDomains: []string{"IA", "AC"},
			Priority: 1,
		},
	},
}

func matchSTIGProfiles(inv *AssetInventory) {
	seen := make(map[string]bool)

	// Build lookup sets
	assetTypes := make(map[AssetType]bool)
	assetNames := make(map[string]bool)
	for _, a := range inv.Assets {
		assetTypes[a.Type] = true
		assetNames[strings.ToLower(a.Name)] = true
	}
	for _, r := range inv.LanguageRuntimes {
		assetNames[strings.ToLower(r.Language)] = true
	}
	for _, img := range inv.ContainerImages {
		assetNames[strings.ToLower(img.Reference)] = true
	}

	for _, entry := range stigLibrary {
		// Check type trigger
		typeMatch := false
		for _, t := range entry.triggers {
			if assetTypes[t] {
				typeMatch = true
				break
			}
		}
		if !typeMatch {
			continue
		}

		// Check keyword match
		var triggeredBy []string
		for _, kw := range entry.keywords {
			for name := range assetNames {
				if strings.Contains(name, strings.ToLower(kw)) {
					triggeredBy = append(triggeredBy, name)
					break
				}
			}
		}
		if len(triggeredBy) == 0 {
			// If no keywords required (open match), still include
			for _, a := range inv.Assets {
				for _, t := range entry.triggers {
					if a.Type == t {
						triggeredBy = append(triggeredBy, a.Name)
						break
					}
				}
			}
		}

		if !seen[entry.profile.STIGID] && len(triggeredBy) > 0 {
			seen[entry.profile.STIGID] = true
			p := entry.profile
			p.AppliesTo = triggeredBy
			sort.Strings(p.AppliesTo)
			inv.ApplicableSTIGs = append(inv.ApplicableSTIGs, p)
		}
	}

	// Sort by priority
	sort.Slice(inv.ApplicableSTIGs, func(i, j int) bool {
		return inv.ApplicableSTIGs[i].Priority < inv.ApplicableSTIGs[j].Priority
	})
}

func recommendCMMCLevel(inv *AssetInventory) string {
	// L3 indicators: PQC, DoD-specific, classified data signals
	for _, a := range inv.Assets {
		if a.Type == AssetTypeCrypto && strings.Contains(strings.ToLower(a.Name), "dilithium") {
			return "L3"
		}
	}
	// L2 indicators: CUI-handling assets — databases, secret stores, CI/CD, MCP
	for _, a := range inv.Assets {
		if a.Type == AssetTypeDatabase || a.Type == AssetTypeSecretStore ||
			a.Type == AssetTypeCICD || a.Type == AssetTypeMCPServer ||
			a.Type == AssetTypeAIAgent {
			return "L2"
		}
	}
	// Default: L1
	return "L1"
}

func buildToolSuggestions(inv *AssetInventory) []ToolSuggestion {
	var suggestions []ToolSuggestion
	priority := 1

	// Always suggest stig_check if STIG profiles matched
	if len(inv.ApplicableSTIGs) > 0 {
		firstSTIG := inv.ApplicableSTIGs[0].STIGID
		suggestions = append(suggestions, ToolSuggestion{
			Tool:     "stig_check",
			Reason:   fmt.Sprintf("STIG profile %s matched — run full control check", firstSTIG),
			Priority: priority,
			SuggestedArgs: map[string]string{
				"framework":    firstSTIG,
				"project_path": inv.ScanRoot,
			},
		})
		priority++
	}

	// PQC inventory if crypto assets detected
	for _, a := range inv.Assets {
		if a.Type == AssetTypeCrypto || a.Type == AssetTypeLanguage {
			suggestions = append(suggestions, ToolSuggestion{
				Tool:     "ert_crypto",
				Reason:   "Cryptographic library detected — run PQC inventory to assess CNSA 2.0 readiness",
				Priority: priority,
				SuggestedArgs: map[string]string{"project_path": inv.ScanRoot},
			})
			priority++
			break
		}
	}

	// Supply chain scan if package manifests detected
	for _, lr := range inv.LanguageRuntimes {
		_ = lr
		suggestions = append(suggestions, ToolSuggestion{
			Tool:     "ert_architect",
			Reason:   "Language runtimes detected — run SBOM + CVE supply chain scan",
			Priority: priority,
			SuggestedArgs: map[string]string{"project_path": inv.ScanRoot},
		})
		priority++
		break
	}

	// CMMC assessment
	suggestions = append(suggestions, ToolSuggestion{
		Tool:     "cmmc_assess",
		Reason:   fmt.Sprintf("CMMC %s indicators detected — run full gap assessment", inv.RecommendedLevel),
		Priority: priority,
		SuggestedArgs: map[string]string{
			"level":        inv.RecommendedLevel,
			"project_path": inv.ScanRoot,
		},
	})
	priority++

	// Evidence export
	suggestions = append(suggestions, ToolSuggestion{
		Tool:     "flight_export",
		Reason:   "After scanning, export CMMC-aligned evidence packet with control mappings",
		Priority: priority,
	})

	return suggestions
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func generateInventoryID() string {
	return fmt.Sprintf("inv-%d", time.Now().UnixNano()%1_000_000_000)
}
