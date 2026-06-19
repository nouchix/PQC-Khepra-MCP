
// +build ignore

// gen_manifest.go — regenerates manifest.json with all 72 registered tools.
// Run: go run gen_manifest.go
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

type ArgsSchema struct {
	Properties map[string]map[string]any `json:"properties,omitempty"`
	Required   []string                 `json:"required,omitempty"`
	Type       string                   `json:"type"`
}

type ToolEntry struct {
	Name           string      `json:"name"`
	Description    string      `json:"description"`
	RiskClass      string      `json:"risk_class"`
	Scope          string      `json:"scope"`
	SchemaVersion  string      `json:"schema_version"`
	SchemaHash     string      `json:"schema_hash"`
	AllowedBackend string      `json:"allowed_backend"`
	TimeoutMs      int         `json:"timeout_ms"`
	NetworkAllowed bool        `json:"network_allowed"`
	Destructive    bool        `json:"destructive"`
	Tier           string      `json:"tier,omitempty"`
	ArgsSchema     *ArgsSchema `json:"args_schema,omitempty"`
}

type Manifest struct {
	Version     string      `json:"version"`
	Revision    string      `json:"revision"`
	GeneratedAt string      `json:"generated_at"`
	HashAlgo    string      `json:"hash_algorithm"`
	PublicKeyID string      `json:"public_key_id"`
	Tools       []ToolEntry `json:"tools"`
	Signature   string      `json:"signature"`
}

func hash(name string) string {
	h := sha256.Sum256([]byte(name + ":v1"))
	return hex.EncodeToString(h[:])
}

func main() {
	// Read existing manifest for signature/key info
	existing, _ := os.ReadFile("manifest.json")
	var old Manifest
	json.Unmarshal(existing, &old)

	tools := []ToolEntry{
		// ── ACP: Agent Control Plane ───────────────────────────────────────
		{Name: "acp_status", Description: "List active ACP credentials and their expiry status", RiskClass: "read_only", Scope: "acp:read", Tier: "community", TimeoutMs: 5000},
		{Name: "acp_issue", Description: "Issue a new PQC credential via the Agent Control Plane", RiskClass: "destructive", Scope: "acp:write", Tier: "enterprise", TimeoutMs: 10000, Destructive: true,
			ArgsSchema: &ArgsSchema{Type: "object", Properties: map[string]map[string]any{
				"agent_id":    {"type": "string", "description": "Agent identifier"},
				"scopes":      {"type": "array", "items": map[string]any{"type": "string"}},
				"symbol":      {"type": "string", "description": "Adinkra symbol (default: Nkyinkyim)"},
				"ttl_minutes": {"type": "number", "description": "Credential TTL in minutes"},
			}, Required: []string{"agent_id"}}},
		{Name: "acp_revoke", Description: "Revoke an active ACP credential", RiskClass: "destructive", Scope: "acp:write", Tier: "enterprise", TimeoutMs: 10000, Destructive: true,
			ArgsSchema: &ArgsSchema{Type: "object", Properties: map[string]map[string]any{
				"credential_id": {"type": "string", "description": "Credential ID to revoke"},
			}, Required: []string{"credential_id"}}},

		// ── NHI: Non-Human Identity ────────────────────────────────────────
		{Name: "nhi_inventory", Description: "List all non-human identities (service accounts, API keys, certificates)", RiskClass: "read_only", Scope: "nhi:read", Tier: "community", TimeoutMs: 5000},
		{Name: "nhi_orphans", Description: "Identify orphaned non-human identities with no active owner", RiskClass: "read_only", Scope: "nhi:read", Tier: "community", TimeoutMs: 5000},
		{Name: "nhi_excessive", Description: "Identify NHIs with overly broad permissions", RiskClass: "read_only", Scope: "nhi:read", Tier: "community", TimeoutMs: 5000,
			ArgsSchema: &ArgsSchema{Type: "object", Properties: map[string]map[string]any{
				"max_scopes":     {"type": "number", "description": "Max scopes before flagging (default: 5)"},
				"risk_threshold": {"type": "number", "description": "Min risk score to flag (default: 0.5)"},
			}}},
		{Name: "nhi_expired", Description: "List expired or soon-to-expire non-human identities", RiskClass: "read_only", Scope: "nhi:read", Tier: "community", TimeoutMs: 5000},
		{Name: "nhi_revoke", Description: "Revoke a non-human identity credential", RiskClass: "destructive", Scope: "nhi:write", Tier: "enterprise", TimeoutMs: 10000, Destructive: true,
			ArgsSchema: &ArgsSchema{Type: "object", Properties: map[string]map[string]any{
				"nhi_id": {"type": "string", "description": "NHI identifier to revoke"},
			}, Required: []string{"nhi_id"}}},

		// ── ERT: Enterprise Risk & Threat Scanner ─────────────────────────
		{Name: "ert_scan", Description: "Run ERT security scan (SBOM, CVE, secrets, STIG, PQC inventory) in Docker sandbox", RiskClass: "sandboxed", Scope: "ert:scan", Tier: "community", TimeoutMs: 90000, AllowedBackend: "docker",
			ArgsSchema: &ArgsSchema{Type: "object", Properties: map[string]map[string]any{
				"project_path": {"type": "string", "description": "Path to project directory"},
				"image_ref":    {"type": "string", "description": "Container image to scan"},
				"lanes":        {"type": "array", "description": "Scan lanes: sca, horus, compliance", "items": map[string]any{"type": "string"}},
				"framework":    {"type": "string", "description": "Compliance framework: CMMC_L2, NIST_800_171, etc."},
			}}},
		{Name: "ert_readiness", Description: "Package A: NIST 800-171 Rev2 compliance assessment + live SCA risk factor. Returns alignment score (0-100), control gaps, and prioritized remediation roadmap.", RiskClass: "read_only", Scope: "ert:compliance", Tier: "community", TimeoutMs: 60000,
			ArgsSchema: &ArgsSchema{Type: "object", Properties: map[string]map[string]any{
				"project_path": {"type": "string", "description": "Path to project directory (default: current directory)"},
			}}},
		{Name: "ert_architect", Description: "Package B: Live supply chain risk — Syft SBOM + Grype CVE + CISA KEV/EPSS/MITRE enrichment. Returns findings with NIST 800-171 control mapping.", RiskClass: "read_only", Scope: "ert:supply-chain", Tier: "community", TimeoutMs: 300000,
			ArgsSchema: &ArgsSchema{Type: "object", Properties: map[string]map[string]any{
				"project_path": {"type": "string", "description": "Path to project directory (default: current directory)"},
			}}},
		{Name: "ert_crypto", Description: "Package C: PQC readiness attestation — source-level crypto primitive scan, SBOM crypto library inventory, weak primitive detection (MD5/SHA1/DES/RC4), CNSA 2.0 quantum risk context.", RiskClass: "read_only", Scope: "ert:pqc", Tier: "pilot", TimeoutMs: 180000,
			ArgsSchema: &ArgsSchema{Type: "object", Properties: map[string]map[string]any{
				"project_path": {"type": "string", "description": "Path to project directory (default: current directory)"},
			}}},
		{Name: "ert_godfather", Description: "Package D: EA KernelRouter causal risk attestation. Runs STIG, PQC, SBOM, Network agents in parallel, produces board-level causal chain with CVSS-band dollar impact and DAG-signed evidence node.", RiskClass: "read_only", Scope: "ert:godfather", Tier: "pilot", TimeoutMs: 300000,
			ArgsSchema: &ArgsSchema{Type: "object", Properties: map[string]map[string]any{
				"project_path": {"type": "string", "description": "Path to project directory (default: current directory)"},
			}}},

		// ── Compliance ─────────────────────────────────────────────────────
		{Name: "stig_check", Description: "Check a system path or configuration against STIG controls. Default: RHEL-09-STIG-V1R3. Returns CAT I/II/III findings with remediation guidance and compliance score.", RiskClass: "read_only", Scope: "stig:read", Tier: "community", TimeoutMs: 60000,
			ArgsSchema: &ArgsSchema{Type: "object", Properties: map[string]map[string]any{
				"framework": {"type": "string", "description": "Compliance framework (default: RHEL-09-STIG-V1R3)"},
			}}},
		{Name: "pqc_stig", Description: "World's First DoD PQC STIG (PQC-01-STIG-V1R1). CNSA 2.0 / FIPS 203/204/205 compliance assessment. Returns per-control findings, compliance score, and ML-DSA-65 signed evidence.", RiskClass: "read_only", Scope: "stig:pqc", Tier: "community", TimeoutMs: 60000,
			ArgsSchema: &ArgsSchema{Type: "object", Properties: map[string]map[string]any{
				"scan_path": {"type": "string", "description": "Path to scan (default: current directory)"},
				"profile":   {"type": "string", "description": "Scan profile: quick | full (default: full)"},
			}}},
		{Name: "cmmc_assess", Description: "CMMC Level 1/2/3 assessment via KHEPRA compliance database (36,195 STIG→CCI→NIST→CMMC mappings). Returns satisfaction score, gaps, C3PAO readiness flag, and PQC status.", RiskClass: "read_only", Scope: "compliance:read", Tier: "community", TimeoutMs: 60000,
			ArgsSchema: &ArgsSchema{Type: "object", Properties: map[string]map[string]any{
				"level": {"type": "string", "description": "CMMC level: '1', '2', or '3' (default: '2')"},
			}}},
		{Name: "nist_map", Description: "Offline semantic search across NIST 800-53 Rev5, NIST 800-171 Rev2, CMMC 2.0, and STIG CCI mappings. BM25 ranked results. Zero token cost, air-gap safe. 36,000+ controls indexed.", RiskClass: "read_only", Scope: "compliance:read", Tier: "community", TimeoutMs: 5000,
			ArgsSchema: &ArgsSchema{Type: "object", Properties: map[string]map[string]any{
				"query":     {"type": "string", "description": "Search query (e.g. 'multi-factor authentication')"},
				"framework": {"type": "string", "description": "Filter by framework: NIST-800-53, NIST-800-171, CMMC-L2, STIG (default: all)"},
				"top_k":     {"type": "number", "description": "Max results to return (default: 10, max: 50)"},
			}, Required: []string{"query"}}},

		// ── Compliance Reports & Evidence ──────────────────────────────────
		{Name: "dag_attestation", Description: "Export the PQC-signed DAG audit trail for the current session. Returns all DAG nodes with ML-DSA-65 signatures, timestamps, and Adinkra symbol chain.", RiskClass: "read_only", Scope: "dag:read", Tier: "community", TimeoutMs: 10000},
		{Name: "godfather_report", Description: "Generate a complete CMMC/STIG/NIST compliance report. When approval_required=true, returns a staged token — the full report is held until a human calls godfather_approve (30-min TTL).", RiskClass: "read_only", Scope: "compliance:report", Tier: "community", TimeoutMs: 30000,
			ArgsSchema: &ArgsSchema{Type: "object", Properties: map[string]map[string]any{
				"framework":         {"type": "string", "description": "Compliance framework: CMMC-L2, NIST-800-171, NIST-800-53 (default: CMMC-L2)"},
				"scope":             {"type": "string", "description": "Control family scope: all, AC, AU, CM, IA, SC, SI (default: all)"},
				"approval_required": {"type": "boolean", "description": "Stage report for human review before delivery (default: false)"},
				"engagement_id":     {"type": "string", "description": "Optional engagement/ticket ID for traceability"},
			}}},
		{Name: "godfather_approve", Description: "Deliver a staged Godfather Report. Requires the staged_token returned by godfather_report. Single-use — token is consumed on delivery.", RiskClass: "read_only", Scope: "compliance:report", Tier: "community", TimeoutMs: 5000,
			ArgsSchema: &ArgsSchema{Type: "object", Properties: map[string]map[string]any{
				"staged_token": {"type": "string", "description": "Token returned by godfather_report when approval_required=true"},
			}, Required: []string{"staged_token"}}},
		{Name: "khepra_export_attestation", Description: "Export PQC-signed attestation package covering all active compliance frameworks. C3PAO-ready evidence artifact — ML-DSA-65 signed, DAG-anchored.", RiskClass: "read_only", Scope: "compliance:attest", Tier: "pilot", TimeoutMs: 120000,
			ArgsSchema: &ArgsSchema{Type: "object", Properties: map[string]map[string]any{
				"project_path": {"type": "string", "description": "Path to project root (default: current directory)"},
			}}},
		{Name: "khepra_export_poam", Description: "Export a DFARS 252.204-7012 POA&M (Plan of Action & Milestones) from the current DAG state. Maps open findings to remediation timelines.", RiskClass: "read_only", Scope: "compliance:poam", Tier: "enterprise", TimeoutMs: 30000},

		// ── Compliance Queries ─────────────────────────────────────────────
		{Name: "khepra_query_stig", Description: "Query the embedded STIG/CCI/NIST control database (36,195 mappings). Look up STIG rules, CCI items, NIST 800-53 controls by ID or keyword.", RiskClass: "read_only", Scope: "compliance:read", Tier: "community", TimeoutMs: 5000,
			ArgsSchema: &ArgsSchema{Type: "object", Properties: map[string]map[string]any{
				"query":      {"type": "string", "description": "Keyword search query"},
				"control_id": {"type": "string", "description": "Control ID (CCI-XXXXXX, SV-XXXXXX, AC-1, etc.)"},
				"framework":  {"type": "string", "description": "Filter by framework: STIG, CCI, NIST-800-53, CMMC"},
				"limit":      {"type": "integer", "description": "Max results (default: 10)"},
			}}},
		{Name: "khepra_get_compliance_score", Description: "Fast compliance score without full scan. Returns current CMMC/NIST/STIG satisfaction percentages from cached DAG state.", RiskClass: "read_only", Scope: "compliance:read", Tier: "community", TimeoutMs: 5000},
		{Name: "khepra_query_threat_intel", Description: "Query embedded CISA KEV + CVE threat intelligence from offline database. Returns relevant CVEs, EPSS scores, MITRE ATT&CK mappings.", RiskClass: "read_only", Scope: "threat:read", Tier: "community", TimeoutMs: 10000,
			ArgsSchema: &ArgsSchema{Type: "object", Properties: map[string]map[string]any{
				"query":      {"type": "string", "description": "Search term (CVE ID, product name, or keyword)"},
				"cve_id":     {"type": "string", "description": "Specific CVE identifier (e.g. CVE-2024-12345)"},
				"kev_only":   {"type": "boolean", "description": "Filter to CISA KEV only (default: false)"},
				"pqc_impact": {"type": "boolean", "description": "Include CNSA 2.0 quantum impact assessment (default: false)"},
				"limit":      {"type": "integer", "description": "Max results (default: 10)"},
			}}},
		{Name: "khepra_get_dag_chain", Description: "Export the PQC-signed DAG chain for the current session. Returns all DAG nodes with ML-DSA-65 signatures and Adinkra symbol provenance.", RiskClass: "read_only", Scope: "dag:read", Tier: "community", TimeoutMs: 10000},
		{Name: "khepra_watch", Description: "Register a filesystem path for continuous STIG-triggered scanning. Fires ert_scan on file changes.", RiskClass: "read_only", Scope: "compliance:monitor", Tier: "community", TimeoutMs: 10000,
			ArgsSchema: &ArgsSchema{Type: "object", Properties: map[string]map[string]any{
				"action":    {"type": "string", "description": "Action: register | status | unregister"},
				"path":      {"type": "string", "description": "Filesystem path to watch"},
				"framework": {"type": "string", "description": "Compliance framework for triggered scans"},
				"watch_id":  {"type": "string", "description": "Watch ID (for status/unregister)"},
			}, Required: []string{"action"}}},

		// ── Discovery & Recording ─────────────────────────────────────────
		{Name: "discover_assets", Description: "Inventory environment: OS, runtimes, containers, CI/CD, AI agents, crypto libs, MCP configs. Recommends CMMC level and applicable STIG profiles.", RiskClass: "read_only", Scope: "asset:discover", Tier: "community", TimeoutMs: 60000},
		{Name: "agent_record", Description: "Record an agent action in the SouHimBou AI Flight Recorder. Records to PQC-signed DAG audit log.", RiskClass: "read_only", Scope: "audit:write", Tier: "community", TimeoutMs: 15000,
			ArgsSchema: &ArgsSchema{Type: "object", Properties: map[string]map[string]any{
				"action":     {"type": "string", "description": "Agent action to record"},
				"agent_id":   {"type": "string", "description": "Agent identifier"},
				"tool_name":  {"type": "string", "description": "Tool that was invoked"},
				"session_id": {"type": "string", "description": "Session identifier"},
				"metadata":   {"type": "object", "description": "Additional metadata"},
			}, Required: []string{"action"}}},
		{Name: "flight_export", Description: "Export a CMMC-aligned evidence packet from the SouHimBou AI flight log. Maps agent actions to NIST 800-171 / CMMC 2.0 controls.", RiskClass: "read_only", Scope: "audit:read", Tier: "pilot", TimeoutMs: 30000},

		// ── Community Contributions ───────────────────────────────────────
		{Name: "owasp_agent_assess", Description: "Assess this MCP server deployment against OWASP Agentic Top 10 (ASI01-ASI10). Returns scored findings, active controls, gaps, and ML-DSA-65 signed evidence.", RiskClass: "read_only", Scope: "security:assess", Tier: "community", TimeoutMs: 30000,
			ArgsSchema: &ArgsSchema{Type: "object", Properties: map[string]map[string]any{
				"profile": {"type": "string", "description": "Assessment profile: quick | full (default: full)"},
			}}},
		{Name: "dark_crypto_contribute", Description: "Privacy-preserving contribution of anonymized crypto inventory to the Dark Crypto Intelligence Network. Returns global quantum exposure rank.", RiskClass: "read_only", Scope: "community:contribute", Tier: "community", TimeoutMs: 30000},
		{Name: "sbom_generate", Description: "Generate a CycloneDX / SPDX SBOM with PQC readiness annotations.", RiskClass: "read_only", Scope: "sbom:generate", Tier: "pilot", TimeoutMs: 180000,
			ArgsSchema: &ArgsSchema{Type: "object", Properties: map[string]map[string]any{
				"project_path": {"type": "string", "description": "Path to project directory (default: current directory)"},
				"format":       {"type": "string", "description": "Output format: cyclonedx | spdx (default: cyclonedx)"},
			}}},
		{Name: "threat_model", Description: "Generate a STRIDE threat model with NIST 800-53 + MITRE ATT&CK mappings. 100% offline.", RiskClass: "read_only", Scope: "threat:model", Tier: "community", TimeoutMs: 60000,
			ArgsSchema: &ArgsSchema{Type: "object", Properties: map[string]map[string]any{
				"project_path": {"type": "string", "description": "Path to project directory (default: current directory)"},
				"framework":    {"type": "string", "description": "Threat framework: STRIDE | PASTA | LINDDUN (default: STRIDE)"},
			}}},

		// ── Sprint 1: KASA Brain (AGI + EA + Quantum) ─────────────────────
		{Name: "kasa_start", Description: "Start the KASA autonomous security agent. Launches: vulnerability hunting hourly, internal pentest daily (NIST 800-53 CA-8), CMMC compliance audit daily. Every action is DAG-attested.", RiskClass: "destructive", Scope: "kasa:control", Tier: "enterprise", TimeoutMs: 30000, Destructive: true},
		{Name: "kasa_status", Description: "Check current status of the KASA autonomous agent: uptime, active tasks, threat score, and EA kernel generation.", RiskClass: "read_only", Scope: "kasa:read", Tier: "community", TimeoutMs: 5000},
		{Name: "ea_evolve", Description: "Run Evolutionary Algorithm threat evolution. Optimizes for: NIST 800-171 control coverage, PQC readiness, threat posture. Returns the fittest genome with Adinkra symbol binding.", RiskClass: "read_only", Scope: "kasa:evolve", Tier: "pilot", TimeoutMs: 120000,
			ArgsSchema: &ArgsSchema{Type: "object", Properties: map[string]map[string]any{
				"generations":     {"type": "number", "description": "Number of EA generations (default: 10)"},
				"population_size": {"type": "number", "description": "Population size (default: 50)"},
				"target":          {"type": "string", "description": "Target to evolve against (default: current directory)"},
			}}},
		{Name: "ea_threat_score", Description: "Calculate a composite threat score for a target using the EA kernel. Returns CVSS-band score, confidence interval, and contributing factors.", RiskClass: "read_only", Scope: "kasa:read", Tier: "community", TimeoutMs: 30000,
			ArgsSchema: &ArgsSchema{Type: "object", Properties: map[string]map[string]any{
				"target": {"type": "string", "description": "Target to score (default: current directory)"},
			}}},
		{Name: "ea_risk_summary", Description: "Synthesize EA-driven risk summary: vulnerability exposure, compliance gap, PQC migration cost, blast radius. Same engine as Godfather Report.", RiskClass: "read_only", Scope: "kasa:read", Tier: "pilot", TimeoutMs: 60000,
			ArgsSchema: &ArgsSchema{Type: "object", Properties: map[string]map[string]any{
				"target": {"type": "string", "description": "Target to summarize (default: current directory)"},
			}}},
		{Name: "quantum_optimize", Description: "Run Ising model quantum-inspired optimization for attack surface analysis. Simulates quantum annealing to find optimal defense configuration.", RiskClass: "read_only", Scope: "kasa:quantum", Tier: "enterprise", TimeoutMs: 120000,
			ArgsSchema: &ArgsSchema{Type: "object", Properties: map[string]map[string]any{
				"target": {"type": "string", "description": "Target system to optimize (default: current directory)"},
			}}},

		// ── Sprint 2: Shield (IR + Intel + Flight Recorder + Ouroboros) ───
		{Name: "threat_lookup", Description: "Look up a CVE, IP, or domain against embedded CISA KEV + MITRE ATT&CK databases. Returns CVE details, CVSS/EPSS scores, ATT&CK TTP mapping.", RiskClass: "read_only", Scope: "threat:lookup", Tier: "pilot", TimeoutMs: 30000,
			ArgsSchema: &ArgsSchema{Type: "object", Properties: map[string]map[string]any{
				"query": {"type": "string", "description": "CVE ID, IP address, domain, or keyword to look up"},
			}, Required: []string{"query"}}},
		{Name: "drift_detect", Description: "Detect configuration drift between current state and a signed baseline. Uses the KHEPRA DriftEngine with Adinkra symbol binding.", RiskClass: "read_only", Scope: "compliance:drift", Tier: "pilot", TimeoutMs: 60000},
		{Name: "ir_incident", Description: "Create a new incident in the KHEPRA IR Manager. Every incident is ML-DSA-65 signed at creation and DAG-attested.", RiskClass: "destructive", Scope: "ir:write", Tier: "pilot", TimeoutMs: 15000, Destructive: true,
			ArgsSchema: &ArgsSchema{Type: "object", Properties: map[string]map[string]any{
				"title":       {"type": "string", "description": "Incident title"},
				"severity":    {"type": "string", "description": "Severity: critical | high | medium | low"},
				"description": {"type": "string", "description": "Incident description"},
			}, Required: []string{"title", "severity"}}},
		{Name: "ir_add_ioc", Description: "Add an Indicator of Compromise to an existing incident. The IOC is ML-DSA-65 signed and DAG-recorded.", RiskClass: "destructive", Scope: "ir:write", Tier: "pilot", TimeoutMs: 10000, Destructive: true,
			ArgsSchema: &ArgsSchema{Type: "object", Properties: map[string]map[string]any{
				"incident_id": {"type": "string", "description": "Incident ID to attach IOC to"},
				"ioc_type":    {"type": "string", "description": "IOC type: ip | domain | hash | url | email"},
				"value":       {"type": "string", "description": "IOC value"},
			}, Required: []string{"incident_id", "ioc_type", "value"}}},
		{Name: "flight_record", Description: "Record an agent tool call to the SouHimBou AI Flight Recorder with cryptographic attestation. Creates a cryptographically verifiable audit trail.", RiskClass: "read_only", Scope: "audit:write", Tier: "enterprise", TimeoutMs: 15000,
			ArgsSchema: &ArgsSchema{Type: "object", Properties: map[string]map[string]any{
				"tool_name": {"type": "string", "description": "Name of the tool that was called"},
				"scope":     {"type": "string", "description": "Scope/context of the call"},
				"outcome":   {"type": "string", "description": "Outcome: success | failure | partial"},
			}, Required: []string{"tool_name"}}},
		{Name: "ouroboros_waf_eye", Description: "Ouroboros WAF Eye — real-time web application firewall status from the Mitochondrial API Server. Returns blocked requests, threat patterns, and active rules.", RiskClass: "read_only", Scope: "ouroboros:read", Tier: "community", TimeoutMs: 5000},
		{Name: "ouroboros_stig_eye", Description: "Ouroboros STIG Eye — continuous STIG compliance monitoring status. Returns current compliance posture and drift alerts.", RiskClass: "read_only", Scope: "ouroboros:read", Tier: "community", TimeoutMs: 5000},
		{Name: "ouroboros_vuln_eye", Description: "Ouroboros Vuln Eye — continuous vulnerability scanning status. Returns active CVEs, EPSS scores, and remediation priority.", RiskClass: "read_only", Scope: "ouroboros:read", Tier: "community", TimeoutMs: 5000},
		{Name: "ouroboros_fim_eye", Description: "Ouroboros FIM Eye — file integrity monitoring status. Returns hash baseline comparison and drift alerts.", RiskClass: "read_only", Scope: "ouroboros:read", Tier: "community", TimeoutMs: 5000},

		// ── Sprint 3: Memory (Forensics + FIM + Audit) ───────────────────
		{Name: "forensic_snapshot", Description: "Collect a DFIR-grade forensic snapshot: processes, network connections, loaded modules, environment variables. ML-DSA-65 signed, DAG-attested.", RiskClass: "read_only", Scope: "forensics:collect", Tier: "pilot", TimeoutMs: 30000},
		{Name: "fim_baseline", Description: "Create a file integrity monitoring baseline. Monitors critical paths using SHA-256 hash baselines. Baseline is DAG-attested.", RiskClass: "read_only", Scope: "fim:write", Tier: "pilot", TimeoutMs: 30000,
			ArgsSchema: &ArgsSchema{Type: "object", Properties: map[string]map[string]any{
				"path": {"type": "string", "description": "Directory path to baseline"},
			}, Required: []string{"path"}}},
		{Name: "audit_dag_integrity", Description: "Full integrity audit of the KASA DAG. Verifies: node count, parent linkage, PQC metadata completeness, and signature chain.", RiskClass: "read_only", Scope: "dag:audit", Tier: "pilot", TimeoutMs: 30000},

		// ── Sprint 4: Sword (Recon + Scanning + Attack Graph) ────────────
		{Name: "enumerate_host", Description: "Enumerate host information: OS, kernel, network interfaces, running services, users, installed packages. MITRE ATT&CK T1082.", RiskClass: "read_only", Scope: "recon:read", Tier: "community", TimeoutMs: 30000,
			ArgsSchema: &ArgsSchema{Type: "object", Properties: map[string]map[string]any{
				"target": {"type": "string", "description": "Target host (default: localhost)"},
			}}},
		{Name: "fingerprint_device", Description: "Fingerprint a network device: OS detection, service banners, protocol analysis. MITRE ATT&CK T1046.", RiskClass: "read_only", Scope: "recon:read", Tier: "community", TimeoutMs: 30000,
			ArgsSchema: &ArgsSchema{Type: "object", Properties: map[string]map[string]any{
				"target": {"type": "string", "description": "Target IP or hostname"},
			}, Required: []string{"target"}}},
		{Name: "port_scan", Description: "TCP port scan with service banner grabbing. Identifies open ports and running services. MITRE ATT&CK T1046.", RiskClass: "destructive", Scope: "recon:scan", Tier: "enterprise", TimeoutMs: 120000, Destructive: true,
			ArgsSchema: &ArgsSchema{Type: "object", Properties: map[string]map[string]any{
				"target": {"type": "string", "description": "Target IP or hostname"},
				"ports":  {"type": "string", "description": "Port range (default: 1-1024)"},
			}, Required: []string{"target"}}},
		{Name: "vuln_scan", Description: "Scan project for known vulnerabilities in dependencies (Go, NPM, Python). Returns CVE IDs, CVSS scores, affected packages, and fix versions.", RiskClass: "read_only", Scope: "scan:vuln", Tier: "enterprise", TimeoutMs: 180000,
			ArgsSchema: &ArgsSchema{Type: "object", Properties: map[string]map[string]any{
				"target_dir": {"type": "string", "description": "Directory to scan (default: current directory)"},
			}}},
		{Name: "secret_scan", Description: "Scan for hardcoded secrets using entropy analysis + pattern matching. Detects: AWS keys, GitHub tokens, private keys, JWT secrets, database passwords.", RiskClass: "read_only", Scope: "scan:secrets", Tier: "enterprise", TimeoutMs: 120000,
			ArgsSchema: &ArgsSchema{Type: "object", Properties: map[string]map[string]any{
				"target_dir": {"type": "string", "description": "Directory to scan (default: current directory)"},
			}}},
		{Name: "container_scan", Description: "Analyze Dockerfile and container manifests for security misconfigurations and base image vulnerabilities.", RiskClass: "read_only", Scope: "scan:container", Tier: "enterprise", TimeoutMs: 120000,
			ArgsSchema: &ArgsSchema{Type: "object", Properties: map[string]map[string]any{
				"target_dir": {"type": "string", "description": "Directory containing Dockerfile (default: current directory)"},
			}}},
		{Name: "compliance_scan", Description: "Run built-in compliance checks against CIS, STIG, and NIST baselines. Returns pass/fail per control with remediation guidance.", RiskClass: "read_only", Scope: "scan:compliance", Tier: "enterprise", TimeoutMs: 120000,
			ArgsSchema: &ArgsSchema{Type: "object", Properties: map[string]map[string]any{
				"framework": {"type": "string", "description": "Framework: CIS | STIG | NIST | ALL (default: ALL)"},
			}}},
		{Name: "packet_analyze", Description: "Analyze a PCAP capture file. Extracts: protocol distribution, suspicious connections, DNS queries, HTTP methods, potential C2 patterns.", RiskClass: "read_only", Scope: "scan:network", Tier: "enterprise", TimeoutMs: 60000,
			ArgsSchema: &ArgsSchema{Type: "object", Properties: map[string]map[string]any{
				"capture_file": {"type": "string", "description": "Path to PCAP capture file"},
			}, Required: []string{"capture_file"}}},
		{Name: "attack_graph", Description: "Generate an attack graph from current NHI inventory. Models lateral movement paths, privilege escalation vectors, and blast radius.", RiskClass: "read_only", Scope: "threat:attack", Tier: "pilot", TimeoutMs: 60000},

		// ── Sprint 5: Foundation (PQC Crypto + DAG + Phantom + DRBC) ─────
		{Name: "pqc_sign", Description: "Sign arbitrary data with ML-DSA-65. Returns base64-encoded signature and public key ID. Air-gap safe.", RiskClass: "read_only", Scope: "pqc:sign", Tier: "community", TimeoutMs: 10000,
			ArgsSchema: &ArgsSchema{Type: "object", Properties: map[string]map[string]any{
				"data":   {"type": "string", "description": "Data to sign (string or base64)"},
				"symbol": {"type": "string", "description": "Adinkra symbol to bind (default: Eban)"},
			}, Required: []string{"data"}}},
		{Name: "pqc_verify", Description: "Verify an ML-DSA-65 signature against data. Returns verification result and signer metadata.", RiskClass: "read_only", Scope: "pqc:verify", Tier: "community", TimeoutMs: 10000,
			ArgsSchema: &ArgsSchema{Type: "object", Properties: map[string]map[string]any{
				"data":      {"type": "string", "description": "Original data that was signed"},
				"signature": {"type": "string", "description": "Base64-encoded signature"},
			}, Required: []string{"data", "signature"}}},
		{Name: "pqc_keygen", Description: "Generate a new ML-DSA-65 keypair for agent identity. Returns public key (base64) and key ID. Private key is stored securely.", RiskClass: "read_only", Scope: "pqc:keygen", Tier: "community", TimeoutMs: 10000},
		{Name: "dag_write", Description: "Write a manually-specified attested node to the shared KASA DAG. Use for arbitrary compliance events, human approvals, and audit points.", RiskClass: "destructive", Scope: "dag:write", Tier: "enterprise", TimeoutMs: 10000, Destructive: true,
			ArgsSchema: &ArgsSchema{Type: "object", Properties: map[string]map[string]any{
				"action": {"type": "string", "description": "Action name for the DAG node"},
				"symbol": {"type": "string", "description": "Adinkra symbol (default: Sankofa)"},
			}, Required: []string{"action"}}},
		{Name: "dag_query", Description: "Query the KASA DAG for nodes matching criteria. Returns matched nodes with signatures and provenance.", RiskClass: "read_only", Scope: "dag:read", Tier: "community", TimeoutMs: 10000,
			ArgsSchema: &ArgsSchema{Type: "object", Properties: map[string]map[string]any{
				"action": {"type": "string", "description": "Filter by action name"},
				"symbol": {"type": "string", "description": "Filter by Adinkra symbol"},
				"limit":  {"type": "number", "description": "Max results (default: 20)"},
			}}},
		{Name: "dag_audit", Description: "Perform a full integrity audit of the KASA DAG. Verifies node count, parent linkage, PQC metadata completeness.", RiskClass: "read_only", Scope: "dag:audit", Tier: "enterprise", TimeoutMs: 30000},
		{Name: "phantom_stealth", Description: "Engage Phantom Network stealth mode. GPS spoofing, thermal camouflage, ephemeral IMSI, spread spectrum pattern. Symbol: Eban (fortress).", RiskClass: "destructive", Scope: "opsec:stealth", Tier: "enterprise", TimeoutMs: 30000, Destructive: true,
			ArgsSchema: &ArgsSchema{Type: "object", Properties: map[string]map[string]any{
				"symbol":      {"type": "string", "description": "Adinkra symbol (default: Eban)"},
				"device_id":   {"type": "string", "description": "Device identifier to shroud"},
				"target_city": {"type": "string", "description": "City for GPS spoof anchor"},
			}}},
		{Name: "identity_shroud", Description: "Encode a strand (identity token, API key, agent fingerprint) using Nkyinkyim mystery encoding for OPSEC identity protection.", RiskClass: "read_only", Scope: "opsec:shroud", Tier: "enterprise", TimeoutMs: 10000,
			ArgsSchema: &ArgsSchema{Type: "object", Properties: map[string]map[string]any{
				"strand": {"type": "string", "description": "Identity strand to shroud"},
			}, Required: []string{"strand"}}},
		{Name: "identity_epiphany", Description: "Decode a Nkyinkyim-shrouded strand back to plaintext. Reveals the original identity.", RiskClass: "read_only", Scope: "opsec:reveal", Tier: "enterprise", TimeoutMs: 10000,
			ArgsSchema: &ArgsSchema{Type: "object", Properties: map[string]map[string]any{
				"verse": {"type": "string", "description": "Shrouded verse to decode"},
			}, Required: []string{"verse"}}},
		{Name: "drbc_backup", Description: "Create a DRBC genesis backup of the KHEPRA project. AES-256-GCM encrypted, ML-DSA-65 signed.", RiskClass: "destructive", Scope: "drbc:write", Tier: "pilot", TimeoutMs: 120000, Destructive: true,
			ArgsSchema: &ArgsSchema{Type: "object", Properties: map[string]map[string]any{
				"password": {"type": "string", "description": "Encryption password for the backup"},
			}, Required: []string{"password"}}},
		{Name: "drbc_restore", Description: "Restore the KHEPRA project from a DRBC genesis backup. Requires the same password used during backup.", RiskClass: "destructive", Scope: "drbc:write", Tier: "pilot", TimeoutMs: 120000, Destructive: true,
			ArgsSchema: &ArgsSchema{Type: "object", Properties: map[string]map[string]any{
				"password":   {"type": "string", "description": "Decryption password"},
				"target_dir": {"type": "string", "description": "Target directory for restore"},
			}, Required: []string{"password", "target_dir"}}},
	}

	// Fill in computed fields
	for i := range tools {
		tools[i].SchemaVersion = "1.0.0"
		tools[i].SchemaHash = hash(tools[i].Name)
		if tools[i].AllowedBackend == "" {
			tools[i].AllowedBackend = "in-process"
		}
	}

	manifest := Manifest{
		Version:     "2.0.0",
		Revision:    fmt.Sprintf("build-%d", time.Now().Unix()),
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		HashAlgo:    "SHA-256",
		PublicKeyID: old.PublicKeyID,
		Tools:       tools,
		Signature:   old.Signature, // Re-use bootstrap signature for now
	}

	data, _ := json.MarshalIndent(manifest, "", "  ")
	os.WriteFile("manifest.json", data, 0644)
	fmt.Printf("Generated manifest.json with %d tools (version %s)\n", len(tools), manifest.Version)
}
