// cmd/manifest-gen/main.go
//
// One-shot utility to generate and sign manifest.json with ML-DSA-65.
// Run: go run ./cmd/manifest-gen > manifest.json

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/adinkra"
)

func main() {
	symbol := "Eban"
	fingerprint := adinkra.GetSpectralFingerprint(symbol)
	_ = fingerprint // Used for provenance only

	// Generate ML-DSA-65 key pair (compatible with adinkra.Sign/Verify)
	pubKey, privKey, err := adinkra.GenerateDilithiumKey()
	if err != nil {
		fmt.Fprintf(os.Stderr, "key generation failed: %v\n", err)
		os.Exit(1)
	}

	keyHash := sha256.Sum256(pubKey)
	keyID := hex.EncodeToString(keyHash[:8])

	hash := func(name string) string {
		h := sha256.Sum256([]byte(name + ":v1"))
		return hex.EncodeToString(h[:])
	}

	type ToolSpec struct {
		Name           string         `json:"name"`
		Description    string         `json:"description"`
		RiskClass      string         `json:"risk_class"`
		Scope          string         `json:"scope"`
		SchemaVersion  string         `json:"schema_version"`
		SchemaHash     string         `json:"schema_hash"`
		AllowedBackend string         `json:"allowed_backend"`
		TimeoutMs      int            `json:"timeout_ms"`
		NetworkAllowed bool           `json:"network_allowed"`
		Destructive    bool           `json:"destructive"`
		ArgsSchema     map[string]any `json:"args_schema,omitempty"`
	}

	tools := []ToolSpec{
		// ── ACP: Agent Control Plane ──────────────────────────────────────────
		{
			Name: "acp_status", Description: "List active ACP credentials and their expiry status",
			RiskClass: "read_only", Scope: "acp:read",
			SchemaVersion: "1.0.0", SchemaHash: hash("acp_status"),
			AllowedBackend: "in-process", TimeoutMs: 5000,
		},
		{
			Name: "acp_issue", Description: "Issue a new PQC credential via the Agent Control Plane",
			RiskClass: "destructive", Scope: "acp:write", Destructive: true,
			SchemaVersion: "1.0.0", SchemaHash: hash("acp_issue"),
			AllowedBackend: "in-process", TimeoutMs: 10000,
			ArgsSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"agent_id":    map[string]any{"type": "string", "description": "Agent identifier"},
					"symbol":      map[string]any{"type": "string", "description": "Adinkra symbol (default: Nkyinkyim)"},
					"scopes":      map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
					"ttl_minutes": map[string]any{"type": "number", "description": "Credential TTL in minutes"},
				},
				"required": []string{"agent_id"},
			},
		},
		{
			Name: "acp_revoke", Description: "Revoke an active ACP credential",
			RiskClass: "destructive", Scope: "acp:write", Destructive: true,
			SchemaVersion: "1.0.0", SchemaHash: hash("acp_revoke"),
			AllowedBackend: "in-process", TimeoutMs: 10000,
			ArgsSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"credential_id": map[string]any{"type": "string", "description": "Credential ID to revoke"},
				},
				"required": []string{"credential_id"},
			},
		},

		// ── NHI: Non-Human Identity ───────────────────────────────────────────
		{
			Name: "nhi_inventory", Description: "List all non-human identities (service accounts, API keys, certificates)",
			RiskClass: "read_only", Scope: "nhi:read",
			SchemaVersion: "1.0.0", SchemaHash: hash("nhi_inventory"),
			AllowedBackend: "in-process", TimeoutMs: 5000,
		},
		{
			Name: "nhi_orphans", Description: "Identify orphaned non-human identities with no active owner",
			RiskClass: "read_only", Scope: "nhi:read",
			SchemaVersion: "1.0.0", SchemaHash: hash("nhi_orphans"),
			AllowedBackend: "in-process", TimeoutMs: 5000,
		},
		{
			Name: "nhi_excessive", Description: "Identify NHIs with overly broad permissions",
			RiskClass: "read_only", Scope: "nhi:read",
			SchemaVersion: "1.0.0", SchemaHash: hash("nhi_excessive"),
			AllowedBackend: "in-process", TimeoutMs: 5000,
			ArgsSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"max_scopes":     map[string]any{"type": "number", "description": "Max scopes before flagging (default: 5)"},
					"risk_threshold": map[string]any{"type": "number", "description": "Min risk score to flag (default: 0.5)"},
				},
			},
		},
		{
			Name: "nhi_expired", Description: "List expired or soon-to-expire non-human identities",
			RiskClass: "read_only", Scope: "nhi:read",
			SchemaVersion: "1.0.0", SchemaHash: hash("nhi_expired"),
			AllowedBackend: "in-process", TimeoutMs: 5000,
		},
		{
			Name: "nhi_revoke", Description: "Revoke a non-human identity credential",
			RiskClass: "destructive", Scope: "nhi:write", Destructive: true,
			SchemaVersion: "1.0.0", SchemaHash: hash("nhi_revoke"),
			AllowedBackend: "in-process", TimeoutMs: 10000,
			ArgsSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"nhi_id": map[string]any{"type": "string", "description": "NHI identifier to revoke"},
				},
				"required": []string{"nhi_id"},
			},
		},

		// ── ERT: Enterprise Risk & Threat (Docker sandbox) ────────────────────
		{
			Name: "ert_scan", Description: "Run ERT security scan (SBOM, CVE, secrets, STIG, PQC inventory) in Docker sandbox",
			RiskClass: "sandboxed", Scope: "ert:scan",
			SchemaVersion: "1.0.0", SchemaHash: hash("ert_scan"),
			AllowedBackend: "docker", TimeoutMs: 90000, NetworkAllowed: false,
			ArgsSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"project_path": map[string]any{"type": "string", "description": "Path to project directory"},
					"image_ref":    map[string]any{"type": "string", "description": "Container image to scan (overrides project_path)"},
					"lanes":        map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "Scan lanes: sca, horus, compliance"},
					"framework":    map[string]any{"type": "string", "description": "Compliance framework: CMMC_L2, NIST_800_171, etc."},
				},
			},
		},

		// ── ERT Packages A–D (in-process, air-gap safe) ──────────────────────
		{
			Name:           "ert_readiness",
			Description:    "Package A: NIST 800-171 Rev2 compliance assessment + live SCA risk factor. Returns alignment score (0-100), control gaps, and prioritized remediation roadmap. Air-gap safe.",
			RiskClass:      "read_only", Scope: "ert:compliance",
			SchemaVersion:  "1.0.0", SchemaHash: hash("ert_readiness"),
			AllowedBackend: "in-process", TimeoutMs: 60000,
			ArgsSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"project_path": map[string]any{"type": "string", "description": "Path to project directory (default: current directory)"},
				},
			},
		},
		{
			Name:           "ert_architect",
			Description:    "Package B: Live supply chain risk — Syft SBOM + Grype CVE + CISA KEV/EPSS/MITRE enrichment. Returns findings with NIST 800-171 control mapping. Requires syft+grype in PATH.",
			RiskClass:      "read_only", Scope: "ert:supply-chain",
			SchemaVersion:  "1.0.0", SchemaHash: hash("ert_architect"),
			AllowedBackend: "in-process", TimeoutMs: 300000,
			ArgsSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"project_path": map[string]any{"type": "string", "description": "Path to project directory (default: current directory)"},
				},
			},
		},
		{
			Name:           "ert_crypto",
			Description:    "Package C: PQC readiness attestation — source-level crypto primitive scan, SBOM crypto library inventory, weak primitive detection (MD5/SHA1/DES/RC4), CNSA 2.0 quantum risk context.",
			RiskClass:      "read_only", Scope: "ert:pqc",
			SchemaVersion:  "1.0.0", SchemaHash: hash("ert_crypto"),
			AllowedBackend: "in-process", TimeoutMs: 180000,
			ArgsSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"project_path": map[string]any{"type": "string", "description": "Path to project directory (default: current directory)"},
				},
			},
		},
		{
			Name:           "ert_godfather",
			Description:    "Package D: EA KernelRouter causal risk attestation. Runs STIG, PQC, SBOM, Network agents in parallel, produces board-level causal chain with CVSS-band dollar impact and DAG-signed evidence node.",
			RiskClass:      "read_only", Scope: "ert:godfather",
			SchemaVersion:  "1.0.0", SchemaHash: hash("ert_godfather"),
			AllowedBackend: "in-process", TimeoutMs: 300000,
			ArgsSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"project_path": map[string]any{"type": "string", "description": "Path to project directory (default: current directory)"},
				},
			},
		},

		// ── DAG Attestation ───────────────────────────────────────────────────
		{
			Name:           "dag_attestation",
			Description:    "Export the PQC-signed DAG audit trail for the current session. Returns all DAG nodes with ML-DSA-65 signatures, timestamps, and Adinkra symbol chain.",
			RiskClass:      "read_only", Scope: "dag:read",
			SchemaVersion:  "1.0.0", SchemaHash: hash("dag_attestation"),
			AllowedBackend: "in-process", TimeoutMs: 10000,
		},

		// ── Godfather Report + Human-in-the-Loop Gate ─────────────────────────
		{
			Name:           "godfather_report",
			Description:    "Generate a complete CMMC/STIG/NIST compliance report. When approval_required=true, returns a staged token — the full report is held until a human calls godfather_approve (30-min TTL).",
			RiskClass:      "read_only", Scope: "compliance:report",
			SchemaVersion:  "1.0.0", SchemaHash: hash("godfather_report"),
			AllowedBackend: "in-process", TimeoutMs: 30000,
			ArgsSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"framework":         map[string]any{"type": "string", "description": "Compliance framework: CMMC-L2, NIST-800-171, NIST-800-53 (default: CMMC-L2)"},
					"scope":             map[string]any{"type": "string", "description": "Control family scope: all, AC, AU, CM, IA, SC, SI (default: all)"},
					"approval_required": map[string]any{"type": "boolean", "description": "Stage report for human review before delivery (default: false)"},
					"engagement_id":     map[string]any{"type": "string", "description": "Optional engagement/ticket ID for traceability"},
				},
			},
		},
		{
			Name:           "godfather_approve",
			Description:    "Deliver a staged Godfather Report. Requires the staged_token returned by godfather_report. Single-use — token is consumed on delivery.",
			RiskClass:      "read_only", Scope: "compliance:report",
			SchemaVersion:  "1.0.0", SchemaHash: hash("godfather_approve"),
			AllowedBackend: "in-process", TimeoutMs: 5000,
			ArgsSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"staged_token": map[string]any{"type": "string", "description": "Token returned by godfather_report when approval_required=true"},
				},
				"required": []string{"staged_token"},
			},
		},

		// ── NIST Map: offline BM25 semantic search ────────────────────────────
		{
			Name:           "nist_map",
			Description:    "Offline semantic search across NIST 800-53 Rev5, NIST 800-171 Rev2, CMMC 2.0, and STIG CCI mappings. BM25 ranked results. Zero token cost, air-gap safe. 36,000+ controls indexed.",
			RiskClass:      "read_only", Scope: "compliance:read",
			SchemaVersion:  "1.0.0", SchemaHash: hash("nist_map"),
			AllowedBackend: "in-process", TimeoutMs: 5000,
			ArgsSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"query":     map[string]any{"type": "string", "description": "Search query (e.g. 'multi-factor authentication', 'encryption at rest')"},
					"framework": map[string]any{"type": "string", "description": "Filter by framework: NIST-800-53, NIST-800-171, CMMC-L2, STIG (default: all)"},
					"top_k":     map[string]any{"type": "number", "description": "Max results to return (default: 10, max: 50)"},
				},
				"required": []string{"query"},
			},
		},

		// ── khepra_watch: continuous filesystem monitoring ─────────────────────
		{
			Name:           "khepra_watch",
			Description:    "Register a filesystem path for continuous STIG-triggered scanning. Fires ert_scan on file changes. Satisfies CMMC AC.2.006, CM.2.061, SI.2.217.",
			RiskClass:      "read_only", Scope: "compliance:monitor",
			SchemaVersion:  "1.0.0", SchemaHash: hash("khepra_watch"),
			AllowedBackend: "in-process", TimeoutMs: 10000,
			ArgsSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"action":    map[string]any{"type": "string", "description": "Action: register | status | unregister"},
					"path":      map[string]any{"type": "string", "description": "Filesystem path to watch"},
					"framework": map[string]any{"type": "string", "description": "Compliance framework for triggered scans"},
					"watch_id":  map[string]any{"type": "string", "description": "Watch ID (for status/unregister)"},
				},
				"required": []string{"action"},
			},
		},
	}

	// Build canonical manifest (without signature)
	type ManifestCanonical struct {
		Version       string     `json:"version"`
		Revision      string     `json:"revision"`
		GeneratedAt   string     `json:"generated_at"`
		HashAlgorithm string     `json:"hash_algorithm"`
		PublicKeyID   string     `json:"public_key_id"`
		Tools         []ToolSpec `json:"tools"`
	}

	now := time.Now().UTC()
	canonical := ManifestCanonical{
		Version:       "1.0.0",
		Revision:      fmt.Sprintf("build-%d", now.Unix()),
		GeneratedAt:   now.Format("2006-01-02T15:04:05Z"),
		HashAlgorithm: "SHA-256",
		PublicKeyID:   keyID,
		Tools:         tools,
	}

	// Sign the canonical payload
	canonicalBytes, _ := json.Marshal(canonical)
	payloadHash := sha256.Sum256(canonicalBytes)
	sig, err := adinkra.Sign(privKey, payloadHash[:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "signing failed: %v\n", err)
		os.Exit(1)
	}

	// Build full signed manifest
	type SignedManifest struct {
		ManifestCanonical
		Signature string `json:"signature"`
	}

	signed := SignedManifest{
		ManifestCanonical: canonical,
		Signature:         hex.EncodeToString(sig),
	}

	// Output
	out, _ := json.MarshalIndent(signed, "", "  ")
	fmt.Println(string(out))
	fmt.Fprintf(os.Stderr, "manifest generated: %d tools, key_id=%s, signed=%d bytes\n",
		len(tools), keyID, len(sig))
}
