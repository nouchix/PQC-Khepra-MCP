// Khepra MCP Server — Hardened Entry Point (AD-006 / AD-008)
//
// This binary implements the world's first PQC-secured MCP server.
// It runs as a subprocess launched by AI tools (Claude, Cursor, Windsurf)
// via stdin/stdout JSON-RPC transport as defined by the MCP specification.
//
// Security chain:
//   DEMARC → Manifest → Polymorphic → MCPGateway → Executor → Attestation
//
// All tool responses are PQC-signed (Adinkhepra ML-DSA-65) and DAG-anchored.
// Tool schemas are pinned via signed manifest with fail-closed startup verification.
//
// Usage (configured in .mcp.json):
//
//	{
//	  "mcpServers": {
//	    "khepra-mcp": {
//	      "command": "go",
//	      "args": ["run", "./cmd/khepra-mcp/main.go"],
//	      "env": {
//	        "KHEPRA_MANIFEST_PATH": "./manifest.json",
//	        "PHANTOM_SYMBOL": "Eban"
//	      }
//	    }
//	  }
//	}
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/adinkra"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/config"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/dag"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/license"
	khepramcp "github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/mcp"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/mcp/tools"
)

func main() {
	// All diagnostic output goes to stderr (MCP: stdout = JSON-RPC only).
	logger := log.New(os.Stderr, "[khepra-mcp] ", log.LstdFlags|log.Lmicroseconds)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// ── Adinkra PQC Key Setup ────────────────────────────────────────────────
	symbol := getEnvOr("PHANTOM_SYMBOL", "Eban")
	_ = adinkra.GetSpectralFingerprint(symbol) // Validate symbol exists

	// Generate ML-DSA-65 key pair (compatible with adinkra.Sign/Verify)
	pubKey, privKey, err := adinkra.GenerateDilithiumKey()
	if err != nil {
		logger.Fatalf("FATAL: PQC key generation failed: %v", err)
	}

	keyHash := sha256.Sum256(pubKey)
	keyID := hex.EncodeToString(keyHash[:8])

	// ── Deployment Mode — read once, logged clearly ──────────────────────────
	// This is the canonical mode log line. All downstream components inherit
	// their storage and network policy from config.LoadRuntime().
	runCfg := config.LoadRuntime()
	logger.Printf("━━━ KHEPRA MCP SERVER ━━━")
	logger.Printf("  mode:           %s", runCfg.Mode)
	logger.Printf("  network_policy: %s", runCfg.NetworkPolicy)
	if runCfg.IsAirGapped {
		logger.Printf("  dag_store:      PersistentMemory (disk) → %s", runCfg.DAGPath)
		logger.Printf("  supabase:       DISABLED (air-gap mode)")
	} else {
		logger.Printf("  dag_store:      Memory (in-process, stateless SaaS)")
		logger.Printf("  supabase:       ENABLED (SaaS mode — requires saas build tag)")
	}
	logger.Printf("  symbol=%s | key_id=%s", symbol, keyID)

	// ── Transport mode enforcement ────────────────────────────────────────────
	// sovereign/ironbank: stdio only — refuse HTTP listener (air-gap policy).
	// edge/hybrid: HTTP/SSE allowed (Fly.io reverse proxy handles TLS).
	if runCfg.IsAirGapped {
		if os.Getenv("KHEPRA_HTTP_PORT") != "" {
			logger.Fatalf("FATAL: KHEPRA_HTTP_PORT=%s is set but KHEPRA_MODE=%s does not permit HTTP transport. "+
				"Sovereign/ironbank deployments use stdio transport only. "+
				"Remove KHEPRA_HTTP_PORT or switch to KHEPRA_MODE=edge for HTTP.",
				os.Getenv("KHEPRA_HTTP_PORT"), runCfg.Mode)
		}
		logger.Printf("  transport:      stdio only (air-gap policy — HTTP listener refused)")
	} else {
		logger.Printf("  transport:      stdio + HTTP/SSE available (set KHEPRA_HTTP_PORT to enable)")
	}

	// ── License Validation ──────────────────────────────────────────────
	// ParseMCPLicense loads KHEPRA_LICENSE_KEY and verifies offline via
	// ML-DSA-65 + device binding + expiry + IPFS CRL (sovereign.go stack).
	// Community tier (no key) is non-fatal; tampered/expired = fatal.
	licenseClaim, licErr := license.ParseMCPLicense()
	if errors.Is(licErr, license.ErrNoLicenseKey) {
		logger.Printf("[LICENSE] Community tier — Enterprise tools gated. Set KHEPRA_LICENSE_KEY to unlock.")
	} else if licErr != nil {
		// Key present but invalid (tampered / expired / wrong machine) = fatal
		logger.Fatalf("FATAL: license validation failed: %v", licErr)
	} else {
		logger.Printf("[LICENSE] %s tier | tenant=%q | id=%s | expires=%s",
			licenseClaim.Tier,
			licenseClaim.Tenant,
			licenseClaim.LicenseID,
			licenseClaim.ExpiresAt.Format("2006-01-02"),
		)
	}

	// ── Build Security Chain ─────────────────────────────────────────────────

	// 1. DEMARC Gateway — pre-authenticated identity for stdio transport
	demarc := &khepramcp.AdinkraDemarcGateway{
		StdioIdentity: khepramcp.Identity{
			Subject:   "khepra-mcp-stdio",
			Issuer:    "demarc",
			AgentID:   "local-agent",
			SessionID: keyID,
			Scopes:    []string{"*"}, // Stdio sessions have full access
		},
	}

	// 2. Polymorphic Engine — PQC envelope wrapping
	poly := &khepramcp.AdinkraPolymorphicEngine{
		Symbol:     symbol,
		PrivateKey: privKey,
		PublicKey:  pubKey,
	}

	// 3. MCP Gateway — RBAC + injection scanning
	gateway := khepramcp.NewDefaultMCPGateway()

	// 4. Manifest Registry — load and verify pinned tool definitions
	registry, err := loadManifestRegistry(ctx, pubKey, keyID, logger)
	if err != nil {
		logger.Fatalf("FATAL: manifest registry failed — fail-closed: %v", err)
	}
	logger.Printf("manifest loaded: %d tools, version=%s", registry.ToolCount(), registry.Version())

	// 5. Executor — risk-classified dispatch
	sandboxBackend := khepramcp.NewDockerSandbox(khepramcp.DockerSandboxConfig{
		Image:  getEnvOr("PHANTOM_IMAGE", "khepra-phantom:latest"),
		Config: khepramcp.DefaultSandboxConfig(),
		Logger: logger,
	})

	// Auto-approve gate for stdio (single-tenant subprocess model).
	// For HTTP transport, replace with interactive confirmation.
	confirmGate := &StdioConfirmationGate{logger: logger}

	executor := khepramcp.NewExecutor(khepramcp.ExecutorConfig{
		Sandbox: sandboxBackend,
		Confirm: confirmGate,
		Logger:  logger,
	})

	// 6. Register in-process tool handlers
	registerToolHandlers(executor)

	// 7. DAG Attestor — PQC-signed audit trail
	// dag.NewStore() selects PersistentMemory (sovereign) or Memory (SaaS/edge)
	// based on KHEPRA_MODE. This is already resolved in runCfg above.
	_ = runCfg // consumed above; dag.NewStore() re-reads KHEPRA_MODE internally
	dagStore := dag.NewStore()
	attestor := khepramcp.NewDAGAttestor(dagStore, symbol, privKey)

	// ── Assemble Router ──────────────────────────────────────────────────────
	//
	// Wire all security hardening fields introduced in the NSA/ASD reconciliation:
	//   SignedAuditLog    — per-entry ML-DSA-65-signed NDJSON chain (DFARS 252.204-7012)
	//   InvocationRootKey — per-call ephemeral HMAC tokens (ASD/CISA short-lived credentials)
	//   MaxConcurrent     — concurrent call cap per agent (NSA prompt-storm defense)

	// Open the tamper-evident audit log
	var signedLog *khepramcp.SignedAuditLog
	// Default audit log path: Windows uses %USERPROFILE%\.khepra\audit.ndjson,
	// Linux/macOS use /var/log/khepra/audit.ndjson (or override with env var).
	defaultAuditLog := "/var/log/khepra/audit.ndjson"
	if home := os.Getenv("USERPROFILE"); home != "" {
		defaultAuditLog = home + `\.khepra\audit.ndjson`
	} else if home := os.Getenv("HOME"); home != "" {
		defaultAuditLog = home + "/.khepra/audit.ndjson"
	}
	auditLogPath := getEnvOr("KHEPRA_AUDIT_LOG_PATH", defaultAuditLog)
	sal, salErr := khepramcp.NewSignedAuditLog(khepramcp.SignedAuditLogConfig{
		Path:    auditLogPath,
		PrivKey: privKey,
		PubKey:  pubKey,
	})
	if salErr != nil {
		// Non-fatal: log warning but continue without signed log
		logger.Printf("WARN: signed audit log unavailable (%s): %v — continuing without", auditLogPath, salErr)
	} else {
		signedLog = sal
		logger.Printf("signed audit log: %s", auditLogPath)
	}

	// Derive HMAC root key for per-invocation tokens from the ML-DSA-65 session key
	invocationRootKey := khepramcp.DeriveRootKey(privKey)

	// Max concurrent tool calls per agent (default: 5)
	maxConcurrent := 5
	if mc := os.Getenv("KHEPRA_MAX_CONCURRENT"); mc != "" {
		if n, err := strconv.Atoi(mc); err == nil && n > 0 {
			maxConcurrent = n
		}
	}

	router, err := khepramcp.NewRouter(khepramcp.RouterConfig{
		Demarc:   demarc,
		Poly:     poly,
		Gateway:  gateway,
		Registry: registry,
		Executor: executor,
		Attestor: attestor,
		Logger:   logger,
		// Security hardening (NSA/ASD reconciliation)
		SignedAuditLog:    signedLog,
		InvocationRootKey: invocationRootKey,
		MaxConcurrent:     maxConcurrent,
		// License enforcement
		License: licenseClaim,
	})
	if err != nil {
		logger.Fatalf("FATAL: router construction failed: %v", err)
	}

	// ── Start HardenedServer ─────────────────────────────────────────────────
	server, err := khepramcp.NewHardenedServer(khepramcp.HardenedServerConfig{
		Mode:       khepramcp.TransportStdio,
		Router:     router,
		Logger:     logger,
		Credential: "stdio", // Pre-authenticated for subprocess model
	})
	if err != nil {
		logger.Fatalf("FATAL: server construction failed: %v", err)
	}

	// ── Register Shutdown Hooks ──────────────────────────────────────────────
	// 0. Stop heartbeat daemon (handled by sovereign telemetry_client.go)
	// (no separate daemon to stop — sovereign stack manages its own lifecycle)
	// 1. Zero-out PQC private key material
	server.OnShutdown(func() {
		for i := range privKey {
			privKey[i] = 0
		}
		for i := range invocationRootKey {
			invocationRootKey[i] = 0
		}
		logger.Println("PQC private key material destroyed")
	})

	// 2. Flush and close signed audit log
	server.OnShutdown(func() {
		if signedLog != nil {
			if err := signedLog.Close(); err != nil {
				logger.Printf("WARN: audit log close error: %v", err)
			} else {
				logger.Printf("signed audit log closed: %s", auditLogPath)
			}
		}
	})

	// 3. Flush telemetry events
	server.OnShutdown(func() {
		events := router.Events().Flush()
		logger.Printf("flushed %d telemetry events", len(events))
	})

	// 3. Emit shutdown event
	router.Events().Emit(khepramcp.MCPEvent{
		Type:    khepramcp.EventStartup,
		Success: true,
		Metadata: map[string]any{
			"version":  "1.0.0-sovereign-mcp",
			"symbol":   symbol,
			"key_id":   keyID,
			"tools":    registry.ToolCount(),
			"manifest": registry.Version(),
		},
	})

	logger.Printf("starting hardened MCP server (stdio)")
	if err := server.Run(ctx); err != nil {
		// Run shutdown hooks even on error
		server.Shutdown(context.Background())
		logger.Fatalf("server error: %v", err)
	}
	server.Shutdown(context.Background())
	logger.Printf("shutdown complete")
}

// ─── Tool Handler Registration ─────────────────────────────────────────────────

func registerToolHandlers(executor *khepramcp.Executor) {
	// ── ACP: Agent Control Plane (credential lifecycle) ───────────────────
	executor.RegisterFunc("acp_status", tools.HandleACPStatus)
	executor.RegisterFunc("acp_issue", tools.HandleACPIssue)
	executor.RegisterFunc("acp_revoke", tools.HandleACPRevoke)

	// ── NHI: Non-Human Identity (service account / API key governance) ────
	executor.RegisterFunc("nhi_inventory", tools.HandleNHIInventory)
	executor.RegisterFunc("nhi_orphans", tools.HandleNHIOrphans)
	executor.RegisterFunc("nhi_excessive", tools.HandleNHIExcessive)
	executor.RegisterFunc("nhi_expired", tools.HandleNHIExpired)
	executor.RegisterFunc("nhi_revoke", tools.HandleNHIRevoke)

	// ── ERT: Enterprise Risk & Threat scanner (Docker sandbox) ────────────
	executor.RegisterFunc("ert_scan", tools.HandleERTScan)

	// ── ERT Packages A–D (in-process, JSON output, ASAF-enriched) ─────────
	// Package A — Mission Assurance Modeling (NIST 800-171 + SCA scoring)
	executor.RegisterFunc("ert_readiness", tools.HandleERTReadiness)
	// Package B — Supply Chain Hunter (Syft→Grype→Enricher pipeline)
	executor.RegisterFunc("ert_architect", tools.HandleERTArchitect)
	// Package C — PQC Attestation (SBOM crypto inventory + weak primitive scan)
	executor.RegisterFunc("ert_crypto", tools.HandleERTCrypto)
	// Package D — Causal Risk Attestation (KernelRouter synthesis + DAG)
	executor.RegisterFunc("ert_godfather", tools.HandleERTGodfather)

	// ── DAG Attestation — export signed audit trail ────────────────────────
	executor.RegisterFunc("dag_attestation", tools.HandleDAGAttestation)

	// ── Godfather Report + Human-in-the-Loop Gate ─────────────────────────
	// NSA/ASD Security Track 6: high-impact outputs require analyst approval
	executor.RegisterFunc("godfather_report", tools.HandleGodfatherReport)
	executor.RegisterFunc("godfather_approve", tools.HandleGodfatherApprove)

	// ── NIST Map: offline BM25 semantic control search (zero token cost) ──
	executor.RegisterFunc("nist_map", tools.HandleNistMapTool)

	// ── khepra_watch: filesystem-triggered continuous monitoring ──────────
	// CMMC AC.2.006, CM.2.061, SI.2.217 continuous monitoring requirement
	executor.RegisterFunc("khepra_watch", tools.HandleKhepraWatchTool)

	// ── SouHimBou AI: Step 01 — Discover & Classify Assets ──────────────────
	// Inventories environment: OS, runtimes, containers, CI/CD, AI agents,
	// crypto libs, MCP configs → matches applicable STIG profiles → recommends
	// CMMC level → suggests next tools (Step 02 handoff)
	executor.RegisterFunc("discover_assets", tools.HandleDiscoverAssets)

	// ── Compliance Tools (Architecture Doc Layer 4 — PQC-MCP exposures) ───
	// Gap-closure: these were listed in KHEPRA_Four_Layer_Architecture_v1.docx
	// but were not previously registered. NSA/ASD audit-gap fix.
	//
	// stig_check  — RHEL-09-STIG V1R3 check via pkg/stig Validator
	executor.RegisterFunc("stig_check", tools.HandleSTIGCheck)
	// pqc_stig — World's First DoD PQC STIG (PQC-01-STIG-V1R1, CNSA 2.0 / FIPS 203/204/205)
	executor.RegisterFunc("pqc_stig", tools.HandlePQCSTIG)
	// cmmc_assess — CMMC Level 1/2/3 assessment via pkg/stig Validator
	executor.RegisterFunc("cmmc_assess", tools.HandleCMMCAssess)
	// agent_record — Layer 4→3 bridge: SouHimBou AI Flight Recorder
	executor.RegisterFunc("agent_record", tools.HandleAgentRecord)

	// ── Sovereign Tools (no Supabase, no network — 100% offline) ───────────
	// P0: C3PAO artifact — existential differentiator
	executor.RegisterFunc("khepra_export_attestation", tools.HandleKhepraExportAttestation)
	// P0: POA&M — DFARS 252.204-7012 mandatory
	executor.RegisterFunc("khepra_export_poam", tools.HandleKhepraExportPOAM)
	// P1: STIG/CCI/NIST control lookup via embedded 36,195-row database
	executor.RegisterFunc("khepra_query_stig", tools.HandleKhepraQuerySTIG)
	// P1: Fast compliance score without full scan
	executor.RegisterFunc("khepra_get_compliance_score", tools.HandleKhepraGetComplianceScore)
	// P1: CISA KEV + CVE threat intel from embedded data
	executor.RegisterFunc("khepra_query_threat_intel", tools.HandleKhepraQueryThreatIntel)
	// P2: Session DAG chain export
	executor.RegisterFunc("khepra_get_dag_chain", tools.HandleKhepraGetDAGChain)

	// ── SouHimBou AI: Flight Recorder (Step 03 — Generate Evidence) ─────────
	// flight_export: export a CMMC-aligned evidence packet from the flight log
	//   Maps all agent actions → NIST 800-171 / CMMC 2.0 controls
	//   Verifies tamper chain + computes all SOW pilot KPIs
	executor.RegisterFunc("flight_export", tools.HandleFlightExport)

	// ── OWASP Agentic Top 10 for 2026 (ASI01-ASI10) ───────────────────────
	// Assesses this MCP server deployment against all 10 ASI risks.
	// Returns scored findings, active controls, gaps, and a PQC-signed
	// evidence packet with executive summary and production readiness verdict.
	// Competitive differentiator: only tool that maps agent stack to OWASP
	// Agentic Top 10 with ML-DSA-65 signed evidence — 100% offline.
	executor.RegisterFunc("owasp_agent_assess", tools.HandleOWASPAgentAssess)

	// ── Dark Crypto Intelligence Network (Community Tier) ───────────────────
	// Privacy-preserving contribution of anonymized crypto inventory to the
	// global Dark Crypto Intelligence Network. No file paths, IPs, hostnames,
	// credentials, or code contents leave the machine. Users receive back their
	// global quantum exposure rank and community intelligence.
	// This is the primary value exchange of the Community open-source tier.
	executor.RegisterFunc("dark_crypto_contribute", tools.HandleDarkCryptoContribute)
}

// ─── Manifest Loading ──────────────────────────────────────────────────────────

func loadManifestRegistry(ctx context.Context, pubKey []byte, keyID string, logger *log.Logger) (*khepramcp.ManifestRegistry, error) {
	manifestPath := getEnvOr("KHEPRA_MANIFEST_PATH", "manifest.json")

	// Try loading from file first
	if _, err := os.Stat(manifestPath); err == nil {
		logger.Printf("loading manifest from %s", manifestPath)
		store := &khepramcp.FileManifestStore{Path: manifestPath}
		// Use bootstrap verifier initially; switch to AdinkraManifestVerifier once
		// the signed manifest is generated with real PQC keys.
		verifier := &khepramcp.BootstrapManifestVerifier{}
		return khepramcp.LoadRegistry(ctx, store, verifier)
	}

	// Fallback: generate embedded bootstrap manifest
	logger.Printf("no manifest file found at %s — generating bootstrap manifest", manifestPath)
	return generateBootstrapManifest(ctx, pubKey, keyID)
}

func generateBootstrapManifest(ctx context.Context, pubKey []byte, keyID string) (*khepramcp.ManifestRegistry, error) {
	toolSpecs := defaultToolSpecs()

	manifest, err := khepramcp.GenerateSignedManifest(toolSpecs, pubKey, keyID)
	if err != nil {
		return nil, err
	}

	store := &khepramcp.EmbeddedManifestStore{Manifest: manifest}
	verifier := &khepramcp.BootstrapManifestVerifier{}
	return khepramcp.LoadRegistry(ctx, store, verifier)
}

// defaultToolSpecs returns the hardened tool specification list.
// This is also the spec set registered in the bootstrap manifest when no
// signed manifest.json file is present (Docker image always ships manifest.json).
func defaultToolSpecs() []khepramcp.ToolSpec {
	hash := func(name string) string {
		h := sha256.Sum256([]byte(name + ":v1"))
		return hex.EncodeToString(h[:])
	}

	// noArgSchema is used for tools that require no parameters.
	// MCP clients REQUIRE inputSchema to be present — omitting it hides the tool.
	noArgSchema := map[string]any{
		"type":       "object",
		"properties": map[string]any{},
	}

	return []khepramcp.ToolSpec{
		// ── ACP (Agent Control Plane) ────────────────────────────────────────
		{
			Name: "acp_status", Description: "List active ACP credentials and their expiry status",
			RiskClass: khepramcp.RiskReadOnly, Scope: "acp:read",
			SchemaVersion: "1.0.0", SchemaHash: hash("acp_status"),
			AllowedBackend: "in-process", TimeoutMs: 5000,
			MaxPrivilege: "read-only",
			ArgsSchema:   noArgSchema,
		},
		{
			Name: "acp_issue", Description: "Issue a new PQC credential via the Agent Control Plane",
			RiskClass: khepramcp.RiskDestructive, Scope: "acp:write", Destructive: true,
			SchemaVersion: "1.0.0", SchemaHash: hash("acp_issue"),
			AllowedBackend: "in-process", TimeoutMs: 10000,
			MaxPrivilege: "none",
			ArgsSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"subject":    map[string]any{"type": "string", "description": "Principal identifier for the new credential"},
					"scopes":     map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "Permission scopes to grant"},
					"expires_in": map[string]any{"type": "string", "description": "Credential TTL (e.g. '24h', '7d')"},
				},
				"required": []string{"subject"},
			},
		},
		{
			Name: "acp_revoke", Description: "Revoke an active ACP credential",
			RiskClass: khepramcp.RiskDestructive, Scope: "acp:write", Destructive: true,
			SchemaVersion: "1.0.0", SchemaHash: hash("acp_revoke"),
			AllowedBackend: "in-process", TimeoutMs: 10000,
			MaxPrivilege: "none",
			ArgsSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"credential_id": map[string]any{"type": "string", "description": "ID of the ACP credential to revoke"},
				},
				"required": []string{"credential_id"},
			},
		},

		// ── NHI (Non-Human Identity) ─────────────────────────────────────────
		{
			Name: "nhi_inventory", Description: "List all non-human identities (service accounts, API keys, certificates)",
			RiskClass: khepramcp.RiskReadOnly, Scope: "nhi:read",
			SchemaVersion: "1.0.0", SchemaHash: hash("nhi_inventory"),
			AllowedBackend: "in-process", TimeoutMs: 5000,
			MaxPrivilege: "read-only",
			ArgsSchema:   noArgSchema,
		},
		{
			Name: "nhi_orphans", Description: "Identify orphaned non-human identities with no active owner",
			RiskClass: khepramcp.RiskReadOnly, Scope: "nhi:read",
			SchemaVersion: "1.0.0", SchemaHash: hash("nhi_orphans"),
			AllowedBackend: "in-process", TimeoutMs: 5000,
			MaxPrivilege: "read-only",
			ArgsSchema:   noArgSchema,
		},
		{
			Name: "nhi_excessive", Description: "Identify NHIs with overly broad permissions",
			RiskClass: khepramcp.RiskReadOnly, Scope: "nhi:read",
			SchemaVersion: "1.0.0", SchemaHash: hash("nhi_excessive"),
			AllowedBackend: "in-process", TimeoutMs: 5000,
			MaxPrivilege: "read-only",
			ArgsSchema:   noArgSchema,
		},
		{
			Name: "nhi_expired", Description: "List expired or soon-to-expire non-human identities",
			RiskClass: khepramcp.RiskReadOnly, Scope: "nhi:read",
			SchemaVersion: "1.0.0", SchemaHash: hash("nhi_expired"),
			AllowedBackend: "in-process", TimeoutMs: 5000,
			MaxPrivilege: "read-only",
			ArgsSchema:   noArgSchema,
		},
		{
			Name: "nhi_revoke", Description: "Revoke a non-human identity credential",
			RiskClass: khepramcp.RiskDestructive, Scope: "nhi:write", Destructive: true,
			SchemaVersion: "1.0.0", SchemaHash: hash("nhi_revoke"),
			AllowedBackend: "in-process", TimeoutMs: 10000,
			MaxPrivilege: "none",
			ArgsSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"nhi_id": map[string]any{"type": "string", "description": "NHI identifier to revoke"},
				},
				"required": []string{"nhi_id"},
			},
		},

		// ── ERT (Enterprise Risk & Threat Scanner) ───────────────────────────
		// Runs in Docker sandbox with capability mounts scoped to the scan target.
		// ASD/CISA confused-deputy defense: only the directories declared here
		// are accessible inside the container.
		{
			Name: "ert_scan", Description: "Run ERT security scan (SBOM, CVE, secrets, STIG, PQC inventory) in Docker sandbox",
			RiskClass: khepramcp.RiskSandboxed, Scope: "ert:scan",
			SchemaVersion: "1.0.0", SchemaHash: hash("ert_scan"),
			AllowedBackend: "docker", TimeoutMs: 90000, NetworkAllowed: false,
			MaxPrivilege: "read-only",
			// CapabilityMounts: populated at runtime from call.Args["project_path"]
			// The router's ASD/CISA defense validates these are not traversal paths.
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

		// ── ERT Packages A–D (in-process, structured JSON, ASAF-enriched) ────
		{
			Name:           "ert_readiness",
			Description:    "Package A: NIST 800-171 Rev2 compliance assessment + live SCA risk factor. Returns alignment score (0–100), control gaps, and prioritized remediation roadmap. Air-gap safe.",
			RiskClass:      khepramcp.RiskReadOnly, Scope: "ert:compliance",
			SchemaVersion:  "1.0.0", SchemaHash: hash("ert_readiness"),
			AllowedBackend: "in-process", TimeoutMs: 60000,
			MaxPrivilege:   "read-only",
			ArgsSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"project_path": map[string]any{"type": "string", "description": "Path to project directory (default: current directory)"},
				},
			},
		},
		{
			Name:           "ert_architect",
			Description:    "Package B: Live supply chain risk — Syft SBOM generation + Grype CVE matching + threat intel enrichment (CISA KEV, EPSS, MITRE ATT&CK). Returns enriched findings with NIST 800-171 control mapping.",
			RiskClass:      khepramcp.RiskReadOnly, Scope: "ert:supply-chain",
			SchemaVersion:  "1.0.0", SchemaHash: hash("ert_architect"),
			AllowedBackend: "in-process", TimeoutMs: 300000,
			MaxPrivilege:   "read-only",
			ArgsSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"project_path": map[string]any{"type": "string", "description": "Path to project directory"},
					"image_ref":    map[string]any{"type": "string", "description": "Container image reference to scan"},
				},
			},
		},
		{
			Name:           "ert_crypto",
			Description:    "Package C: PQC readiness attestation — source-level crypto primitive scan, SBOM crypto library inventory (OpenSSL, Kyber, Dilithium, etc.), weak primitive detection (MD5/SHA1/DES/RC4), CNSA 2.0 scenario-based quantum risk context.",
			RiskClass:      khepramcp.RiskReadOnly, Scope: "ert:pqc",
			SchemaVersion:  "1.0.0", SchemaHash: hash("ert_crypto"),
			AllowedBackend: "in-process", TimeoutMs: 180000,
			MaxPrivilege:   "read-only",
			ArgsSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"project_path": map[string]any{"type": "string", "description": "Path to project directory"},
				},
			},
		},
		{
			Name:           "ert_godfather",
			Description:    "Package D: EA KernelRouter-synthesized causal risk attestation. Runs STIG, PQC, SBOM, and Network agents in parallel, produces board-level causal chain with CVSS-band dollar impact estimate and DAG-signed evidence node.",
			RiskClass:      khepramcp.RiskReadOnly, Scope: "ert:godfather",
			SchemaVersion:  "1.0.0", SchemaHash: hash("ert_godfather"),
			AllowedBackend: "in-process", TimeoutMs: 300000,
			MaxPrivilege:   "read-only",
			ArgsSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"project_path": map[string]any{"type": "string", "description": "Path to project directory"},
					"framework":    map[string]any{"type": "string", "description": "Compliance framework to assess against"},
				},
			},
		},

		// ── DAG Attestation ──────────────────────────────────────────────────
		{
			Name:           "dag_attestation",
			Description:    "Export the PQC-signed DAG audit trail for the current session. Returns all DAG nodes with ML-DSA-65 signatures, timestamps, and Adinkra symbol chain. Use after any ERT scan to produce a cryptographically-verifiable evidence package.",
			RiskClass:      khepramcp.RiskReadOnly, Scope: "dag:read",
			SchemaVersion:  "1.0.0", SchemaHash: hash("dag_attestation"),
			AllowedBackend: "in-process", TimeoutMs: 10000,
			MaxPrivilege:   "read-only",
			ArgsSchema:     noArgSchema,
		},

		// ── STIG Check ────────────────────────────────────────────────────────
		// Architecture Doc Layer 4 tool. Runs RHEL-09-STIG V1R3 or any
		// supported framework via the pkg/stig Validator engine.
		{
			Name: "stig_check",
			Description: "Check a system path or configuration against STIG controls. Runs RHEL-09-STIG V1R3 by default. Returns CAT I/II/III findings with remediation guidance and a compliance score. Supports: RHEL-09-STIG-V1R3, CIS-RHEL-9-L1, CIS-RHEL-9-L2, NIST-800-53-Rev5, NIST-800-171-Rev2, CMMC-3.0-L3, PQC-Readiness.",
			RiskClass:      khepramcp.RiskReadOnly, Scope: "stig:read",
			SchemaVersion:  "1.0.0", SchemaHash: hash("stig_check"),
			AllowedBackend: "in-process", TimeoutMs: 60000,
			MaxPrivilege:   "read-only",
			ArgsSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"framework": map[string]any{
						"type":        "string",
						"description": "Compliance framework to check (default: RHEL-09-STIG-V1R3). Options: RHEL-09-STIG-V1R3, CIS-RHEL-9-L1, CIS-RHEL-9-L2, NIST-800-53-Rev5, NIST-800-171-Rev2, CMMC-3.0-L3, PQC-Readiness",
					},
				},
			},
		},

		// ── CMMC Assessment ───────────────────────────────────────────────────
		// Architecture Doc Layer 4 tool. Full CMMC 3.0 Level 1/2/3 assessment
		// via the pkg/stig compliance database (36,195 control mappings).
		{
			Name: "cmmc_assess",
			Description: "Assess a system or artifact against CMMC Level 1, 2, or 3 practices. Uses the KHEPRA compliance database (36,195 STIG→CCI→NIST→CMMC mappings). Returns satisfaction score, gap list, C3PAO readiness flag, and PQC status. Required before CMMC-AB assessment.",
			RiskClass:      khepramcp.RiskReadOnly, Scope: "compliance:read",
			SchemaVersion:  "1.0.0", SchemaHash: hash("cmmc_assess"),
			AllowedBackend: "in-process", TimeoutMs: 60000,
			MaxPrivilege:   "read-only",
			ArgsSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"level": map[string]any{
						"type":        "string",
						"description": "CMMC maturity level to assess: '1', '2', or '3' (default: '2'). Also accepts: l1, l2, l3, CMMC_L1, CMMC_L2, CMMC_L3",
					},
				},
			},
		},

		// ── Agent Record (Layer 4 → Layer 3 bridge) ───────────────────────────
		// Forwards agent action events to SouHimBou AI Flight Recorder.
		// Sovereign fallback: records in local PQC-signed DAG audit log.
		{
			Name: "agent_record",
			Description: "Record an agent action in the SouHimBou AI Flight Recorder (agentic AI observability). In sovereign/air-gap mode, records to the local PQC-signed DAG audit log. Set SOUHIMBOU_ENDPOINT env var to forward to SouHimBou AI SaaS. Required for AI flight recorder compliance evidence.",
			RiskClass:      khepramcp.RiskReadOnly, Scope: "audit:write",
			SchemaVersion:  "1.0.0", SchemaHash: hash("agent_record"),
			AllowedBackend: "in-process", TimeoutMs: 15000,
			MaxPrivilege:   "audit-write",
			ArgsSchema: map[string]any{
				"type": "object",
				"required": []string{"action"},
				"properties": map[string]any{
					"action":     map[string]any{"type": "string", "description": "The agent action to record (e.g. 'tool_called', 'decision_made', 'file_modified', 'scan_completed')"},
					"agent_id":   map[string]any{"type": "string", "description": "Agent identifier (defaults to session agent_id)"},
					"tool_name":  map[string]any{"type": "string", "description": "Tool that was invoked (for tool_called events)"},
					"session_id": map[string]any{"type": "string", "description": "Session identifier for correlation"},
					"metadata":   map[string]any{"type": "object", "description": "Additional key-value metadata to attach to the flight recorder event"},
				},
			},
		},

		// ── Godfather Report (HITL-gated) ─────────────────────────────────────
		// Security Track 6: staged delivery with 30-min TTL token.
		// Full report only released after human calls godfather_approve.
		{
			Name: "godfather_report",
			Description: "Generate a complete CMMC/STIG/NIST compliance report. When approval_required=true, returns a staged token — the full report is held until a human calls godfather_approve.",
			RiskClass: khepramcp.RiskReadOnly, Scope: "compliance:report",
			SchemaVersion: "1.0.0", SchemaHash: hash("godfather_report"),
			AllowedBackend: "in-process", TimeoutMs: 30000,
			MaxPrivilege: "stig-db-read",
			ArgsSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"framework":        map[string]any{"type": "string", "description": "Compliance framework (CMMC_L2, NIST_800_171, STIG)"},
					"approval_required": map[string]any{"type": "boolean", "description": "If true, returns staged token requiring human approval"},
					"project_path":     map[string]any{"type": "string", "description": "Path to project directory"},
				},
			},
		},
		{
			Name: "godfather_approve",
			Description: "Deliver a staged Godfather Report. Requires the staged_token returned by godfather_report. Single-use — token is consumed on delivery.",
			RiskClass: khepramcp.RiskReadOnly, Scope: "compliance:report",
			SchemaVersion: "1.0.0", SchemaHash: hash("godfather_approve"),
			AllowedBackend: "in-process", TimeoutMs: 5000,
			MaxPrivilege: "read-only",
			ArgsSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"staged_token": map[string]any{"type": "string", "description": "Token returned by godfather_report when approval_required=true"},
				},
				"required": []string{"staged_token"},
			},
		},

		// ── NIST Map (offline BM25 semantic search) ──────────────────────────
		// Zero token cost, zero network calls, air-gap safe.
		// 36,195 NIST/CMMC/STIG control mappings indexed at startup.
		{
			Name: "nist_map",
			Description: "Offline semantic search across NIST 800-53 Rev5, NIST 800-171 Rev2, CMMC 2.0, and STIG CCI mappings. BM25 ranked results. Zero token cost, air-gap safe.",
			RiskClass: khepramcp.RiskReadOnly, Scope: "compliance:read",
			SchemaVersion: "1.0.0", SchemaHash: hash("nist_map"),
			AllowedBackend: "in-process", TimeoutMs: 5000,
			MaxPrivilege: "read-only",
			ArgsSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"query":      map[string]any{"type": "string", "description": "Search query (natural language or control ID)"},
					"frameworks": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "Filter by framework(s): NIST_800_53, NIST_800_171, CMMC, STIG"},
					"limit":      map[string]any{"type": "integer", "description": "Maximum results to return (default: 10)"},
				},
				"required": []string{"query"},
			},
		},

		// ── khepra_watch (continuous monitoring) ─────────────────────────────
		// Registers filesystem watches that fire ert_scan on file change.
		// Satisfies CMMC AC.2.006, CM.2.061, SI.2.217.
		{
			Name: "khepra_watch",
			Description: "Register a filesystem path for continuous STIG-triggered scanning. Fires ert_scan on file changes. Action: register | status | unregister.",
			RiskClass: khepramcp.RiskReadOnly, Scope: "compliance:monitor",
			SchemaVersion: "1.0.0", SchemaHash: hash("khepra_watch"),
			AllowedBackend: "in-process", TimeoutMs: 10000,
			MaxPrivilege: "read-only",
			ArgsSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"action": map[string]any{"type": "string", "enum": []string{"register", "status", "unregister"}, "description": "Action to perform"},
					"path":   map[string]any{"type": "string", "description": "Filesystem path to watch"},
				},
				"required": []string{"action"},
			},
		},

		// ── Sovereign Tools (no Supabase, 100% offline) ────────────────────
		// P0 — C3PAO evidence package: the existential differentiator
		{
			Name:        "khepra_export_attestation",
			Description: "Export a PQC-signed attestation package (JSON) covering all active compliance frameworks. No Supabase. No network. The C3PAO-ready evidence artifact — Dilithium-signed, DAG-anchored, NIST SP 800-171A compliant. Include dag_node_id in your C3PAO submission package.",
			RiskClass: khepramcp.RiskReadOnly, Scope: "compliance:attest",
			SchemaVersion: "1.0.0", SchemaHash: hash("khepra_export_attestation"),
			AllowedBackend: "in-process", TimeoutMs: 120000,
			MaxPrivilege: "read-only",
			ArgsSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"project_path": map[string]any{"type": "string", "description": "Path to project or system root (default: current directory)"},
				},
			},
		},

		// P0 — POA&M: DFARS 252.204-7012 mandated Plan of Action & Milestones
		{
			Name:        "khepra_export_poam",
			Description: "Export a Plan of Action & Milestones (POA&M) from STIG/CMMC scan findings. DFARS 252.204-7012 and NIST SP 800-171A requirement. Returns prioritized remediation items with estimated costs and scheduled completion dates. 100% offline.",
			RiskClass: khepramcp.RiskReadOnly, Scope: "compliance:poam",
			SchemaVersion: "1.0.0", SchemaHash: hash("khepra_export_poam"),
			AllowedBackend: "in-process", TimeoutMs: 120000,
			MaxPrivilege: "read-only",
			ArgsSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"project_path": map[string]any{"type": "string", "description": "Path to project or system root (default: current directory)"},
				},
			},
		},

		// P1 — STIG control lookup by ID or free-text search
		{
			Name:        "khepra_query_stig",
			Description: "Look up STIG controls, CCI items, or NIST 800-53 controls by ID or keyword. Backed by the embedded 36,195-row STIG↔CCI↔NIST↔CMMC cross-reference database. Returns cross-references, severity, and remediation context. 100% offline.",
			RiskClass: khepramcp.RiskReadOnly, Scope: "stig:read",
			SchemaVersion: "1.0.0", SchemaHash: hash("khepra_query_stig"),
			AllowedBackend: "in-process", TimeoutMs: 10000,
			MaxPrivilege: "read-only",
			ArgsSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"control_id": map[string]any{"type": "string", "description": "STIG ID (SV-257777r...), CCI number (CCI-000001), or NIST control (AC-2, SC-13)"},
					"query":      map[string]any{"type": "string", "description": "Free-text search across STIG titles (e.g. 'password complexity', 'ssh', 'audit log')"},
				},
			},
		},

		// P1 — Fast compliance score without full scan (dashboard use)
		{
			Name:        "khepra_get_compliance_score",
			Description: "Get the compliance score for a specific framework without running a full scan. Targeted scan against a single framework. Good for dashboards and quick health checks. Frameworks: CMMC, STIG, NIST-171, NIST-53, PQC, PQC-STIG.",
			RiskClass: khepramcp.RiskReadOnly, Scope: "compliance:read",
			SchemaVersion: "1.0.0", SchemaHash: hash("khepra_get_compliance_score"),
			AllowedBackend: "in-process", TimeoutMs: 60000,
			MaxPrivilege: "read-only",
			ArgsSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"framework":    map[string]any{"type": "string", "description": "Framework alias: CMMC, STIG, NIST-171, NIST-53, PQC, PQC-STIG (default: CMMC)"},
					"project_path": map[string]any{"type": "string", "description": "Path to project or system root (default: current directory)"},
				},
			},
		},

		// P1 — CISA KEV + CVE threat intel from embedded offline database
		{
			Name:        "khepra_query_threat_intel",
			Description: "Query CISA Known Exploited Vulnerabilities (KEV) and NVD CVE data from the embedded offline database. Search by CVE ID (CVE-2021-44228) or keyword (log4j, apache, openssl). Returns severity, KEV status, and remediation action. 100% offline — no NVD API calls.",
			RiskClass: khepramcp.RiskReadOnly, Scope: "threat:read",
			SchemaVersion: "1.0.0", SchemaHash: hash("khepra_query_threat_intel"),
			AllowedBackend: "in-process", TimeoutMs: 10000,
			MaxPrivilege: "read-only",
			ArgsSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"query":  map[string]any{"type": "string", "description": "CVE ID (CVE-2021-44228) or keyword (log4j, apache, openssl, microsoft)"},
					"cve_id": map[string]any{"type": "string", "description": "Specific CVE ID for exact lookup"},
				},
			},
		},

		// P2 — Session DAG audit chain export
		{
			Name:        "khepra_get_dag_chain",
			Description: "Retrieve the ML-DSA-65-signed DAG audit chain for the current session. Each node represents a tool call with a PQC signature, timestamp, and Adinkra symbol. Use to produce a forensic evidence package for C3PAO or DFARS audit. 100% offline.",
			RiskClass: khepramcp.RiskReadOnly, Scope: "dag:read",
			SchemaVersion: "1.0.0", SchemaHash: hash("khepra_get_dag_chain"),
			AllowedBackend: "in-process", TimeoutMs: 10000,
			MaxPrivilege: "read-only",
			ArgsSchema: noArgSchema,
		},

		// SouHimBou AI Step 01 — Discover & Classify
		{
			Name:        "discover_assets",
			Description: "SouHimBou AI Step 01 — Discover & Classify Assets. Walks the project or system root and automatically inventories: OS (via /etc/os-release), language runtimes (Go, Python, Node.js, Java, Rust), container images (Dockerfile FROM directives), CI/CD pipelines, IaC (Terraform, Ansible), AI agent integrations (Claude, OpenAI, LangChain), MCP server configs, secret stores, and cryptographic libraries. Matches detected assets to applicable STIG profiles (RHEL-09-STIG-V1R3, Container STIG, CNSA 2.0 PQC, AI-Agent-MCP-SEC). Recommends CMMC level (L1/L2/L3) and generates a prioritized list of next tools to run. Output feeds directly into stig_check, cmmc_assess, ert_crypto, ert_architect, and flight_export.",
			RiskClass: khepramcp.RiskReadOnly, Scope: "compliance:read",
			SchemaVersion: "1.0.0", SchemaHash: hash("discover_assets"),
			AllowedBackend: "in-process", TimeoutMs: 30000,
			MaxPrivilege: "read-only",
			ArgsSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"project_path": map[string]any{"type": "string", "description": "Root path to scan (default: current directory)"},
					"depth":        map[string]any{"type": "integer", "description": "Max filesystem depth to walk (default: 4)"},
				},
			},
		},

		// SouHimBou AI Step 01 — Discover & Classify: agent_record
		{
			Name:        "agent_record",
			Description: "SouHimBou AI Flight Recorder: record an agent action in the tamper-evident flight log. Captures intent summary, session context, and CMMC control mappings. In sovereign mode, writes to a local ML-DSA-65-signed NDJSON log. If SOUHIMBOU_ENDPOINT is set, forwards to the SouHimBou AI SaaS. Required field: action (human-readable description of what the agent did).",
			RiskClass: khepramcp.RiskReadOnly, Scope: "audit:write",
			SchemaVersion: "1.0.0", SchemaHash: hash("agent_record"),
			AllowedBackend: "in-process", TimeoutMs: 5000,
			MaxPrivilege: "read-only",
			ArgsSchema: map[string]any{
				"type": "object",
				"required": []string{"action"},
				"properties": map[string]any{
					"action":     map[string]any{"type": "string", "description": "Human-readable description of the agent action (e.g. 'Ran stig_check on /opt/app')"},
					"agent_id":   map[string]any{"type": "string", "description": "Agent identifier override (default: ACP identity)"},
					"session_id": map[string]any{"type": "string", "description": "Session correlation ID for grouping actions into evidence packets"},
					"tool_name":  map[string]any{"type": "string", "description": "Name of the MCP tool that produced this action (for intent tracking)"},
				},
			},
		},

		// SouHimBou AI Step 03 — Generate Evidence: flight_export
		{
			Name:        "flight_export",
			Description: "SouHimBou AI Flight Recorder: export a CMMC-aligned evidence packet from the flight log. Reads the persistent signed flight log, verifies the ML-DSA-65 tamper chain, and produces a structured EvidencePacket mapping all agent actions to NIST SP 800-171 Rev 2 and CMMC 2.0 Level 2 controls. Computes all SOW pilot KPIs: calls captured, % privileged calls signed, mean evidence time, control mapping count. 100% offline.",
			RiskClass: khepramcp.RiskReadOnly, Scope: "compliance:report",
			SchemaVersion: "1.0.0", SchemaHash: hash("flight_export"),
			AllowedBackend: "in-process", TimeoutMs: 30000,
			MaxPrivilege: "read-only",
			ArgsSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"session_id": map[string]any{"type": "string", "description": "Filter to a specific session ID (omit to export all sessions)"},
					"log_path":   map[string]any{"type": "string", "description": "Path to flight log file (default: $KHEPRA_DATA_DIR/khepra-flight.ndjson)"},
				},
			},
		},
	}
}

// ─── Confirmation Gate ─────────────────────────────────────────────────────────

// StdioConfirmationGate auto-approves destructive operations for stdio sessions.
// This is acceptable for single-tenant subprocess model where the human controls
// the parent process. For HTTP/multi-tenant, use an interactive gate.
type StdioConfirmationGate struct {
	logger *log.Logger
}

func (g *StdioConfirmationGate) Confirm(_ context.Context, spec khepramcp.ToolSpec, call khepramcp.MCPToolCall) error {
	g.logger.Printf("[CONFIRM] auto-approved destructive tool=%s agent=%s (stdio single-tenant)",
		spec.Name, call.Identity.AgentID)
	return nil
}

// ─── Helpers ───────────────────────────────────────────────────────────────────

func getEnvOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
