// ASAF Stargate Hub — The Unification Binary
//
// "Take the skin and muscles of the CMMC Graph UI and bolt it on the skeleton
//  and nervous system of the PQC-Khepra-MCP Server."
//
// Binary layout:
//   PORT 8443 — Stargate Hub:  UI + Fleet API + KASA + Imhotep + Blackhole VPN
//   PORT 8444 — MCP Server:    PQC-Khepra-MCP HTTP/SSE (42 tools, SEKHEM WAF, KASA)
//
// The two ports share: DAG store, KASA engine, PQC keys, license, Sekhem Triad.
// The Stargate UI at :8443 calls /api/v1/mcp/ask on :8444 for AI-assisted queries.
//
// Build:
//   go build -o bin/asaf-hub.exe ./cmd/asaf-hub
//   ./bin/asaf-hub.exe
//
// Copyright: SOUHIMBOU DOH KONE LLC — exclusively licensed to SecRed Knowledge Inc.
// Patent Pending: USPTO #73565085
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/nouchix/PQC-Khepra-MCP/pkg/adinkra"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/agi"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/asaf/fleet"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/asaf/hub"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/asaf/scanner"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/config"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/dag"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/gateway"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/license"
	khepramcp "github.com/nouchix/PQC-Khepra-MCP/pkg/mcp"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/mcp/tools"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/sekhem"
)

const (
	version     = "1.5.0"
	defaultHubPort = "8443"
	defaultMCPPort = "8444"
)

func main() {
	logger := log.New(os.Stderr, "[asaf-hub] ", log.LstdFlags|log.Lmicroseconds)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// ── Config ────────────────────────────────────────────────────────────────
	hubPort := getEnv("KHEPRA_HUB_PORT", defaultHubPort)
	mcpPort := getEnv("KHEPRA_MCP_PORT", defaultMCPPort)
	hubAddr := fmt.Sprintf(":%s", hubPort)
	mcpAddr := fmt.Sprintf(":%s", mcpPort)
	orgName := getEnv("KHEPRA_ORG_NAME", "NouchiX / SecRed Knowledge Inc.")
	khepraMode := getEnv("KHEPRA_MODE", "sovereign")
	frameworks := getEnv("KHEPRA_FRAMEWORKS", "CMMC,NIST800-171,STIG")
	hubExtAddr := getEnv("KHEPRA_HUB_ADDR", fmt.Sprintf("http://localhost:%s", hubPort))
	dataPath := dataDir()

	runCfg := config.LoadRuntime()

	logger.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	logger.Printf("  ASAF Stargate Hub v%s — USPTO #73565085", version)
	logger.Printf("  SecRed Knowledge Inc. / SOUHIMBOU DOH KONE LLC")
	logger.Printf("  mode=%-12s  org=%s", khepraMode, orgName)
	logger.Printf("  data=%s", dataPath)
	logger.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	// ── PQC Keys ──────────────────────────────────────────────────────────────
	symbol := getEnv("PHANTOM_SYMBOL", "Eban")
	_ = adinkra.GetSpectralFingerprint(symbol)

	pubKey, privKey, err := adinkra.GenerateDilithiumKey()
	if err != nil {
		logger.Fatalf("FATAL: PQC key generation failed: %v", err)
	}
	keyHash := sha256.Sum256(pubKey)
	keyID := hex.EncodeToString(keyHash[:8])
	logger.Printf("[PQC] ML-DSA-65 | symbol=%s | key_id=%s", symbol, keyID)

	// ── License ───────────────────────────────────────────────────────────────
	licenseClaim, licErr := license.ParseMCPLicense()
	if errors.Is(licErr, license.ErrNoLicenseKey) {
		logger.Printf("[LICENSE] Community tier — set KHEPRA_LICENSE_KEY for Enterprise")
	} else if licErr != nil {
		logger.Fatalf("FATAL: license validation failed: %v", licErr)
	} else {
		logger.Printf("[LICENSE] %s | tenant=%q | expires=%s",
			licenseClaim.Tier, licenseClaim.Tenant,
			licenseClaim.ExpiresAt.Format("2006-01-02"))
	}

	// ── DAG Store (shared between MCP and Hub) ────────────────────────────────
	dagStore := dag.NewStore()
	seededCount := dag.SeedDemoNodes(dagStore, dag.SeedConfig{
		MinNodes: 10, PrivKey: privKey, ServerVersion: version,
	})
	if seededCount > 0 {
		logger.Printf("[DAG] %d demo nodes seeded (mode=%s)", seededCount, runCfg.Mode)
	}

	// ── KASA Engine (shared) ──────────────────────────────────────────────────
	kasaEngine := agi.NewEngine(dagStore)
	kasaEngine.Start()
	logger.Printf("[KASA] Autonomous security auditor online")

	// ── Sekhem Triad (shared) ──────────────────────────────────────────────────
	sekhemTriad, triadErr := sekhem.NewSekhemTriad(kasaEngine, dagStore, sekhem.ModeFromEnv())
	if triadErr != nil {
		logger.Printf("[SEKHEM] WARN: %v — DuatRealm only", triadErr)
	} else if sekhemTriad != nil {
		if hErr := sekhemTriad.Harmonize(); hErr != nil {
			logger.Printf("[SEKHEM] WARN: Harmonize: %v", hErr)
		} else {
			logger.Printf("[SEKHEM] Triad: %d realm(s) active", sekhemTriad.GetActiveRealmCount())
		}
	}

	// WAFShield for HTTP transport
	var wafShield *sekhem.WAFShield
	if sekhemTriad != nil && sekhemTriad.DuatRealm != nil {
		wafShield = sekhemTriad.DuatRealm.WAFShield
	}

	// ── 4-Layer Gateway ───────────────────────────────────────────────────────
	gw, gwErr := gateway.New(gateway.DefaultConfig())
	if gwErr != nil {
		logger.Printf("[GATEWAY] WARN: %v — gateway disabled", gwErr)
	} else {
		logger.Printf("[GATEWAY] 4-layer Khepra Gateway: ACTIVE")
	}

	// ── MCP Security Chain ────────────────────────────────────────────────────
	demarc := &khepramcp.AdinkraDemarcGateway{
		StdioIdentity: khepramcp.Identity{
			Subject:   "asaf-hub",
			Issuer:    "demarc",
			AgentID:   "asaf-hub-v1",
			SessionID: keyID,
			Scopes:    []string{"*"},
		},
	}
	poly := &khepramcp.AdinkraPolymorphicEngine{
		Symbol: symbol, PrivateKey: privKey, PublicKey: pubKey,
	}
	mcpGateway := khepramcp.NewDefaultMCPGateway()

	// Manifest Registry — use existing loadManifestRegistry pattern from khepra-mcp
	mcpRegistry, regErr := loadManifestRegistry(ctx, pubKey, keyID, logger)
	if regErr != nil {
		logger.Fatalf("FATAL: manifest registry failed: %v", regErr)
	}
	logger.Printf("[MANIFEST] %d tools, version=%s", mcpRegistry.ToolCount(), mcpRegistry.Version())

	// Executor + tool handlers
	sandboxBackend := khepramcp.NewDockerSandbox(khepramcp.DockerSandboxConfig{
		Image:  getEnv("PHANTOM_IMAGE", "khepra-phantom:latest"),
		Config: khepramcp.DefaultSandboxConfig(),
		Logger: logger,
	})
	executor := khepramcp.NewExecutor(khepramcp.ExecutorConfig{
		Sandbox: sandboxBackend,
		Confirm: &hubConfirmGate{logger: logger},
		Logger:  logger,
	})
	registerToolHandlers(executor)

	attestor := khepramcp.NewDAGAttestor(dagStore, symbol, privKey)

	// Signed audit log
	var signedLog *khepramcp.SignedAuditLog
	auditPath := filepath.Join(dataPath, "audit.ndjson")
	if sal, salErr := khepramcp.NewSignedAuditLog(khepramcp.SignedAuditLogConfig{
		Path: auditPath, PrivKey: privKey, PubKey: pubKey,
	}); salErr != nil {
		logger.Printf("[AUDIT] WARN: %v", salErr)
	} else {
		signedLog = sal
		logger.Printf("[AUDIT] %s", auditPath)
	}

	// Router
	invRootKey := khepramcp.DeriveRootKey(privKey)
	maxConcurrent := 5
	if mc := getEnv("KHEPRA_MAX_CONCURRENT", ""); mc != "" {
		if n, e := strconv.Atoi(mc); e == nil && n > 0 {
			maxConcurrent = n
		}
	}
	router, routerErr := khepramcp.NewRouter(khepramcp.RouterConfig{
		Demarc:            demarc,
		Poly:              poly,
		Gateway:           mcpGateway,
		Registry:          mcpRegistry,
		Executor:          executor,
		Attestor:          attestor,
		Logger:            logger,
		SignedAuditLog:    signedLog,
		InvocationRootKey: invRootKey,
		MaxConcurrent:     maxConcurrent,
		License:           licenseClaim,
	})
	if routerErr != nil {
		logger.Fatalf("FATAL: router construction failed: %v", routerErr)
	}

	dagBridge := khepramcp.NewDAGBridge(dagStore, privKey, pubKey)
	router.Events().AddHook(dagBridge.Hook)
	logger.Printf("[DAGBridge] active — key_id=%s", keyID)

	router.Events().Emit(khepramcp.MCPEvent{
		Type:    khepramcp.EventStartup,
		Success: true,
		Metadata: map[string]any{
			"version": version, "symbol": symbol, "key_id": keyID,
			"tools": mcpRegistry.ToolCount(),
		},
	})

	// ── MCP HardenedServer (PORT 8444) ────────────────────────────────────────
	mcpServer, mcpErr := khepramcp.NewHardenedServer(khepramcp.HardenedServerConfig{
		Mode:       khepramcp.TransportHTTP,
		Router:     router,
		Logger:     logger,
		Credential: nil, // per-request auth
		HTTPConfig: khepramcp.HTTPTransportConfig{
			ListenAddr:          mcpAddr,
			MaxRequestSize:      4 << 20,
			ReadTimeout:         30 * time.Second,
			WriteTimeout:        0, // SSE requires no write deadline
			AllowedOrigins:      allowedOrigins(hubPort),
			EnableSecureHeaders: true,
			WAF:                 wafShield,
			Gateway:             gw,
			DagStore:            dagStore,
			SSE: khepramcp.SSEConfig{
				MaxConns:     50,
				IdleTimeout:  60 * time.Minute,
				PingInterval: 30 * time.Second,
			},
		},
	})
	if mcpErr != nil {
		logger.Fatalf("FATAL: MCP server construction failed: %v", mcpErr)
	}

	// Run MCP server on :8444 in background
	go func() {
		logger.Printf("[MCP] Starting HTTP/SSE transport on %s", mcpAddr)
		if runErr := mcpServer.Run(ctx); runErr != nil && runErr != context.Canceled {
			logger.Printf("[MCP] ERROR: %v", runErr)
		}
		mcpServer.Shutdown(context.Background()) //nolint:errcheck
	}()

	// ── Fleet Registry ────────────────────────────────────────────────────────
	if err2 := os.MkdirAll(dataPath, 0700); err2 != nil {
		logger.Fatalf("FATAL: data path creation failed: %v", err2)
	}
	fleetRegistry, fleetErr := fleet.NewRegistry(dataPath)
	if fleetErr != nil {
		logger.Fatalf("FATAL: fleet registry init failed: %v", fleetErr)
	}
	logger.Printf("[FLEET] %d assets | %d enclaves",
		len(fleetRegistry.ListAssets("", "")),
		len(fleetRegistry.ListEnclaves()))

	// ── Fleet Scanner (BulkScanner ↔ FleetRegistry bridge) ───────────────────
	fleetScanner := scanner.NewFleetScanner(fleetRegistry, dagStore, privKey, logger)
	logger.Printf("[FLEET-SCAN] Fleet scanner initialized (concurrency=8, STIG profiles: rhel9/windows/ubuntu)")

	// ── Hub HTTP Mux (PORT 8443) ───────────────────────────────────────────────
	mux := http.NewServeMux()

	// Stargate UI
	mux.HandleFunc("/asaf-config.js", makeConfigHandler(khepraMode, orgName, frameworks, mcpPort))
	setupStargateUI(mux, logger)

	// Fleet Manager REST API
	hub.NewFleetHandlers(fleetRegistry).Register(mux)

	// Fleet Scanner (trigger + SSE progress + last results)
	hub.NewFleetScanHandlers(fleetScanner).Register(mux)

	// KASA status
	hub.NewKASAHandlers().Register(mux)

	// Imhotep remediation approval
	hub.NewImhotepHandlers().Register(mux)

	// Blackhole VPN
	hub.NewBlackholeHandlers(hubExtAddr).Register(mux)

	// Health (Hub-level — MCP has its own at :8444/health)
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok","version":%q,"mcp_port":%q}`, version, mcpPort)
	})

	// ── Middleware ────────────────────────────────────────────────────────────
	var handler http.Handler = mux
	handler = corsMiddleware(allowedOrigins(hubPort))(handler)
	handler = secureHeadersMiddleware(handler)

	// ── Hub HTTP Server (PORT 8443) ───────────────────────────────────────────
	hubSrv := &http.Server{
		Addr:        hubAddr,
		Handler:     handler,
		ReadTimeout: 30 * time.Second,
	}

	go func() {
		<-ctx.Done()
		logger.Printf("[HUB] Draining connections...")
		shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = hubSrv.Shutdown(shutCtx)
		if sekhemTriad != nil {
			sekhemTriad.Stop()
		}
		kasaEngine.Stop()
		if signedLog != nil {
			_ = signedLog.Close()
		}
		for i := range privKey {
			privKey[i] = 0
		}
		logger.Printf("[HUB] Shutdown complete — PQC key material destroyed")
	}()

	logger.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	logger.Printf("  [Stargate]  http://localhost:%s/              ← CISO UI", hubPort)
	logger.Printf("  [Fleet]     http://localhost:%s/api/v1/fleet/*", hubPort)
	logger.Printf("  [KASA]      http://localhost:%s/api/v1/kasa/*", hubPort)
	logger.Printf("  [Imhotep]   http://localhost:%s/api/v1/imhotep/*", hubPort)
	logger.Printf("  [Blackhole] http://localhost:%s/enroll        ← reporter VPN", hubPort)
	logger.Printf("  [MCP]       http://localhost:%s/mcp           ← AI agents", mcpPort)
	logger.Printf("  [SSE]       http://localhost:%s/sse", mcpPort)
	logger.Printf("  [DAG]       http://localhost:%s/api/v1/dag/history", mcpPort)
	logger.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	tlsCert := getEnv("KHEPRA_TLS_CERT", "")
	tlsKey := getEnv("KHEPRA_TLS_KEY", "")
	if tlsCert != "" && tlsKey != "" {
		logger.Printf("[HUB] HTTPS on %s", hubAddr)
		if e := hubSrv.ListenAndServeTLS(tlsCert, tlsKey); e != nil && e != http.ErrServerClosed {
			logger.Fatalf("FATAL: %v", e)
		}
	} else {
		logger.Printf("[HUB] HTTP on %s", hubAddr)
		if e := hubSrv.ListenAndServe(); e != nil && e != http.ErrServerClosed {
			logger.Fatalf("FATAL: %v", e)
		}
	}
}

// ── hubConfirmGate ────────────────────────────────────────────────────────────

// hubConfirmGate implements mcp.ConfirmationGate.
// In the Hub context, tool execution confirmations go through the Imhotep UI,
// not inline. All MCP tool calls are auto-confirmed; risky operations (sysctl,
// PAM, SELinux) must be dispatched as ChangeRequests through Imhotep.
type hubConfirmGate struct{ logger *log.Logger }

func (g *hubConfirmGate) Confirm(ctx context.Context, spec khepramcp.ToolSpec, call khepramcp.MCPToolCall) error {
	g.logger.Printf("[CONFIRM] auto-approve: %s (risk_class=%s)", spec.Name, spec.RiskClass)
	return nil
}

// ── Manifest Registry ──────────────────────────────────────────────────────────

// loadManifestRegistry loads the signed tool manifest from disk or generates a bootstrap.
// Mirrors cmd/khepra-mcp/main.go loadManifestRegistry.
func loadManifestRegistry(ctx context.Context, pubKey []byte, keyID string, logger *log.Logger) (*khepramcp.ManifestRegistry, error) {
	manifestPath := getEnv("KHEPRA_MANIFEST_PATH", "manifest.json")
	if _, err := os.Stat(manifestPath); err == nil {
		logger.Printf("[MANIFEST] loading from %s", manifestPath)
		store := &khepramcp.FileManifestStore{Path: manifestPath}
		verifier := &khepramcp.BootstrapManifestVerifier{}
		return khepramcp.LoadRegistry(ctx, store, verifier)
	}
	logger.Printf("[MANIFEST] no manifest at %s — generating bootstrap", manifestPath)
	toolSpecs := defaultToolSpecs(pubKey)
	manifest, err := khepramcp.GenerateSignedManifest(toolSpecs, pubKey, keyID)
	if err != nil {
		return nil, fmt.Errorf("manifest: generate bootstrap: %w", err)
	}
	store := &khepramcp.EmbeddedManifestStore{Manifest: manifest}
	verifier := &khepramcp.BootstrapManifestVerifier{}
	return khepramcp.LoadRegistry(ctx, store, verifier)
}

func defaultToolSpecs(pubKey []byte) []khepramcp.ToolSpec {
	hashFn := func(name string) string {
		h := sha256.Sum256([]byte(name + ":v1"))
		return hex.EncodeToString(h[:])
	}
	_ = pubKey
	noArgs := map[string]any{"type": "object", "properties": map[string]any{}}
	// Return a minimal spec set — the full list lives in cmd/khepra-mcp/main.go.
	// Tools registered via registerToolHandlers below are the operative set.
	return []khepramcp.ToolSpec{
		{Name: "ert_scan", Description: "Enterprise Risk & Threat scanner",
			RiskClass: khepramcp.RiskReadOnly, Scope: "ert:read",
			SchemaVersion: "1.0.0", SchemaHash: hashFn("ert_scan"),
			AllowedBackend: "in-process", TimeoutMs: 120000,
			MaxPrivilege: "read-only", ArgsSchema: noArgs},
		{Name: "stig_check", Description: "RHEL-09-STIG compliance check",
			RiskClass: khepramcp.RiskReadOnly, Scope: "stig:read",
			SchemaVersion: "1.0.0", SchemaHash: hashFn("stig_check"),
			AllowedBackend: "in-process", TimeoutMs: 30000,
			MaxPrivilege: "read-only", ArgsSchema: noArgs},
		{Name: "cmmc_assess", Description: "CMMC Level 2 assessment",
			RiskClass: khepramcp.RiskReadOnly, Scope: "cmmc:read",
			SchemaVersion: "1.0.0", SchemaHash: hashFn("cmmc_assess"),
			AllowedBackend: "in-process", TimeoutMs: 60000,
			MaxPrivilege: "read-only", ArgsSchema: noArgs},
	}
}

// ── registerToolHandlers ───────────────────────────────────────────────────────

// registerToolHandlers wires all in-process tool handlers into the executor.
// Mirrors cmd/khepra-mcp/main.go registerToolHandlers exactly.
func registerToolHandlers(executor *khepramcp.Executor) {
	executor.RegisterFunc("acp_status", tools.HandleACPStatus)
	executor.RegisterFunc("acp_issue", tools.HandleACPIssue)
	executor.RegisterFunc("acp_revoke", tools.HandleACPRevoke)
	executor.RegisterFunc("nhi_inventory", tools.HandleNHIInventory)
	executor.RegisterFunc("nhi_orphans", tools.HandleNHIOrphans)
	executor.RegisterFunc("nhi_excessive", tools.HandleNHIExcessive)
	executor.RegisterFunc("nhi_expired", tools.HandleNHIExpired)
	executor.RegisterFunc("nhi_revoke", tools.HandleNHIRevoke)
	executor.RegisterFunc("ert_scan", tools.HandleERTScan)
	executor.RegisterFunc("ert_readiness", tools.HandleERTReadiness)
	executor.RegisterFunc("ert_architect", tools.HandleERTArchitect)
	executor.RegisterFunc("ert_crypto", tools.HandleERTCrypto)
	executor.RegisterFunc("ert_godfather", tools.HandleERTGodfather)
	executor.RegisterFunc("dag_attestation", tools.HandleDAGAttestation)
	executor.RegisterFunc("godfather_report", tools.HandleGodfatherReport)
	executor.RegisterFunc("godfather_approve", tools.HandleGodfatherApprove)
	executor.RegisterFunc("nist_map", tools.HandleNistMapTool)
	executor.RegisterFunc("khepra_watch", tools.HandleKhepraWatchTool)
	executor.RegisterFunc("discover_assets", tools.HandleDiscoverAssets)
	executor.RegisterFunc("stig_check", tools.HandleSTIGCheck)
	executor.RegisterFunc("pqc_stig", tools.HandlePQCSTIG)
	executor.RegisterFunc("cmmc_assess", tools.HandleCMMCAssess)
	executor.RegisterFunc("agent_record", tools.HandleAgentRecord)
	executor.RegisterFunc("khepra_export_attestation", tools.HandleKhepraExportAttestation)
	executor.RegisterFunc("khepra_export_poam", tools.HandleKhepraExportPOAM)
	executor.RegisterFunc("khepra_query_stig", tools.HandleKhepraQuerySTIG)
	executor.RegisterFunc("khepra_get_compliance_score", tools.HandleKhepraGetComplianceScore)
	executor.RegisterFunc("khepra_query_threat_intel", tools.HandleKhepraQueryThreatIntel)
	executor.RegisterFunc("khepra_get_dag_chain", tools.HandleKhepraGetDAGChain)
	executor.RegisterFunc("flight_export", tools.HandleFlightExport)
	executor.RegisterFunc("owasp_agent_assess", tools.HandleOWASPAgentAssess)
	executor.RegisterFunc("agent_scan", tools.HandleAgentScan)
	executor.RegisterFunc("dark_crypto_contribute", tools.HandleDarkCryptoContribute)
	executor.RegisterFunc("sbom_generate", tools.HandleSBOMGenerate)
	executor.RegisterFunc("threat_model", tools.HandleThreatModel)
	executor.RegisterFunc("kasa_start", tools.HandleKASAStart)
	executor.RegisterFunc("kasa_status", tools.HandleKASAStatus)
	executor.RegisterFunc("kasa_task", tools.HandleKASATask)
	executor.RegisterFunc("kasa_scan", tools.HandleKASAScan)
	executor.RegisterFunc("kasa_forensics", tools.HandleKASAForensics)
	executor.RegisterFunc("kasa_crypto_agent", tools.HandleKASACryptoAgent)
	executor.RegisterFunc("ea_evolve", tools.HandleEAEvolve)
	executor.RegisterFunc("ea_threat_score", tools.HandleEAThreatScore)
	executor.RegisterFunc("ea_risk_summary", tools.HandleEARiskSummary)
	executor.RegisterFunc("quantum_optimize", tools.HandleQuantumOptimize)
	executor.RegisterFunc("threat_lookup", tools.HandleThreatLookup)
	executor.RegisterFunc("drift_detect", tools.HandleDriftDetect)
	executor.RegisterFunc("ir_incident", tools.HandleIRIncident)
	executor.RegisterFunc("ir_add_ioc", tools.HandleIRAddIOC)
	executor.RegisterFunc("flight_record", tools.HandleFlightRecord)
	executor.RegisterFunc("ouroboros_waf_eye", tools.HandleOuroborosWAFEye)
	executor.RegisterFunc("ouroboros_stig_eye", tools.HandleOuroborosSTIGEye)
	executor.RegisterFunc("ouroboros_vuln_eye", tools.HandleOuroborosVulnEye)
	executor.RegisterFunc("ouroboros_fim_eye", tools.HandleOuroborosFIMEye)
	executor.RegisterFunc("forensic_snapshot", tools.HandleForensicsCollect)
	executor.RegisterFunc("fim_baseline", tools.HandleFIMBaseline)
	executor.RegisterFunc("audit_dag_integrity", tools.HandleAuditExport)
	executor.RegisterFunc("enumerate_host", tools.HandleEnumerateHost)
	executor.RegisterFunc("fingerprint_device", tools.HandleFingerprintDevice)
	executor.RegisterFunc("port_scan", tools.HandlePortScan)
	executor.RegisterFunc("vuln_scan", tools.HandleVulnScan)
	executor.RegisterFunc("secret_scan", tools.HandleSecretScan)
	executor.RegisterFunc("container_scan", tools.HandleContainerScan)
	executor.RegisterFunc("compliance_scan", tools.HandleComplianceScan)
	executor.RegisterFunc("packet_analyze", tools.HandlePacketAnalyze)
	executor.RegisterFunc("attack_graph", tools.HandleAttackGraph)
	executor.RegisterFunc("pqc_sign", tools.HandlePQCSign)
	executor.RegisterFunc("pqc_verify", tools.HandlePQCVerify)
	executor.RegisterFunc("pqc_keygen", tools.HandlePQCKeygen)
	executor.RegisterFunc("dag_write", tools.HandleDAGWrite)
	executor.RegisterFunc("dag_query", tools.HandleDAGQuery)
	executor.RegisterFunc("dag_audit", tools.HandleDAGAudit)
	executor.RegisterFunc("phantom_stealth", tools.HandlePhantomStealth)
	executor.RegisterFunc("identity_shroud", tools.HandleIdentityShroud)
	executor.RegisterFunc("identity_epiphany", tools.HandleIdentityEpiphany)
	executor.RegisterFunc("drbc_backup", tools.HandleDRBCBackup)
	executor.RegisterFunc("drbc_restore", tools.HandleDRBCRestore)
}

// ── Stargate UI ───────────────────────────────────────────────────────────────

func setupStargateUI(mux *http.ServeMux, logger *log.Logger) {
	distPath := "dist"
	if _, err := os.Stat(distPath); err == nil {
		fsys := os.DirFS(distPath)
		fileServer := http.FileServer(http.FS(fsys))
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if isBackendRoute(r.URL.Path) {
				http.NotFound(w, r)
				return
			}
			if r.URL.Path == "/" || r.URL.Path == "" {
				http.ServeFileFS(w, r, fsys, "index.html")
				return
			}
			if _, err2 := fs.Stat(fsys, strings.TrimPrefix(r.URL.Path, "/")); err2 != nil {
				http.ServeFileFS(w, r, fsys, "index.html")
				return
			}
			fileServer.ServeHTTP(w, r)
		})
		logger.Printf("[STARGATE] UI: serving from dist/")
	} else {
		mux.HandleFunc("/", devPlaceholder)
		logger.Printf("[STARGATE] UI: dev placeholder (run `make build-hub`)")
	}
}

func isBackendRoute(path string) bool {
	for _, p := range []string{
		"/api/", "/health", "/enroll", "/heartbeat", "/dispatch", "/asaf-config.js",
	} {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

func devPlaceholder(w http.ResponseWriter, r *http.Request) {
	if isBackendRoute(r.URL.Path) {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, devHTML)
}

const devHTML = `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>ASAF Stargate</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{background:#0a0f1e;color:#e2e8f0;font-family:-apple-system,sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;flex-direction:column;gap:2rem}h1{font-size:2rem;color:#4EAEF5}p{color:#94a3b8;text-align:center;max-width:480px;line-height:1.6}.cmd{background:#1e293b;border:1px solid #334155;border-radius:8px;padding:1rem 1.5rem;font-family:monospace;color:#4EAEF5}.badge{border:1px solid #4EAEF5;color:#4EAEF5;padding:.25rem .75rem;border-radius:999px;font-size:.75rem}.routes{background:#1e293b;border:1px solid #334155;border-radius:8px;padding:1rem 1.5rem;font-size:.8rem;color:#94a3b8;text-align:left}.routes span{color:#4EAEF5}</style>
</head><body>
<div class="badge">USPTO #73565085 — KHEPRA PROTOCOL</div>
<h1>ASAF Stargate Hub is running</h1>
<p>The Stargate UI is not yet built. Run this to embed it:</p>
<div class="cmd">make build-hub</div>
<div class="routes">
<span>Hub :8443</span><br>
Fleet API → /api/v1/fleet/*<br>
KASA → /api/v1/kasa/*<br>
Imhotep → /api/v1/imhotep/*<br>
Blackhole → /enroll • /heartbeat<br>
<br>
<span>MCP :8444</span><br>
AI Agents → /mcp<br>
SSE → /sse<br>
DAG → /api/v1/dag/history<br>
NLChat → /api/v1/mcp/ask
</div>
<p style="font-size:.75rem;color:#475569">SecRed Knowledge Inc. • SDVOSB • Army Signal Corps 25S<br>Zero egress. Air-gappable. Patent pending.</p>
</body></html>`

// ── asaf-config.js injection ──────────────────────────────────────────────────

func makeConfigHandler(mode, orgName, frameworks, mcpPort string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		productName := getEnv("KHEPRA_PRODUCT_NAME", "ASAF Stargate")
		logoURL := getEnv("KHEPRA_LOGO_URL", "")
		fwCtx := map[string]string{
			"sovereign": "CMMC Level 2, NIST 800-171, RHEL-09-STIG, DISA, DoD supply chain",
			"ironbank":  "CMMC Level 3, DISA Iron Bank, STIG, ATO, DoD production",
			"hybrid":    "SOC 2 Type II, ISO 27001, NIST CSF, CMMC",
			"edge":      "OWASP ASVS, ISO 27001, general security, AI agent safety",
		}[mode]
		if fwCtx == "" {
			fwCtx = "CMMC Level 2, NIST 800-171, STIG"
		}
		w.Header().Set("Content-Type", "application/javascript")
		w.Header().Set("Cache-Control", "no-cache")
		mcpBaseURL := fmt.Sprintf("http://localhost:%s", mcpPort)
		fmt.Fprintf(w, `window.ASAF_CONFIG={apiURL:"",mcpBaseURL:%q,khepraMode:%q,frameworks:%q,frameworkContext:%q,orgName:%q,productName:%q,logoURL:%q,version:%q,os:%q,fleetAPI:"/api/v1/fleet",kasaAPI:"/api/v1/kasa",imhotepAPI:"/api/v1/imhotep",mcpAskURL:%q,dagHistoryURL:%q,sseURL:%q};`,
			mcpBaseURL, mode, frameworks, fwCtx, orgName, productName, logoURL, version, runtime.GOOS,
			mcpBaseURL+"/api/v1/mcp/ask",
			mcpBaseURL+"/api/v1/dag/history",
			mcpBaseURL+"/sse")
	}
}

// ── Middleware ────────────────────────────────────────────────────────────────

func corsMiddleware(origins []string) func(http.Handler) http.Handler {
	set := make(map[string]bool)
	for _, o := range origins {
		set[o] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if o := r.Header.Get("Origin"); o != "" && set[o] {
				w.Header().Set("Access-Control-Allow-Origin", o)
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Session-Id")
				w.Header().Set("Access-Control-Max-Age", "86400")
			}
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func secureHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		next.ServeHTTP(w, r)
	})
}

func allowedOrigins(hubPort string) []string {
	base := []string{
		"https://adinkhepra.com", "https://www.adinkhepra.com",
		"https://souhimbou.ai", "https://www.souhimbou.ai",
		"http://localhost:3000",
		fmt.Sprintf("http://localhost:%s", hubPort),
		fmt.Sprintf("http://127.0.0.1:%s", hubPort),
	}
	if extra := getEnv("KHEPRA_CORS_ORIGINS", ""); extra != "" {
		for _, o := range strings.Split(extra, ",") {
			if o = strings.TrimSpace(o); o != "" {
				base = append(base, o)
			}
		}
	}
	return base
}

// ── Utilities ─────────────────────────────────────────────────────────────────

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func dataDir() string {
	if h := os.Getenv("HOME"); h != "" {
		return filepath.Join(h, ".khepra", "hub")
	}
	if up := os.Getenv("USERPROFILE"); up != "" {
		return filepath.Join(up, ".khepra", "hub")
	}
	return filepath.Join(".", ".khepra", "hub")
}
