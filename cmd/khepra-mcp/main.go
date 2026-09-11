package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/nouchix/PQC-Khepra-MCP/pkg/adinkra"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/attestenvelope"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/license"
	khepramcp "github.com/nouchix/PQC-Khepra-MCP/pkg/mcp"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/mcp/kernelports"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/mcp/tools"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/mcp/upstream"
)

// ─── Upstream broker (Mitochondrial egress) ───────────────────────────────────
//
// KHEPRA_UPSTREAM_MCP="uptimerobot=https://mcp.uptimerobot.com/mcp,github=https://…"
// Each upstream's tools are re-exposed as <alias>__<tool> and run through the
// full Router chain. Egress is refused under KHEPRA_MODE=sovereign|ironbank
// unless KHEPRA_UPSTREAM_ALLOW_SOVEREIGN=1, because those profiles publicly
// promise zero egress.

type upstreamEntry struct{ alias, url string }

func parseUpstreams(spec string) ([]upstreamEntry, error) {
	var out []upstreamEntry
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		alias, u, ok := strings.Cut(part, "=")
		if !ok {
			return nil, fmt.Errorf("KHEPRA_UPSTREAM_MCP entry %q must be alias=url", part)
		}
		out = append(out, upstreamEntry{alias: strings.TrimSpace(alias), url: strings.TrimSpace(u)})
	}
	return out, nil
}

// egressPermitted is the profile gate. Sovereign/Iron Bank builds ship with a
// documented zero-egress posture (see owasp_agent_assess + TRUST_CENTER.md);
// brokering an external MCP server there must be an explicit operator act.
func egressPermitted() (bool, string) {
	mode := strings.ToLower(os.Getenv("KHEPRA_MODE"))
	if mode == "sovereign" || mode == "ironbank" {
		if os.Getenv("KHEPRA_UPSTREAM_ALLOW_SOVEREIGN") == "1" {
			return true, "KHEPRA_MODE=" + mode + " with explicit KHEPRA_UPSTREAM_ALLOW_SOVEREIGN=1 override"
		}
		return false, "KHEPRA_MODE=" + mode + " forbids egress (set KHEPRA_UPSTREAM_ALLOW_SOVEREIGN=1 to override — this changes the deployment's attested posture)"
	}
	return true, "KHEPRA_MODE=" + firstNonEmpty(mode, "default")
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func newBroker(e upstreamEntry, store *upstream.Store, interactive bool, logger *log.Logger) (*upstream.Broker, error) {
	return upstream.New(upstream.Config{
		URL:         e.url,
		Alias:       e.alias,
		Store:       store,
		Interactive: interactive,
		OAuth: upstream.OAuthConfig{
			ClientName:  "KHEPRA MCP Broker",
			OpenBrowser: interactive,
			Scope:       os.Getenv("KHEPRA_UPSTREAM_SCOPE"),
		},
		Logger: logger,
	})
}

// wireUpstreams connects every configured upstream and registers its tools.
// A failing upstream is logged and skipped; native tools keep serving.
func wireUpstreams(ctx context.Context, registry *khepramcp.ManifestRegistry, executor *khepramcp.Executor, logger *log.Logger) {
	spec := os.Getenv("KHEPRA_UPSTREAM_MCP")
	if spec == "" {
		return
	}
	ok, why := egressPermitted()
	if !ok {
		logger.Printf("[UPSTREAM] DISABLED — %s", why)
		return
	}
	entries, err := parseUpstreams(spec)
	if err != nil {
		logger.Printf("[UPSTREAM] config error: %v", err)
		return
	}
	store, err := upstream.OpenStore(upstream.DefaultDir())
	if err != nil {
		logger.Printf("[UPSTREAM] sealed store unavailable: %v", err)
		return
	}
	interactive := os.Getenv("KHEPRA_UPSTREAM_INTERACTIVE") == "1"
	logger.Printf("[UPSTREAM] egress permitted (%s); %d upstream(s); sealed store %s", why, len(entries), store.Dir())
	for _, e := range entries {
		b, err := newBroker(e, store, interactive, logger)
		if err != nil {
			logger.Printf("[UPSTREAM:%s] %v", e.alias, err)
			continue
		}
		if err := b.Connect(ctx); err != nil {
			logger.Printf("[UPSTREAM:%s] connect failed: %v", e.alias, err)
			continue
		}
		if err := registry.RegisterBrokered(b.Specs()); err != nil {
			logger.Printf("[UPSTREAM:%s] registry refused: %v", e.alias, err)
			continue
		}
		b.RegisterHandlers(executor)
		for _, s := range b.Specs() {
			logger.Printf("[UPSTREAM:%s]   %-48s %s", e.alias, s.Name, s.RiskClass)
		}
	}
}

// runLogin performs the one-time interactive consent for an upstream and
// exits. Meant to be run from a terminal, not by an MCP client.
func runLogin(ctx context.Context, alias, url string, logger *log.Logger) {
	if alias == "" {
		alias = "upstream"
	}
	store, err := upstream.OpenStore(upstream.DefaultDir())
	if err != nil {
		logger.Fatalf("sealed store: %v", err)
	}
	b, err := newBroker(upstreamEntry{alias: alias, url: url}, store, true, logger)
	if err != nil {
		logger.Fatalf("%v", err)
	}
	if err := b.Login(ctx); err != nil {
		logger.Fatalf("login failed: %v", err)
	}
	// Prove it end-to-end: connect, pin, and print the tool table.
	if err := b.Connect(ctx); err != nil {
		logger.Fatalf("authorized, but tool discovery failed: %v", err)
	}
	fmt.Printf("\nAuthorized %s → %s\nSealed under %s\n\n%-48s %s\n", alias, url, store.Dir(), "TOOL", "RISK")
	for _, s := range b.Specs() {
		fmt.Printf("%-48s %s\n", s.Name, s.RiskClass)
	}
	if len(b.Refused) > 0 {
		fmt.Printf("\nREFUSED (pin mismatch): %s\n", strings.Join(b.Refused, ", "))
	}
	fmt.Printf("\nNow set: KHEPRA_UPSTREAM_MCP=%s=%s\n", alias, url)
}

type stdioConfirmGate struct{ logger *log.Logger }

func (g *stdioConfirmGate) Confirm(ctx context.Context, spec khepramcp.ToolSpec, call khepramcp.MCPToolCall) error {
	g.logger.Printf("[CONFIRM] auto-approve: %s (risk_class=%s)", spec.Name, spec.RiskClass)
	return nil
}

func defaultToolSpecs(pubKey []byte) []khepramcp.ToolSpec {
	hashFn := func(name string) string {
		h := sha256.Sum256([]byte(name + ":v1"))
		return hex.EncodeToString(h[:])
	}
	_ = pubKey
	noArgs := map[string]any{"type": "object", "properties": map[string]any{}}
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
		{Name: "nist_map", Description: "NIST SP 800-53 Rev 5 control mapper",
			RiskClass: khepramcp.RiskReadOnly, Scope: "compliance:read",
			SchemaVersion: "1.0.0", SchemaHash: hashFn("nist_map"),
			AllowedBackend: "in-process", TimeoutMs: 5000,
			MaxPrivilege: "read-only", ArgsSchema: noArgs},
		{Name: "godfather_report", Description: "Godfather AI governance report generator",
			RiskClass: khepramcp.RiskReadOnly, Scope: "compliance:report",
			SchemaVersion: "1.0.0", SchemaHash: hashFn("godfather_report"),
			AllowedBackend: "in-process", TimeoutMs: 30000,
			MaxPrivilege: "read-only", ArgsSchema: noArgs},
		{Name: "godfather_approve", Description: "Godfather HITL approval validator",
			RiskClass: khepramcp.RiskReadOnly, Scope: "compliance:report",
			SchemaVersion: "1.0.0", SchemaHash: hashFn("godfather_approve"),
			AllowedBackend: "in-process", TimeoutMs: 5000,
			MaxPrivilege: "read-only", ArgsSchema: noArgs},
		{Name: "khepra_watch", Description: "Filesystem integrity monitor",
			RiskClass: khepramcp.RiskReadOnly, Scope: "compliance:monitor",
			SchemaVersion: "1.0.0", SchemaHash: hashFn("khepra_watch"),
			AllowedBackend: "in-process", TimeoutMs: 10000,
			MaxPrivilege: "read-only", ArgsSchema: noArgs},
		{Name: "acp_status", Description: "Agent Capability Policy status",
			RiskClass: khepramcp.RiskReadOnly, Scope: "acp:read",
			SchemaVersion: "1.0.0", SchemaHash: hashFn("acp_status"),
			AllowedBackend: "in-process", TimeoutMs: 5000,
			MaxPrivilege: "read-only", ArgsSchema: noArgs},
		{Name: "acp_issue", Description: "Issue Agent Capability Policy token",
			RiskClass: khepramcp.RiskDestructive, Scope: "acp:write",
			SchemaVersion: "1.0.0", SchemaHash: hashFn("acp_issue"),
			AllowedBackend: "in-process", TimeoutMs: 10000,
			MaxPrivilege: "admin", ArgsSchema: noArgs},
		{Name: "acp_revoke", Description: "Revoke Agent Capability Policy token",
			RiskClass: khepramcp.RiskDestructive, Scope: "acp:write",
			SchemaVersion: "1.0.0", SchemaHash: hashFn("acp_revoke"),
			AllowedBackend: "in-process", TimeoutMs: 10000,
			MaxPrivilege: "admin", ArgsSchema: noArgs},
		{Name: "nhi_inventory", Description: "Non-Human Identity inventory",
			RiskClass: khepramcp.RiskReadOnly, Scope: "nhi:read",
			SchemaVersion: "1.0.0", SchemaHash: hashFn("nhi_inventory"),
			AllowedBackend: "in-process", TimeoutMs: 5000,
			MaxPrivilege: "read-only", ArgsSchema: noArgs},
		{Name: "nhi_orphans", Description: "List orphaned Non-Human Identities",
			RiskClass: khepramcp.RiskReadOnly, Scope: "nhi:read",
			SchemaVersion: "1.0.0", SchemaHash: hashFn("nhi_orphans"),
			AllowedBackend: "in-process", TimeoutMs: 5000,
			MaxPrivilege: "read-only", ArgsSchema: noArgs},
		{Name: "nhi_excessive", Description: "List excessive permission NHIs",
			RiskClass: khepramcp.RiskReadOnly, Scope: "nhi:read",
			SchemaVersion: "1.0.0", SchemaHash: hashFn("nhi_excessive"),
			AllowedBackend: "in-process", TimeoutMs: 5000,
			MaxPrivilege: "read-only", ArgsSchema: noArgs},
		{Name: "nhi_expired", Description: "List expired Non-Human Identities",
			RiskClass: khepramcp.RiskReadOnly, Scope: "nhi:read",
			SchemaVersion: "1.0.0", SchemaHash: hashFn("nhi_expired"),
			AllowedBackend: "in-process", TimeoutMs: 5000,
			MaxPrivilege: "read-only", ArgsSchema: noArgs},
		{Name: "nhi_revoke", Description: "Revoke Non-Human Identity credentials",
			RiskClass: khepramcp.RiskDestructive, Scope: "nhi:write",
			SchemaVersion: "1.0.0", SchemaHash: hashFn("nhi_revoke"),
			AllowedBackend: "in-process", TimeoutMs: 10000,
			MaxPrivilege: "admin", ArgsSchema: noArgs},
	}
}

func loadManifestRegistry(ctx context.Context, privKey []byte, keyID string, logger *log.Logger) (*khepramcp.ManifestRegistry, error) {
	manifestPath := os.Getenv("KHEPRA_MANIFEST_PATH")
	if manifestPath == "" {
		manifestPath = "manifest.json"
	}
	if _, err := os.Stat(manifestPath); err == nil {
		logger.Printf("[MANIFEST] loading from %s", manifestPath)
		store := &khepramcp.FileManifestStore{Path: manifestPath}
		verifier := &khepramcp.BootstrapManifestVerifier{}
		return khepramcp.LoadRegistry(ctx, store, verifier)
	}
	logger.Printf("[MANIFEST] generating bootstrap manifest (%s)", manifestPath)
	toolSpecs := defaultToolSpecs(privKey)
	manifest, err := khepramcp.GenerateSignedManifest(toolSpecs, privKey, keyID, &kernelports.NoopSigner{})
	if err != nil {
		return nil, fmt.Errorf("manifest: generate bootstrap: %w", err)
	}
	store := &khepramcp.EmbeddedManifestStore{Manifest: manifest}
	verifier := &khepramcp.BootstrapManifestVerifier{}
	return khepramcp.LoadRegistry(ctx, store, verifier)
}

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
	executor.RegisterFunc("attest_export", tools.HandleAttestExport)
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
}

func main() {
	logger := log.New(os.Stderr, "[khepra-mcp] ", log.LstdFlags|log.Lmicroseconds)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	loginURL := flag.String("login", "", "authorize an upstream MCP server (OAuth 2.1 + PKCE) and exit")
	loginAlias := flag.String("alias", "", "tool namespace for -login (default: upstream)")
	logoutURL := flag.String("logout", "", "forget sealed credentials and pins for an upstream and exit")
	flag.Parse()
	if *loginURL != "" {
		runLogin(ctx, *loginAlias, *loginURL, logger)
		return
	}
	if *logoutURL != "" {
		store, err := upstream.OpenStore(upstream.DefaultDir())
		if err != nil {
			logger.Fatalf("sealed store: %v", err)
		}
		if err := store.Forget(*logoutURL); err != nil {
			logger.Fatalf("logout: %v", err)
		}
		logger.Printf("forgot %s", *logoutURL)
		return
	}

	logger.Printf("━━━ KHEPRA MCP OSS KERNEL ━━━")
	symbol := os.Getenv("KHEPRA_SYMBOL")
	if symbol == "" {
		symbol = "Eban"
	}

	pubKey, privKey, err := adinkra.GenerateDilithiumKey()
	if err != nil {
		logger.Fatalf("FATAL: PQC key generation failed: %v", err)
	}
	keyHash := sha256.Sum256(pubKey)
	keyID := hex.EncodeToString(keyHash[:8])
	logger.Printf("[PQC] ML-DSA-65 | symbol=%s | key_id=%s", symbol, keyID)

	licenseClaim, licErr := license.ParseMCPLicense()
	if errors.Is(licErr, license.ErrNoLicenseKey) {
		logger.Printf("[LICENSE] Community tier — set KHEPRA_LICENSE_KEY for Enterprise")
	} else if licErr != nil {
		logger.Printf("[LICENSE] WARN: license parse (%v) — falling back to Community", licErr)
	} else {
		logger.Printf("[LICENSE] %s | tenant=%q | expires=%s",
			licenseClaim.Tier, licenseClaim.Tenant,
			licenseClaim.ExpiresAt.Format("2006-01-02"))
	}

	demarc := &khepramcp.DefaultDemarcGateway{
		StdioIdentity: khepramcp.Identity{
			Subject:   "khepra-mcp-stdio",
			Issuer:    "demarc",
			AgentID:   "local-agent",
			SessionID: keyID,
			Scopes:    []string{"*"},
		},
	}

	// Signer was never set here (since f86e1df6), so WrapRequest nil-panicked
	// on every tool call — native or brokered. Wire the real ML-DSA signer
	// against the key generated above rather than kernelports' NoopSigner.
	poly := &khepramcp.DefaultPolymorphicEngine{
		Symbol:     symbol,
		PrivateKey: privKey,
		PublicKey:  pubKey,
		Signer:     attestenvelope.AdinkraSigner{},
	}

	mcpGateway := khepramcp.NewDefaultMCPGateway()

	mcpRegistry, regErr := loadManifestRegistry(ctx, privKey, keyID, logger)
	if regErr != nil {
		logger.Fatalf("FATAL: manifest registry failed: %v", regErr)
	}
	logger.Printf("[MANIFEST] %d tools registered, version=%s", mcpRegistry.ToolCount(), mcpRegistry.Version())

	executor := khepramcp.NewExecutor(khepramcp.ExecutorConfig{
		Confirm: &stdioConfirmGate{logger: logger},
		Logger:  logger,
	})
	registerToolHandlers(executor)
	wireUpstreams(ctx, mcpRegistry, executor, logger)
	logger.Printf("[MANIFEST] %d tools after upstream brokering", mcpRegistry.ToolCount())

	attestor := kernelports.Defaults().Attestor
	invRootKey := khepramcp.DeriveRootKey(privKey)

	router, err := khepramcp.NewRouter(khepramcp.RouterConfig{
		Demarc:            demarc,
		Poly:              poly,
		Gateway:           mcpGateway,
		Registry:          mcpRegistry,
		Executor:          executor,
		Attestor:          attestor,
		Logger:            logger,
		InvocationRootKey: invRootKey,
		MaxConcurrent:     10,
		License:           licenseClaim,
	})
	if err != nil {
		logger.Fatalf("Router error: %v", err)
	}

	srv, err := khepramcp.NewHardenedServer(khepramcp.HardenedServerConfig{
		Mode:   khepramcp.TransportStdio,
		Router: router,
		Logger: logger,
	})
	if err != nil {
		logger.Fatalf("Server error: %v", err)
	}

	logger.Printf("KHEPRA MCP Server listening on stdio...")
	if err := srv.Run(ctx); err != nil && err != context.Canceled {
		logger.Fatalf("Serve error: %v", err)
	}
}
