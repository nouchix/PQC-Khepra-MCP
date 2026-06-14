//go:build saas

// SEKHEM Gateway - Khepra Protocol Secure Gateway
// "SEKHEM — The Divine Gateway"
// Sekhem (Egyptian): Power, might, divine authority — the scepter that commands
// the boundary between chaos and order.
//
// The central consciousness hub connecting:
// - Go AGI (KASA)          - Logic & Execution
// - Python AGI (SouHimBou) - Intuition & Soul
// - Telemetry Server       - Long-Term Memory
// - Client API             - User Interface
//
// Environment Variables:
//   KHEPRA_SERVICE_SECRET     - Shared HMAC secret for service authentication (required)
//   PORT                      - Server port (default: 443 for TLS, 8080 without)
//   HOST                      - Server host (default: 0.0.0.0)
//   TLS_ENABLED               - Disable TLS for local dev: TLS_ENABLED=false (default: true)
//   TLS_DOMAIN                - Domain for Let's Encrypt (required when TLS enabled)
//   CERT_CACHE_DIR             - Directory for certificate cache
//   DEBUG                     - Enable debug mode (default: false)
//   TELEMETRY_URL             - Telemetry server URL (default: https://telemetry.souhimbou.org)
//
//   ASAF_ALLOW_EVAL_WITHOUT_LICENSE - If "true", allow scan_type eval/basic when license invalid (public funnel; set on Fly with care)
//
//   PQC Auth (ML-DSA-65 / NIST FIPS 204):
//   SUPABASE_JWT_SECRET       - Supabase project JWT secret (enables Supabase Auth login)
//
//   Supabase MCP persistence:
//   SUPABASE_URL              - Supabase project URL (e.g. https://xxx.supabase.co)
//   SUPABASE_SERVICE_ROLE_KEY - Supabase service role key (bypasses RLS)
//
//   Natural Language Security Engine:
//   LLM_PROVIDER              - LLM backend: "ollama" (default) | "none"
//   LLM_URL                   - Ollama base URL (default: http://localhost:11434)
//   LLM_MODEL                 - Ollama model (default: auto-discovered via /api/tags)
//   LLM_API_KEY               - Optional bearer key for hosted Ollama

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/apiserver"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/asaf"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/auth"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/dag"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/license"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/llm/ollama"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/mcp"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/sekhem"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/supabase"
)

func main() {
	cfg, flags := parseConfig()

	printBanner()

	dagStore, licMgr := initInfrastructure(cfg)

	// ── SEKHEM Triad (Ouroboros + WAFShield + Sensor/Actuator mesh) ───────────
	// Must be created and harmonized BEFORE server.Start() so that WAFShield
	// exists when setupMiddleware() wires it into the Gin handler chain.
	triad := initSekhemTriad(dagStore)

	// Create server — dependencies injected before Start()
	server := initServices(cfg, flags, dagStore, licMgr)
	server.WithSekhemTriad(triad)

	// ── ASAF Flight Recorder (security camera + DAG-backed audit trail) ─────
	initASAFRecorder(server)

	// ── PQC Auth Gateway (ML-DSA-65 / NIST FIPS 204) ─────────────────────────
	initPQCAuthGateway(server)

	// ── Supabase MCP Persistence Layer ───────────────────────────────────────
	initSupabaseMCPStore(server)

	// ── Natural Language Security Engine ─────────────────────────────────────
	initNLProcessor(server)

	// Start server in background (setupMiddleware runs here with WAFShield ready)
	go func() {
		if err := server.Start(); err != nil {
			log.Fatalf("Server error: %v", err)
		}
	}()

	// Log service status
	log.Println("╔═══════════════════════════════════════════════════════════════════╗")
	log.Println("║                    SEKHEM Gateway Active                          ║")
	log.Println("╚═══════════════════════════════════════════════════════════════════╝")
	log.Printf("  Address:           %s:%d", cfg.host, cfg.port)
	log.Printf("  TLS:               %v", cfg.tlsEnabled)
	log.Printf("  Service Auth:      %s", getSecretStatus())
	log.Printf("  Telemetry Server:  %s", cfg.telemetryURL)
	log.Println("")
	log.Println("  Auth Endpoints (public — no auth required):")
	log.Println("    POST /api/v1/auth/token            - Exchange Supabase JWT → PQC token")
	log.Println("    POST /api/v1/auth/saml/callback    - SAML 2.0 / Claude Enterprise WorkOS")
	log.Println("    GET  /api/v1/auth/introspect       - RFC 7662 token introspection")
	log.Println("    GET  /api/v1/auth/keys/public      - ML-DSA-65 public key")
	log.Println("")
	log.Println("  REST Endpoints (authenticated):")
	log.Println("    GET  /health                      - Health check")
	log.Println("    GET  /version                     - Version info")
	log.Println("    POST /api/v1/mcp/ask              - NL security query (ChatGPT moment)")
	log.Println("    GET  /api/v1/mcp/dashboard        - Security risk dashboard")
	log.Println("    GET  /api/v1/mcp/alerts           - Active IDS/IPS alerts")
	log.Println("    GET  /api/v1/mcp/timeline         - Security event timeline")
	log.Println("    POST /api/v1/telemetry/ingest     - Telemetry ingestion (service auth)")
	log.Println("    GET  /api/v1/telemetry/stats      - Telemetry statistics")
	log.Println("    POST /api/v1/scans/trigger        - Trigger crypto scan")
	log.Println("    GET  /api/v1/license/status       - License status")
	log.Println("")
	log.Println("  WebSocket Endpoints:")
	log.Println("    WS   /ws/scans                    - Real-time scan updates")
	log.Println("    WS   /ws/dag                      - DAG state changes")
	log.Println("    WS   /ws/license                  - License events")
	log.Println("")
	log.Println("  SEKHEM is online. The Gateway stands.")

	// Graceful shutdown on interrupt
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit

	log.Println("")
	log.Println("Received shutdown signal...")

	// Shutdown with 30-second timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Printf("Server forced to shutdown: %v", err)
	}

	// Stop license heartbeat
	licMgr.Stop()

	// Stop SEKHEM Triad (Ouroboros cycle + WAFShield rotation + file handles)
	if triad != nil {
		triad.Stop()
	}

	log.Println("SEKHEM gateway exited gracefully. The scepter rests.")
}

type serverConfig struct {
	port         int
	host         string
	tlsEnabled   bool
	tlsDomain    string
	certCacheDir string
	debug        bool
	telemetryURL string
}

func parseConfig() (*serverConfig, map[string]interface{}) {
	port := flag.Int("port", 443, "Server port (default 443 for TLS)")
	host := flag.String("host", "0.0.0.0", "Server host")
	tlsEnabled := flag.Bool("tls", true, "Enable TLS with Let's Encrypt (default: true)")
	tlsDomain := flag.String("tls-domain", "", "Domain for Let's Encrypt (required when TLS enabled)")
	certCacheDir := flag.String("cert-cache", "/var/cache/khepra-certs", "Certificate cache directory")
	debug := flag.Bool("debug", false, "Enable debug mode")
	telemetryURL := flag.String("telemetry-url", "https://telemetry.souhimbou.org", "Telemetry server URL")
	flag.Parse()

	// Environment variable overrides
	if envPort := os.Getenv("PORT"); envPort != "" {
		if p, err := strconv.Atoi(envPort); err == nil {
			*port = p
		}
	}
	if envHost := os.Getenv("HOST"); envHost != "" {
		*host = envHost
	}
	if os.Getenv("TLS_ENABLED") == "false" {
		*tlsEnabled = false
		if *port == 443 {
			*port = 8080
		}
	}
	if envDomain := os.Getenv("TLS_DOMAIN"); envDomain != "" {
		*tlsDomain = envDomain
	}
	if envCertDir := os.Getenv("CERT_CACHE_DIR"); envCertDir != "" {
		*certCacheDir = envCertDir
	}
	if os.Getenv("DEBUG") == "true" {
		*debug = true
	}
	if envTelemetry := os.Getenv("TELEMETRY_URL"); envTelemetry != "" {
		*telemetryURL = envTelemetry
	}

	// Warn if TLS is enabled but domain is not configured
	if *tlsEnabled && *tlsDomain == "" {
		log.Println("WARNING: TLS_DOMAIN not set. Falling back to HTTP on port 8080.")
		*tlsEnabled = false
		*port = 8080
	}

	// Validate service secret
	if os.Getenv("KHEPRA_SERVICE_SECRET") == "" {
		log.Println("WARNING: KHEPRA_SERVICE_SECRET not set!")
	}

	cfg := &serverConfig{
		port:         *port,
		host:         *host,
		tlsEnabled:   *tlsEnabled,
		tlsDomain:    *tlsDomain,
		certCacheDir: *certCacheDir,
		debug:        *debug,
		telemetryURL: *telemetryURL,
	}

	return cfg, map[string]interface{}{
		"host":         host,
		"port":         port,
		"tlsEnabled":   tlsEnabled,
		"tlsDomain":    tlsDomain,
		"certCacheDir": certCacheDir,
		"telemetryURL": telemetryURL,
	}
}

// initSekhemTriad creates the SekhemTriad in Edge mode and harmonizes all realms.
// Harmonize() calls DuatRealm.Awaken() which initializes WAFShield, WAFEye,
// and starts the Ouroboros cycle. Must complete before server.Start() so the
// WAFShield is available when setupMiddleware() wires it into Gin.
func initSekhemTriad(dagStore dag.Store) *sekhem.SekhemTriad {
	triad, err := sekhem.NewSekhemTriad(nil, dagStore, sekhem.ModeEdge)
	if err != nil {
		log.Fatalf("SEKHEM Triad init failed: %v", err)
	}
	if err := triad.Harmonize(); err != nil {
		// WAFShield failure is fatal — we never run without the perimeter guard.
		log.Fatalf("SEKHEM Triad harmonize failed: %v", err)
	}
	log.Printf("[SEKHEM] Triad harmonized — mode=%s realms=%d", triad.GetMode(), triad.GetActiveRealmCount())
	return triad
}

func initInfrastructure(cfg *serverConfig) (dag.Store, *license.Manager) {
	// Initialize DAG
	dagStore := dag.GlobalDAG()
	log.Printf("DAG initialized with %d nodes", len(dagStore.All()))

	// Initialize license manager
	licMgr, err := license.NewManager(cfg.telemetryURL)
	if err != nil {
		log.Fatalf("Failed to create license manager: %v", err)
	}

	if err := licMgr.Initialize(); err != nil {
		log.Printf("License validation failed: %v", err)
	} else {
		log.Println("License validated - full features enabled")
	}

	return dagStore, licMgr
}

func initServices(cfg *serverConfig, flags map[string]interface{}, dagStore dag.Store, licMgr *license.Manager) *apiserver.Server {
	config := &apiserver.Config{
		Host:         cfg.host,
		Port:         cfg.port,
		TLSEnabled:   cfg.tlsEnabled,
		TLSDomain:    cfg.tlsDomain,
		CertCacheDir: cfg.certCacheDir,
		AllowedOrigins: []string{
			// NouchiX / ASAF production origins
			"https://docs.nouchix.com",        // ASAF NLP UI — served here, fetches localhost agent
			"https://nouchix.com",
			"https://www.nouchix.com",
			"https://adinkhepra.com",
			"https://www.adinkhepra.com",
			"https://adinkhepra.dev",
			"https://souhimbou.org",
			"https://www.souhimbou.org",
			"https://gateway.souhimbou.org",
			"https://telemetry.souhimbou.org",
			// Local development
			"http://localhost:3000",
			"http://localhost:5173",
			"http://localhost:7777", // serve-nlp default
			"http://localhost:8080",
		},
		Debug: cfg.debug,
	}

	dagAdapter := apiserver.NewDAGStoreAdapter(dagStore)
	licAdapter := apiserver.NewLicenseManagerAdapter(licMgr)

	apiserver.LoadDefaultServiceAccounts()

	return apiserver.NewServer(config, dagAdapter, licAdapter)
}

func initASAFRecorder(server *apiserver.Server) {
	wrapper := asaf.NewASAFWrapper(dag.GlobalDAG(), nil)
	recorder := asaf.NewRecorder(wrapper)
	server.WithASAFRecorder(recorder)
	log.Println("ASAF flight recorder: active")
	log.Println("  GET  /api/v1/asaf/stream   — SSE live feed (public)")
	log.Println("  POST /api/v1/asaf/record   — MCP bridge ingestion (service-auth)")
	log.Println("  GET  /api/v1/asaf/sessions — active session list (authenticated)")
	log.Println("  GET  /api/v1/asaf/history  — action history by session (authenticated)")
}

func initPQCAuthGateway(server *apiserver.Server) {
	pqcGateway, pqcErr := auth.NewPQCAuthGateway(nil, nil, auth.PQCAuthGatewayConfig{
		Symbol:   "Eban",
		Issuer:   "khepra-pqc-gateway",
		TokenTTL: time.Hour,
	})
	if pqcErr != nil {
		log.Printf("WARNING: PQC auth gateway initialization failed: %v", pqcErr)
		log.Println("  Falling back to legacy API key authentication")
	} else {
		server.WithPQCAuthGateway(pqcGateway)
		log.Println("PQC auth gateway: ML-DSA-65 (NIST FIPS 204) — active")
		log.Println("  Supported: Supabase JWT, SAML 2.0 (WorkOS/Claude Enterprise), PQC tokens")
		if os.Getenv("SUPABASE_JWT_SECRET") == "" {
			log.Println("  NOTE: SUPABASE_JWT_SECRET not set — Supabase Auth login disabled")
		}
	}
}

func initSupabaseMCPStore(server *apiserver.Server) {
	supabaseURL := os.Getenv("SUPABASE_URL")
	supabaseKey := os.Getenv("SUPABASE_SERVICE_ROLE_KEY")
	if supabaseURL != "" && supabaseKey != "" {
		sbClient := supabase.NewClient(supabase.Config{
			ProjectURL:     supabaseURL,
			ServiceRoleKey: supabaseKey,
		})
		mcpStore := supabase.NewMCPStore(sbClient)
		server.WithMCPStore(mcpStore)
		log.Printf("Supabase MCP store: connected (%s)", supabaseURL)
	} else {
		log.Println("Supabase MCP store: disabled (set SUPABASE_URL + SUPABASE_SERVICE_ROLE_KEY)")
	}
}

func initNLProcessor(server *apiserver.Server) {
	llmProvider := os.Getenv("LLM_PROVIDER")
	if llmProvider == "" {
		llmProvider = "ollama"
	}
	if llmProvider != "none" {
		llmURL := os.Getenv("LLM_URL")
		if llmURL == "" {
			llmURL = "http://localhost:11434"
		}
		llmModel := os.Getenv("LLM_MODEL")
		if llmModel == "" {
			// Auto-discover: probes /api/tags and selects gemma3:4b > phi4:latest > ...
			llmModel = ollama.DiscoverModel(llmURL)
		}
		llmAPIKey := os.Getenv("LLM_API_KEY")

		ollamaClient := ollama.NewClient(llmURL, llmModel, llmAPIKey)
		executor := apiserver.NewServerToolExecutor(server)
		nlProc := mcp.NewNLProcessor(ollamaClient, executor)
		server.WithNLProcessor(nlProc)

		llmStatus := "offline (keyword routing active)"
		if ollamaClient.CheckHealth() {
			llmStatus = "online — full NL synthesis enabled"
		}
		log.Printf("NL security engine: provider=%s model=%s url=%s [%s]",
			llmProvider, llmModel, llmURL, llmStatus)
	} else {
		log.Println("NL security engine: disabled (LLM_PROVIDER=none) — keyword routing active")
	}
}

func getSecretStatus() string {
	if os.Getenv("KHEPRA_SERVICE_SECRET") != "" {
		return "configured (HMAC-SHA256)"
	}
	return "NOT SET (using development default)"
}

func printBanner() {
	banner := `
╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║   ███████╗███████╗██╗  ██╗██╗  ██╗███████╗███╗   ███╗            ║
║   ██╔════╝██╔════╝██║ ██╔╝██║  ██║██╔════╝████╗ ████║            ║
║   ███████╗█████╗  █████╔╝ ███████║█████╗  ██╔████╔██║            ║
║   ╚════██║██╔══╝  ██╔═██╗ ██╔══██║██╔══╝  ██║╚██╔╝██║            ║
║   ███████║███████╗██║  ██╗██║  ██║███████╗██║ ╚═╝ ██║            ║
║   ╚══════╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝            ║
║                                                                   ║
║          "The Divine Gateway — Power Commands the Boundary"       ║
║                                                                   ║
║   L7 WAF | PQC Auth | Telemetry | WebSocket | Ouroboros Cycle     ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
`
	fmt.Println(banner)
}
