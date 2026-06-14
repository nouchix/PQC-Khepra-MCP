//go:build saas

package apiserver

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/acme/autocert"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/adinkra"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/asaf"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/auth"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/license"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/mcp"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/sekhem"
)

// Server represents the SEKHEM gateway — the divine boundary between clients and the inner realms.
type Server struct {
	router      *gin.Engine
	wsHub       *WebSocketHub
	dagStore    DAGStore
	licMgr      LicenseManager
	config      *Config
	startTime   time.Time
	version     string
	httpServer  *http.Server
	agentMgr    AgentManagerInterface
	mcpStore    MCPStore              // Supabase MCP persistence layer (optional)
	nlProcessor *mcp.NLProcessor      // Natural language → tool chain processor (optional)
	pqcGateway  *auth.PQCAuthGateway  // PQC-SAML-OAuth2 auth gateway (optional)
	sigPrivKey  []byte                // ML-DSA-65 Dilithium3 signing key (server identity)
	sigPubKey   []byte                // ML-DSA-65 Dilithium3 verification key (server identity)
	sekhemTriad *sekhem.SekhemTriad   // Ouroboros cycle, WAF realm, sensor/actuator mesh (optional)
	recorder    *asaf.Recorder        // ASAF flight recorder — nil until WithASAFRecorder is called
	autopilot   *AutopilotEngine      // Continuous compliance scheduler (Autopilot tier)
}

const (
	errWsupgrade = "WebSocket upgrade error: %v"
)

// AgentManagerInterface abstracts the connection to remote environments
type AgentManagerInterface interface {
	ExecuteOnAgent(machineID string, command string, args []string) (string, error)
}

// Config holds server configuration
type Config struct {
	Host           string
	Port           int
	TLSEnabled     bool
	TLSDomain      string   // For Let's Encrypt
	CertCacheDir   string   // For Let's Encrypt cert cache
	AllowedOrigins []string // CORS origins
	Debug          bool
}

// DAGStore interface for DAG operations
type DAGStore interface {
	NodeCount() int
	All() []DAGNodeResponse
	Add(nodeID string, action string, parents []string, pqc map[string]string) error
}

// LicenseManager interface for license operations
type LicenseManager interface {
	IsValid() (bool, error)
	ValidateAPIKey(apiKey string) (bool, error)
	GetStatus() LicenseStatus

	// Egyptian Tier management
	CreateLicense(id string, tier license.EgyptianTier, days int) (*license.License, error)
	GetLicense(id string) (*license.License, error)
	GetAllLicenses() []*license.License
	UpgradeLicense(id string, newTier license.EgyptianTier) error

	// Telemetry & Enrollment
	Register(token string) (*license.RegisterResponse, error)
	Heartbeat() (*license.HeartbeatResponse, error)
	GetFullStatus() *license.ValidateResponse
	GetMachineID() string

	// Revocation (called by internal webhook service on subscription cancellation)
	RevokeLicense(stripeEventID, reason string) error
}

// NewServer creates a new API server instance
func NewServer(config *Config, dagStore DAGStore, licMgr LicenseManager) *Server {
	if !config.Debug {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.New()
	wsHub := NewWebSocketHub()

	server := &Server{
		router:    router,
		wsHub:     wsHub,
		dagStore:  dagStore,
		licMgr:    licMgr,
		config:    config,
		startTime: time.Now(),
		version:   "1.0.0",
		agentMgr:  nil, // To be injected if Gateway is present
	}

	// Generate persistent ML-DSA-65 signing identity for this server instance
	pub, priv, err := adinkra.GenerateDilithiumKey()
	if err != nil {
		log.Printf("[SERVER] Warning: PQC key generation failed: %v", err)
	} else {
		server.sigPrivKey = priv
		server.sigPubKey = pub
		// Share with standalone HTTP handlers in command_center.go
		SetPackageSigningKeys(priv, pub)
	}

	// NOTE: setupMiddleware() and setupRoutes() are intentionally NOT called here.
	// They are called from Start() after all optional dependencies (SekhemTriad,
	// PQCAuthGateway, MCPStore, NLProcessor) have been injected via With* methods.
	return server
}

// setupMiddleware configures all middleware in the correct SEKHEM order:
//
//  1. RecoveryMiddleware  — catches panics from any middleware below it, including WAF
//  2. LoggingMiddleware   — logs all requests (including blocked ones, before WAF fires)
//  3. CORSMiddleware      — CORS headers applied first; OPTIONS preflights must get
//     Access-Control-* headers BEFORE the WAF can reject them
//  4. WAFMiddleware       — Merkaba L7 perimeter: SQLi/XSS/path traversal/rate-limit
//  5. AuthMiddleware      — only for authenticated route groups (applied per-group below)
//
// RateLimitMiddleware is removed: its function is now handled by SEKHEM-007
// inside WAFShield (per-IP sync.Map rate limiter, same 100 req/min threshold).
func (s *Server) setupMiddleware() {
	s.router.Use(RecoveryMiddleware())
	s.router.Use(LoggingMiddleware())
	s.router.Use(CORSMiddleware(s.config.AllowedOrigins...))

	// WAF — nil-safe: if sekhemTriad is not yet wired (e.g. test mode),
	// WAFMiddleware logs a warning and is a no-op.
	var wafShield *sekhem.WAFShield
	if s.sekhemTriad != nil && s.sekhemTriad.DuatRealm != nil {
		wafShield = s.sekhemTriad.DuatRealm.WAFShield
	}
	s.router.Use(WAFMiddleware(wafShield))
}

// setupRoutes configures all API routes
func (s *Server) setupRoutes() {
	// Public routes (no auth required)
	s.router.GET("/health", s.handleHealth)
	s.router.GET("/healthz", s.handleHealth) // alias — frontend probes /healthz
	s.router.GET("/version", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"version": s.version,
			"service": "sekhem-gateway",
		})
	})

	// Public attestation verification (no auth — C3PAOs verify independently)
	s.registerPublicVerificationRoute()

	// Public auth bootstrap endpoints (no auth required — they create credentials)
	pubV1 := s.router.Group("/api/v1")
	s.setupAuthRoutes(pubV1)

	// Public onboarding scan funnel — no auth required for eval/basic scans.
	// Gated server-side by ASAF_ALLOW_EVAL_WITHOUT_LICENSE env var.
	// Uses /onboarding/ prefix to avoid Gin route collision with authenticated /scans/*.
	pubV1.POST("/onboarding/scan", s.handleTriggerScan)
	pubV1.GET("/onboarding/scan/:id", s.handleGetScanStatus)

	// NL security query — public so the AI assistant is accessible without auth.
	// BYOK path uses the caller's own OpenRouter key; keyword-router path exposes
	// no sensitive data. Authenticated routes (tools, audit, sessions) stay on v1.
	pubV1.POST("/mcp/ask", s.handleMCPNaturalLanguageQuery)

	// Stripe webhook — public, no API-key auth. Security is HMAC via STRIPE_WEBHOOK_SECRET.
	pubV1.POST("/stripe/webhook", s.handleStripeWebhook)

	// Internal license revocation — called by the webhook service on subscription cancellation.
	// No Bearer auth (webhook has no credentials); protected by localhost-only guard in handler.
	pubV1.POST("/license/revoke", s.handleRevokeLicense)

	// API v1 routes — PQC auth when gateway is wired, legacy API key otherwise
	v1 := s.router.Group("/api/v1")
	if s.pqcGateway != nil {
		v1.Use(s.PQCGinMiddleware())
	} else {
		v1.Use(s.AuthMiddleware())
	}
	{
		// Scan endpoints
		scans := v1.Group("/scans")
		{
			scans.POST("/trigger", s.handleTriggerScan)
			scans.GET("/:id", s.handleGetScanStatus)
			scans.GET("", s.handleListScans)
		}

		// DAG endpoints
		dag := v1.Group("/dag")
		{
			dag.GET("/nodes", s.handleGetDAGNodes)
			dag.GET("/nodes/:id", func(c *gin.Context) {
				c.JSON(http.StatusNotImplemented, gin.H{"error": "not implemented"})
			})
		}

		// STIG endpoints
		stig := v1.Group("/stig")
		{
			stig.POST("/validate", s.handleSTIGValidation)
			stig.POST("/remediate", s.handleSTIGRemediation)
		}

		// CMMC endpoints — protected by Mitochondrial API Gateway (WAF + PQC Auth)
		compliance := v1.Group("/compliance")
		{
			compliance.GET("/cmmc-audit", s.handleCMMCAudit)
			compliance.GET("/cmmc-scorecard", s.handleCMMCScorecard)
			compliance.GET("/mapping-chain", s.handleCMMCMappingChain)
		}

		// Command Center endpoints (4-Quadrant "Compliance in 4 Clicks")
		cc := v1.Group("/cc")
		{
			// Dashboard
			cc.GET("/dashboard", s.handleCCDashboard)

			// Quadrant 1: Discover
			cc.POST("/discover", s.handleCCDiscover)
			cc.GET("/discover/endpoints", s.handleCCListEndpoints)

			// Quadrant 2: Assess
			cc.POST("/assess", s.handleCCAssess)
			cc.GET("/assess/status", s.handleCCAssessStatus)

			// Quadrant 3: Rollback
			cc.POST("/rollback/snapshot", s.handleCCCreateSnapshot)
			cc.GET("/rollback/snapshots", s.handleCCListSnapshots)
			cc.POST("/rollback/restore", s.handleCCRollback)

			// Quadrant 4: Prove
			cc.POST("/prove/attest", s.handleCCCreateAttestation)
			cc.GET("/prove/verify", s.handleCCVerifyAttestation)
			cc.POST("/prove/export", s.handleCCExportEvidence)
		}

		// Autopilot — Continuous Compliance Engine (Autopilot tier)
		ap := v1.Group("/autopilot")
		{
			ap.POST("/start", s.handleAutopilotStart)
			ap.POST("/stop", s.handleAutopilotStop)
			ap.POST("/pause", s.handleAutopilotPause)
			ap.POST("/resume", s.handleAutopilotResume)
			ap.GET("/status", s.handleAutopilotStatus)
			ap.GET("/events", s.handleAutopilotEvents)
		}

		// Organization & Seat Management
		org := v1.Group("/org")
		{
			org.POST("/create", s.handleCreateOrganization)
			org.GET("/:org_id", s.handleGetOrganization)
			org.GET("/:org_id/seats", s.handleListSeats)
			org.POST("/:org_id/seats/invite", s.handleInviteSeat)
			org.DELETE("/:org_id/seats/:seat_id", s.handleRevokeSeat)
			org.POST("/:org_id/upgrade", s.handleUpgradeTier)
		}

		// Billing & Stripe
		billing := v1.Group("/billing")
		{
			billing.POST("/checkout", s.handleCreateCheckout)
			billing.POST("/simulate-complete", s.handleSimulateComplete)
			billing.POST("/webhook", s.handleStripeWebhook)
			billing.GET("/subscription", s.handleGetSubscriptionStatus)
		}

		// ERT (Evidence Recording Token) endpoints
		ert := v1.Group("/ert")
		{
			ert.POST("/generate", s.handleGenerateERT)
			ert.GET("/verify/:id", func(c *gin.Context) {
				c.JSON(http.StatusNotImplemented, gin.H{"error": "not implemented"})
			})
		}

		// License endpoints (Merkaba Egyptian mythology licensing system)
		license := v1.Group("/license")
		{
			// Basic license management
			license.GET("/status", s.handleGetLicenseStatus)
			license.POST("/create", s.handleCreateLicense)
			license.GET("/:license_id", s.handleGetLicense)
			license.POST("/:license_id/upgrade", s.handleUpgradeLicense)
			license.GET("/:license_id/usage", s.handleGetLicenseUsage)

			// Admin/list endpoints
			license.GET("/admin/list", s.handleListLicenses)

			// Telemetry integration with Cloudflare server
			telemetry := license.Group("/telemetry")
			{
				telemetry.POST("/enroll", s.handleTelemetryEnroll)
				telemetry.POST("/heartbeat", s.handleTelemetryHeartbeat)
				telemetry.GET("/status", s.handleTelemetryStatus)
			}
		}

		// Telemetry analytics (read-only, requires user auth)
		v1.GET("/telemetry/stats", s.handleTelemetryStats)
		v1.GET("/telemetry/dark-crypto-moat", s.handleDarkCryptoMoat)
		v1.GET("/metrics/system", s.handleSystemMetrics)

		// MCP (Model Context Protocol) endpoints — Supabase bridge + AI tool integration
		s.setupMCPRoutes(v1)
	}

	// Service-to-service API (authenticated with service tokens)
	// OWASP API2:2023 - Strong service authentication
	svc := s.router.Group("/api/v1/telemetry")
	svc.Use(ServiceAuthMiddleware())
	svc.Use(RequirePermission("telemetry:write"))
	{
		svc.POST("/ingest", s.handleTelemetryIngest)
	}

	// ASAF recording routes — nil-safe, no-op when WithASAFRecorder not called
	s.setupASAFRoutes(pubV1, v1)

	// WebSocket endpoints (auth via query param or first message)
	var upgrader = websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin: func(r *http.Request) bool {
			origin := r.Header.Get("Origin")
			if origin == "" {
				return true // Allow requests with no origin (e.g. CLI)
			}
			for _, allowed := range s.config.AllowedOrigins {
				if origin == allowed {
					return true
				}
			}
			return false
		},
	}

	s.router.GET("/ws/scans", func(c *gin.Context) {
		conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
		if err != nil {
			log.Printf(errWsupgrade, err)
			return
		}
		s.wsHub.ServeWebSocket(conn, "scans")
	})

	s.router.GET("/ws/dag", func(c *gin.Context) {
		conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
		if err != nil {
			log.Printf(errWsupgrade, err)
			return
		}
		s.wsHub.ServeWebSocket(conn, "dag")
	})

	s.router.GET("/ws/license", func(c *gin.Context) {
		conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
		if err != nil {
			log.Printf(errWsupgrade, err)
			return
		}
		s.wsHub.ServeWebSocket(conn, "license")
	})
}

// Start starts the API server.
// All With* dependency injections must be called before Start().
// setupMiddleware and setupRoutes run here so the WAFShield (from SekhemTriad)
// is available when middleware is configured.
func (s *Server) Start() error {
	// Setup middleware and routes now — all dependencies are injected
	s.setupMiddleware()
	s.setupRoutes()

	// Start WebSocket hub in background
	go s.wsHub.Run()

	addr := fmt.Sprintf("%s:%d", s.config.Host, s.config.Port)
	log.Printf("[SEKHEM] Starting SEKHEM Gateway on %s", addr)
	log.Printf("TLS Enabled: %v", s.config.TLSEnabled)
	log.Printf("Version: %s", s.version)

	s.httpServer = &http.Server{
		Addr:         addr,
		Handler:      s.router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	if s.config.TLSEnabled {
		return s.startTLS()
	}

	return s.httpServer.ListenAndServe()
}

// startTLS starts the server with TLS using Let's Encrypt
func (s *Server) startTLS() error {
	if s.config.TLSDomain == "" {
		return fmt.Errorf("TLS domain not configured")
	}

	log.Printf("Starting with Let's Encrypt TLS for domain: %s", s.config.TLSDomain)

	certManager := autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(s.config.TLSDomain),
		Cache:      autocert.DirCache(s.config.CertCacheDir),
	}

	s.httpServer.TLSConfig = &tls.Config{
		GetCertificate: certManager.GetCertificate,
		MinVersion:     tls.VersionTLS12,
	}

	// Start HTTP->HTTPS redirect server
	go func() {
		httpServer := &http.Server{
			Addr:    ":80",
			Handler: certManager.HTTPHandler(nil),
		}
		log.Printf("Starting HTTP->HTTPS redirect server on :80")
		if err := httpServer.ListenAndServe(); err != nil {
			log.Printf("HTTP redirect server error: %v", err)
		}
	}()

	return s.httpServer.ListenAndServeTLS("", "")
}

// WithSekhemTriad injects the SekhemTriad (Ouroboros + WAF realm) into the gateway.
// Must be called before Start(). The triad's lifecycle (Harmonize/Stop) is managed
// by the caller in main.go alongside the server lifecycle.
func (s *Server) WithSekhemTriad(triad *sekhem.SekhemTriad) {
	s.sekhemTriad = triad
}

// WithASAFRecorder injects the ASAF flight recorder into the gateway.
// Must be called before Start(). When set, four routes are registered:
//
//	GET  /api/v1/asaf/stream   — public SSE live feed for dashboards
//	POST /api/v1/asaf/record   — service-auth (asaf:write) for the MCP bridge
//	GET  /api/v1/asaf/sessions — authenticated session list
//	GET  /api/v1/asaf/history  — authenticated action history
func (s *Server) WithASAFRecorder(r *asaf.Recorder) {
	s.recorder = r
}

// setupASAFRoutes registers all ASAF recording endpoints.
// It is a no-op when no recorder has been injected (WithASAFRecorder not called).
// Extracted from setupRoutes to keep cognitive complexity within bounds.
func (s *Server) setupASAFRoutes(pubV1, v1 *gin.RouterGroup) {
	if s.recorder == nil {
		return
	}

	// Public SSE live feed — dashboard clients subscribe here (read-only, no auth required)
	pubV1.GET("/asaf/stream", gin.WrapF(s.recorder.HandleSSE))

	// Authenticated query endpoints — require the same auth as the rest of v1
	asafGroup := v1.Group("/asaf")
	asafGroup.GET("/sessions", gin.WrapF(s.recorder.HandleSessions))
	asafGroup.GET("/history", gin.WrapF(s.recorder.HandleHistory))

	// Service-auth record endpoint — MCP bridge posts one entry per intercepted tool call
	asafSvc := s.router.Group("/api/v1/asaf")
	asafSvc.Use(ServiceAuthMiddleware())
	asafSvc.Use(RequirePermission("asaf:write"))
	asafSvc.POST("/record", gin.WrapF(s.recorder.HandleRecord))
}

// Shutdown gracefully shuts down the server
func (s *Server) Shutdown(ctx context.Context) error {
	log.Println("[SEKHEM] Shutting down SEKHEM Gateway...")

	if s.httpServer != nil {
		if err := s.httpServer.Shutdown(ctx); err != nil {
			return fmt.Errorf("server shutdown error: %w", err)
		}
	}

	log.Println("[SEKHEM] Gateway shutdown complete")
	return nil
}

// GetWebSocketHub returns the WebSocket hub for external use
func (s *Server) GetWebSocketHub() *WebSocketHub {
	return s.wsHub
}

// GetRouter returns the Gin router for testing
func (s *Server) GetRouter() *gin.Engine {
	return s.router
}

// checkOrganizationAccess verifies if the provided API key has access to the organization.
// This implements granular RBAC by validating organization-level permissions.
func (s *Server) checkOrganizationAccess(apiKey string, requestedOrgID string) (bool, error) {
	if requestedOrgID == "" {
		return true, nil // No organization specified, allow (legacy/global behavior)
	}

	if s.licMgr == nil {
		return true, nil // No license manager, allow for local development
	}

	status := s.licMgr.GetFullStatus()
	if status == nil {
		return false, fmt.Errorf("could not retrieve license status")
	}

	// TRL10 PRODUCTION RBAC:
	// Verify that the license is bound to the requested organization
	if status.Organization != requestedOrgID && status.Organization != "GLOBAL_ADMIN" {
		log.Printf("[RBAC] Access denied: API key %s (Org: %s) attempted to access Org: %s",
			apiKey, status.Organization, requestedOrgID)
		return false, nil
	}

	return true, nil
}
