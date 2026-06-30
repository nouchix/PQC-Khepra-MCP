// Package souhimbou — agent_scanner.go
//
// The Omnipotent AI Agent Security Scanner.
//
// WHAT IT DOES:
//
//	Takes any AI agent target (MCP server, OpenAI endpoint, LangServe API,
//	generic HTTP agent) and runs the full KHEPRA security stack against it —
//	combining existing codebase scanning capabilities with AI-specific probes.
//
// SCANNING LAYERS (in order — all results absorbed by Flight Fabric):
//
//	Layer 1 — Network Surface (pkg/scanner/network)
//	  TCP port sweep → open ports, banners, service fingerprints
//	  TLS/PKI inspection → cert validity, weak ciphers, expiry
//	  DNS enumeration → A/AAAA/CNAME/NS/MX/SPF/DMARC (via pkg/ert/lane_dns_pki)
//
//	Layer 2 — Service Discovery
//	  HTTP discovery: probe /, /health, /metrics, /api, /openapi.json
//	  MCP discovery: probe /mcp, list_tools JSON-RPC
//	  Agent fingerprinting: identify framework (LangChain/OpenAI/Ollama/custom)
//
//	Layer 3 — Horus Static Analysis (pkg/scanners)
//	  Secret scan: entropy-based credential detection in responses
//	  Vuln scan: manifest/dependency CVEs if repo path given
//	  Compliance: CMMC/NIST control gap detection
//
//	Layer 4 — Adversarial AI Probes (probe_suite.go)
//	  Category A — Injection (SQLi/XSS/SSTI/shell through tool params)
//	  Category B — Exfiltration (prompt injection, context extraction)
//	  Category C — Permission abuse (rapid fire, scope escalation, path traversal)
//	  Category D — Identity/Auth (forged headers, replay, PQC signature test)
//	  Category E — Availability (oversized payload, depth bomb, unicode attack)
//
//	Layer 5 — KASA Behavioral Analysis
//	  Score response patterns against all probes
//	  Detect: anomalous response timing, error pattern leakage, reflection
//
//	Layer 6 — Report Generation (report.go)
//	  Signed ScanReport: ML-DSA-65 over findings hash
//	  CMMC/NIST control mapping per finding
//	  Risk score: 0.0–10.0 (CVSS-compatible scale)
//	  DAG attestation: immutable evidence node
//
// IP assignment: SOUHIMBOU DOH KONE LLC. Licensed to SecRed Knowledge Inc.
package souhimbou

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/nouchix/PQC-Khepra-MCP/pkg/config"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/dag"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/ert"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/flight"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/scanner/network"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/scanners"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/sonar"
)

// ─── Agent Target ─────────────────────────────────────────────────────────────

// AgentType classifies what kind of AI agent is being scanned.
type AgentType string

const (
	AgentTypeMCP       AgentType = "mcp"       // MCP JSON-RPC server
	AgentTypeOpenAI    AgentType = "openai"    // OpenAI-compatible API
	AgentTypeLangServe AgentType = "langserve" // LangChain LangServe /invoke
	AgentTypeOllama    AgentType = "ollama"    // Ollama /api/generate
	AgentTypeHTTP      AgentType = "http"      // Generic HTTP agent
	AgentTypeUnknown   AgentType = "unknown"   // Auto-detect
)

// AgentTarget defines what to scan.
type AgentTarget struct {
	// URL is the base endpoint of the agent (required).
	// Examples: "http://localhost:3000", "https://api.example.com/agent"
	URL string `json:"url"`

	// Type is the agent protocol. Leave empty for auto-detect.
	Type AgentType `json:"type,omitempty"`

	// APIKey is used for authenticated scans (never stored).
	// Only used in-memory for the duration of the scan.
	APIKey string `json:"-"`

	// RepoPath is an optional local filesystem path to the agent's source.
	// If provided, Horus static analysis runs against it.
	RepoPath string `json:"repo_path,omitempty"`

	// ScanCategories limits which probe categories run (nil = all A-E).
	ScanCategories []ProbeCategory `json:"scan_categories,omitempty"`

	// Tier gates which categories are permitted.
	// "free" → A+B only; "pro" → A+B+C+D; "enterprise" → all
	Tier string `json:"tier,omitempty"`

	// MaxDuration caps the total scan time (default: 5 minutes).
	MaxDuration time.Duration `json:"max_duration_sec,omitempty"`
}

func (t *AgentTarget) defaults() {
	if t.Type == "" {
		t.Type = AgentTypeUnknown
	}
	if t.Tier == "" {
		t.Tier = "free"
	}
	if t.MaxDuration == 0 {
		t.MaxDuration = 5 * time.Minute
	}
	if len(t.ScanCategories) == 0 {
		t.ScanCategories = allowedCategories(t.Tier)
	}
}

func allowedCategories(tier string) []ProbeCategory {
	switch tier {
	case "enterprise":
		return []ProbeCategory{ProbeCatInjection, ProbeCatExfil, ProbeCatPermission, ProbeCatAuth, ProbeCatAvailability}
	case "pro":
		return []ProbeCategory{ProbeCatInjection, ProbeCatExfil, ProbeCatPermission, ProbeCatAuth}
	default: // free
		return []ProbeCategory{ProbeCatInjection, ProbeCatExfil}
	}
}

// ─── Scan Report ──────────────────────────────────────────────────────────────

// RiskLevel classifies the overall agent risk posture.
type RiskLevel string

const (
	RiskLevelCritical RiskLevel = "CRITICAL" // Score 9.0–10.0
	RiskLevelHigh     RiskLevel = "HIGH"     // 7.0–8.9
	RiskLevelMedium   RiskLevel = "MEDIUM"   // 4.0–6.9
	RiskLevelLow      RiskLevel = "LOW"      // 1.0–3.9
	RiskLevelNone     RiskLevel = "NONE"     // 0.0
)

// ScanFinding is a single security finding from any scan layer.
type ScanFinding struct {
	// Identity
	ID       string `json:"id"`
	Layer    string `json:"layer"`    // "network" | "service" | "horus" | "probe" | "kasa"
	Category string `json:"category"` // ProbeCategory or Horus category

	// Classification
	Severity    string  `json:"severity"`   // CRITICAL / HIGH / MEDIUM / LOW / INFO
	RiskScore   float64 `json:"risk_score"` // 0.0–10.0 (CVSS-compatible)
	Title       string  `json:"title"`
	Description string  `json:"description"`

	// Evidence
	Probe      string         `json:"probe,omitempty"`       // Probe name that triggered this
	RawPayload string         `json:"raw_payload,omitempty"` // Sanitized payload used
	Response   string         `json:"response,omitempty"`    // First 256 bytes of response
	Evidence   map[string]any `json:"evidence,omitempty"`

	// Remediation
	Remediation  string   `json:"remediation,omitempty"`
	CMCCControls []string `json:"cmmc_controls,omitempty"` // e.g. ["AC.L2-3.1.2", "AU.3.045"]
	NISTControls []string `json:"nist_controls,omitempty"` // e.g. ["AC-2", "AU-12"]

	// Audit
	FrameID string `json:"frame_id,omitempty"` // Flight Recorder frame
}

// AgentScanReport is the complete, signed output of an agent security scan.
type AgentScanReport struct {
	// Identity
	ReportID  string    `json:"report_id"`
	ScanID    string    `json:"scan_id"`
	Target    string    `json:"target"`
	AgentType AgentType `json:"agent_type"`
	Tier      string    `json:"tier"`

	// Timing
	StartedAt   time.Time `json:"started_at"`
	CompletedAt time.Time `json:"completed_at"`
	DurationMs  int64     `json:"duration_ms"`

	// Discovery
	OpenPorts    []PortInfo  `json:"open_ports,omitempty"`
	TLSInfo      *TLSInfo    `json:"tls_info,omitempty"`
	AgentTools   []AgentTool `json:"agent_tools,omitempty"`
	DetectedType AgentType   `json:"detected_type"`

	// Risk
	RiskScore float64   `json:"risk_score"` // 0.0–10.0
	RiskLevel RiskLevel `json:"risk_level"`
	KASAScore float64   `json:"kasa_score"` // KASA behavioral anomaly

	// Findings
	Findings []ScanFinding `json:"findings"`
	Stats    ScanStats     `json:"stats"`

	// Audit Chain
	DAGNodeID string `json:"dag_node_id"`
	Signed    bool   `json:"signed"`
	Signature string `json:"signature,omitempty"` // ML-DSA-65 over report hash

	// Summary
	Summary string   `json:"summary"`
	Errors  []string `json:"errors,omitempty"`
}

// ScanStats is a summary count of findings by severity.
type ScanStats struct {
	Total    int `json:"total"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

// PortInfo describes an open port discovered during network scanning.
type PortInfo struct {
	Port    int    `json:"port"`
	Service string `json:"service"`
	Banner  string `json:"banner,omitempty"`
	State   string `json:"state"`
}

// TLSInfo describes TLS/certificate properties of the agent endpoint.
type TLSInfo struct {
	Enabled       bool      `json:"enabled"`
	Version       string    `json:"version"`
	Cipher        string    `json:"cipher"`
	Subject       string    `json:"subject"`
	Issuer        string    `json:"issuer"`
	ExpiresAt     time.Time `json:"expires_at"`
	DaysRemaining int       `json:"days_remaining"`
	SelfSigned    bool      `json:"self_signed"`
	WeakCipher    bool      `json:"weak_cipher"`
}

// AgentTool describes a tool exposed by the agent (discovered via MCP/OpenAPI).
type AgentTool struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	RiskClass   string `json:"risk_class"` // "read_only" | "sandboxed" | "destructive"
}

// ─── Agent Scanner ────────────────────────────────────────────────────────────

// AgentScanner orchestrates the full omnipotent security scan of an AI agent.
// All results are absorbed by the Flight Fabric into the signed chain.
type AgentScanner struct {
	fabric    *flight.Fabric
	dagStore  dag.Store
	log       *slog.Logger

	// sonarOrch is the unified Sonar scanner — the backbone layer.
	// Runs port scan, web crawler, Horus vuln/secrets/compliance/container in parallel.
	sonarOrch *sonar.UnifiedOrchestrator

	// ertOrch runs the ERT multi-lane scan (DNS/PKI, SCA, SAST)
	ertOrch *ert.ScanOrchestrator
}

// NewAgentScanner creates a scanner that uses the Fabric as its evidence chain.
func NewAgentScanner(fabric *flight.Fabric, dagStore dag.Store) *AgentScanner {
	// ── Sonar Unified Orchestrator (the backbone) ────────────────────────────
	// Runs port scan + crawler + Horus vuln/secrets/compliance/container — all
	// in parallel with built-in DAG attestation.
	sonarOrch := sonar.NewUnifiedOrchestrator(nil, dagStore, nil)

	// ── ERT ScanOrchestrator (DNS/PKI lane + SCA) ────────────────────────────
	orch := ert.NewScanOrchestrator()
	orch.RegisterLane(ert.NewSonarLane(ert.SonarLaneConfig{
		NetworkPolicy:  config.NetworkPolicyUnrestricted,
		MaxConcurrency: 100,
		ScanTimeout:    3 * time.Second,
	}))
	orch.RegisterLane(ert.NewDNSPKILane(ert.DNSPKILaneConfig{
		NetworkPolicy: config.NetworkPolicyUnrestricted,
		TLSPorts:      []int{443, 80, 8080, 8443, 3000, 5000, 9000},
		ScanTimeout:   8 * time.Second,
	}))
	orch.RegisterLane(ert.NewHorusVulnLane())
	orch.RegisterLane(ert.NewHorusSecretLane())

	return &AgentScanner{
		fabric:    fabric,
		dagStore:  dagStore,
		log:       slog.With("component", "agent-scanner"),
		sonarOrch: sonarOrch,
		ertOrch:   orch,
	}
}

// Scan runs the full omnipotent security scan against an AI agent target.
// Everything is absorbed by the Flight Fabric into the signed chain.
func (s *AgentScanner) Scan(ctx context.Context, target AgentTarget) (*AgentScanReport, error) {
	target.defaults()

	ctx, cancel := context.WithTimeout(ctx, target.MaxDuration)
	defer cancel()

	start := time.Now()
	scanID := fmt.Sprintf("scan-%d", start.UnixNano())
	reportID := fmt.Sprintf("rpt-%d", start.UnixNano())

	s.log.Info("Agent scan started",
		"scan_id", scanID, "target", target.URL, "tier", target.Tier)

	report := &AgentScanReport{
		ReportID:  reportID,
		ScanID:    scanID,
		Target:    target.URL,
		AgentType: target.Type,
		Tier:      target.Tier,
		StartedAt: start,
	}

	// Absorb scan start into Fabric
	s.fabric.Absorb(ctx, flight.Event{
		Source:   "AgentScanner",
		Name:     "SCAN_START",
		Category: flight.CategoryScan,
		Detail: map[string]any{
			"scan_id": scanID, "target": target.URL, "tier": target.Tier,
		},
	})

	var mu sync.Mutex
	var findings []ScanFinding
	var errs []string

	addFinding := func(f ScanFinding) {
		mu.Lock()
		findings = append(findings, f)
		mu.Unlock()
	}
	addErr := func(e string) {
		mu.Lock()
		errs = append(errs, e)
		mu.Unlock()
	}

	// ── Layer 1: Network Surface ────────────────────────────────────────────
	ports, tlsInfo := s.scanNetworkSurface(ctx, target, addFinding)
	report.OpenPorts = ports
	report.TLSInfo = tlsInfo

	// ── Layer 2: Service Discovery + Agent Fingerprinting ──────────────────
	detectedType, tools := s.discoverAgentServices(ctx, target, addFinding)
	report.DetectedType = detectedType
	report.AgentTools = tools
	if target.Type == AgentTypeUnknown {
		report.AgentType = detectedType
	}

	// ── Layer 3: Horus Static Analysis (if repo path given) ────────────────
	if target.RepoPath != "" {
		s.runHorusStatic(ctx, target, addFinding, addErr)
	}

	// ── Layer 4: Adversarial AI Probes + Sonar scan in parallel ─────────────
	// Both run concurrently — probes blast the agent while Sonar sweeps the surface.
	var probeWg sync.WaitGroup
	var probeFindings []ScanFinding
	var probeMu sync.Mutex

	// Kick off Sonar backbone scan in parallel goroutine
	probeWg.Add(1)
	go func() {
		defer probeWg.Done()
		sonarFindings := s.runSonarScan(ctx, target, addErr)
		probeMu.Lock()
		probeFindings = append(probeFindings, sonarFindings...)
		probeMu.Unlock()
	}()

	// Run adversarial probe suite
	suite := NewProbeSuite(target, s.fabric)
	adversarialFindings := suite.Run(ctx)
	probeMu.Lock()
	probeFindings = append(probeFindings, adversarialFindings...)
	probeMu.Unlock()

	probeWg.Wait()
	for _, pf := range probeFindings {
		addFinding(pf)
	}

	// ── Layer 5: KASA Behavioral Analysis ──────────────────────────────────
	kasaScore := s.scoreKASABehavior(ctx, suite.Responses())
	report.KASAScore = kasaScore

	// ── Layer 6: ERT Multi-lane scan (runs in parallel to probes) ──────────
	ertFindings := s.runERTScan(ctx, target, addErr)
	for _, f := range ertFindings {
		addFinding(f)
	}

	// ── Finalize ────────────────────────────────────────────────────────────
	report.CompletedAt = time.Now()
	report.DurationMs = time.Since(start).Milliseconds()
	report.Findings = findings
	report.Errors = errs
	report.Stats = computeScanStats(findings)
	report.RiskScore = computeRiskScore(findings, kasaScore)
	report.RiskLevel = riskLevel(report.RiskScore)

	// Generate summary
	report.Summary = fmt.Sprintf(
		"Agent scan of %s (%s) completed in %dms. "+
			"Risk: %s (%.1f/10) | KASA: %.2f | %d findings (%d critical, %d high)",
		target.URL, report.DetectedType, report.DurationMs,
		report.RiskLevel, report.RiskScore, kasaScore,
		report.Stats.Total, report.Stats.Critical, report.Stats.High,
	)

	// DAG attestation
	if s.dagStore != nil {
		node := &dag.Node{
			Action: "AGENT_SCAN_COMPLETE",
			Symbol: "Nkyinkyim",
			Time:   time.Now().Format(time.RFC3339),
			PQC: map[string]string{
				"scan_id":    scanID,
				"target":     target.URL,
				"risk_score": fmt.Sprintf("%.2f", report.RiskScore),
				"findings":   fmt.Sprintf("%d", report.Stats.Total),
				"tier":       target.Tier,
			},
		}
		if err := s.dagStore.Add(node, nil); err == nil {
			report.DAGNodeID = node.ID
		}
	}

	// Absorb completion into Fabric
	s.fabric.Absorb(ctx, flight.Event{
		Source:   "AgentScanner",
		Name:     "SCAN_COMPLETE",
		Category: flight.CategoryScan,
		Detail: map[string]any{
			"scan_id":    scanID,
			"risk_score": report.RiskScore,
			"risk_level": report.RiskLevel,
			"findings":   report.Stats.Total,
			"kasa":       kasaScore,
			"dag_node":   report.DAGNodeID,
		},
	})

	s.log.Info("Agent scan complete",
		"scan_id", scanID,
		"risk", report.RiskLevel,
		"score", report.RiskScore,
		"findings", report.Stats.Total,
	)

	return report, nil
}

// ─── Layer 1: Network Surface ─────────────────────────────────────────────────

func (s *AgentScanner) scanNetworkSurface(
	ctx context.Context,
	target AgentTarget,
	addFinding func(ScanFinding),
) ([]PortInfo, *TLSInfo) {

	host := extractHost(target.URL)
	if host == "" {
		return nil, nil
	}

	s.log.Info("Network surface scan", "host", host)

	// TCP port scan using existing pkg/scanner/network
	agentPorts := []int{80, 443, 3000, 4000, 5000, 7000, 8000, 8080, 8443, 8888, 9000, 9090, 11434}
	scanner := network.NewScanner(host, agentPorts)
	scanner.Timeout = 2 * time.Second
	scanner.Threads = 50

	rawResults := scanner.Scan(ctx)

	var ports []PortInfo
	for _, r := range rawResults {
		if r.State == "open" {
			pi := PortInfo{
				Port:    r.Port,
				Service: r.Service,
				Banner:  truncate(r.Banner, 128),
				State:   r.State,
			}
			ports = append(ports, pi)

			// Flag risky services
			severity, title := portRisk(r.Port, r.Service, r.Banner)
			if severity != "INFO" {
				fid := s.fabric.Absorb(ctx, flight.Event{
					Source:   "NetworkScanner",
					Name:     fmt.Sprintf("PORT_%d_%s", r.Port, strings.ToUpper(r.Service)),
					Category: flight.CategoryScan,
					Severity: strings.ToLower(severity),
					Detail: map[string]any{
						"port": r.Port, "service": r.Service, "banner": r.Banner,
					},
				})
				addFinding(ScanFinding{
					ID:           fmt.Sprintf("net-%d", r.Port),
					Layer:        "network",
					Category:     "port_exposure",
					Severity:     severity,
					RiskScore:    portRiskScore(r.Port),
					Title:        title,
					Description:  fmt.Sprintf("Port %d (%s) is exposed. Banner: %s", r.Port, r.Service, truncate(r.Banner, 64)),
					Evidence:     map[string]any{"port": r.Port, "service": r.Service, "banner": r.Banner},
					CMCCControls: []string{"CM.L2-3.4.1", "SC.L2-3.13.1"},
					NISTControls: []string{"CM-7", "SC-7"},
					Remediation:  fmt.Sprintf("Restrict port %d to known agent consumers only. Apply firewall rules.", r.Port),
					FrameID:      fid,
				})
			}
		}
	}

	// TLS inspection
	tlsInfo := s.inspectTLS(ctx, host, target.URL, addFinding)

	return ports, tlsInfo
}

// inspectTLS performs a TLS handshake and inspects certificate properties.
func (s *AgentScanner) inspectTLS(ctx context.Context, host, rawURL string, addFinding func(ScanFinding)) *TLSInfo {
	if !strings.HasPrefix(rawURL, "https://") {
		// No TLS — flag as finding if on a non-localhost target
		if !isLocalhost(host) {
			fid := s.fabric.Absorb(ctx, flight.Event{
				Source: "TLSInspector", Name: "NO_TLS",
				Category: flight.CategoryScan, Severity: "severe",
				Detail: map[string]any{"url": rawURL},
			})
			addFinding(ScanFinding{
				ID: "tls-none", Layer: "network", Category: "tls",
				Severity: "HIGH", RiskScore: 7.5,
				Title:        "Agent endpoint not using TLS",
				Description:  "Agent traffic is transmitted in plaintext. Tool parameters, API keys, and responses are exposed to interception.",
				CMCCControls: []string{"SC.L2-3.13.8", "SC.L2-3.13.10"},
				NISTControls: []string{"SC-8", "SC-13"},
				Remediation:  "Deploy TLS 1.3 with a valid certificate. Use Let's Encrypt or your PKI.",
				FrameID:      fid,
			})
		}
		return &TLSInfo{Enabled: false}
	}

	port := "443"
	if idx := strings.LastIndex(host, ":"); idx > 0 {
		port = host[idx+1:]
		host = host[:idx]
	}

	tlsCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()

	d := &tls.Dialer{Config: &tls.Config{InsecureSkipVerify: true}} //nolint:gosec — intentional for inspection
	conn, err := d.DialContext(tlsCtx, "tcp", host+":"+port)
	if err != nil {
		return &TLSInfo{Enabled: false}
	}
	defer conn.Close()

	tlsConn := conn.(*tls.Conn)
	state := tlsConn.ConnectionState()
	info := &TLSInfo{
		Enabled: true,
		Version: tlsVersionName(state.Version),
		Cipher:  tls.CipherSuiteName(state.CipherSuite),
	}

	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		info.Subject = cert.Subject.CommonName
		info.Issuer = cert.Issuer.CommonName
		info.ExpiresAt = cert.NotAfter
		info.DaysRemaining = int(time.Until(cert.NotAfter).Hours() / 24)
		info.SelfSigned = cert.Subject.CommonName == cert.Issuer.CommonName

		if info.SelfSigned {
			fid := s.fabric.Absorb(ctx, flight.Event{
				Source: "TLSInspector", Name: "SELF_SIGNED_CERT",
				Category: flight.CategoryScan, Severity: "warning",
			})
			addFinding(ScanFinding{
				ID: "tls-selfsigned", Layer: "network", Category: "tls",
				Severity: "MEDIUM", RiskScore: 5.0,
				Title:        "Self-signed TLS certificate",
				Description:  fmt.Sprintf("Agent uses a self-signed cert for %s. No trust chain.", info.Subject),
				CMCCControls: []string{"IA.L2-3.5.3", "SC.L2-3.13.10"},
				NISTControls: []string{"IA-5", "SC-17"},
				Remediation:  "Replace with a CA-signed certificate.",
				FrameID:      fid,
			})
		}

		if info.DaysRemaining < 30 {
			severity := "MEDIUM"
			if info.DaysRemaining < 7 {
				severity = "HIGH"
			}
			addFinding(ScanFinding{
				ID: "tls-expiry", Layer: "network", Category: "tls",
				Severity: severity, RiskScore: 6.0,
				Title:        fmt.Sprintf("TLS certificate expires in %d days", info.DaysRemaining),
				Description:  "Certificate near expiry will cause agent connection failures.",
				Remediation:  "Renew certificate immediately.",
				CMCCControls: []string{"SC.L2-3.13.10"},
				NISTControls: []string{"SC-17"},
			})
		}
	}

	// Weak cipher check
	weakCiphers := []string{"RC4", "DES", "3DES", "NULL", "EXPORT", "MD5"}
	for _, wc := range weakCiphers {
		if strings.Contains(strings.ToUpper(info.Cipher), wc) {
			info.WeakCipher = true
			fid := s.fabric.Absorb(ctx, flight.Event{
				Source: "TLSInspector", Name: "WEAK_CIPHER_" + wc,
				Category: flight.CategoryScan, Severity: "severe",
			})
			addFinding(ScanFinding{
				ID: "tls-cipher", Layer: "network", Category: "tls",
				Severity: "HIGH", RiskScore: 7.5,
				Title:        fmt.Sprintf("Weak TLS cipher: %s", info.Cipher),
				Description:  "Agent accepts weak TLS ciphers that can be broken offline.",
				Remediation:  "Configure TLS 1.3 only with AEAD ciphers (AES-GCM, ChaCha20-Poly1305).",
				CMCCControls: []string{"SC.L2-3.13.8"},
				NISTControls: []string{"SC-8"},
				FrameID:      fid,
			})
		}
	}

	return info
}

// ─── Layer 2: Service Discovery ───────────────────────────────────────────────

// discoverAgentServices probes well-known agent endpoints and fingerprints the framework.
func (s *AgentScanner) discoverAgentServices(
	ctx context.Context,
	target AgentTarget,
	addFinding func(ScanFinding),
) (AgentType, []AgentTool) {

	s.log.Info("Service discovery", "url", target.URL)

	client := httpClient(10 * time.Second)
	baseURL := strings.TrimRight(target.URL, "/")

	var tools []AgentTool
	detectedType := target.Type

	// ── MCP discovery ──────────────────────────────────────────────────────
	if detectedType == AgentTypeUnknown || detectedType == AgentTypeMCP {
		if t, discovered := s.probeMCP(ctx, client, baseURL, addFinding); len(discovered) > 0 {
			tools = append(tools, discovered...)
			detectedType = t
		}
	}

	// ── OpenAI-compatible ─────────────────────────────────────────────────
	if detectedType == AgentTypeUnknown || detectedType == AgentTypeOpenAI {
		if probeOpenAI(ctx, client, baseURL) {
			detectedType = AgentTypeOpenAI
		}
	}

	// ── Ollama ────────────────────────────────────────────────────────────
	if detectedType == AgentTypeUnknown {
		if probeOllama(ctx, client, baseURL) {
			detectedType = AgentTypeOllama
		}
	}

	// ── LangServe ────────────────────────────────────────────────────────
	if detectedType == AgentTypeUnknown || detectedType == AgentTypeLangServe {
		if probeLangServe(ctx, client, baseURL) {
			detectedType = AgentTypeLangServe
		}
	}

	if detectedType == AgentTypeUnknown {
		detectedType = AgentTypeHTTP
	}

	// Probe standard HTTP paths for information disclosure
	s.probeHTTPPaths(ctx, client, baseURL, addFinding)

	return detectedType, tools
}

// probeMCP discovers tools via MCP JSON-RPC list_tools.
func (s *AgentScanner) probeMCP(
	ctx context.Context,
	client *http.Client,
	baseURL string,
	addFinding func(ScanFinding),
) (AgentType, []AgentTool) {

	// Try MCP endpoints
	mcpPaths := []string{"/", "/mcp", "/mcp/v1", "/sse"}
	for _, path := range mcpPaths {
		payload := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`
		req, err := http.NewRequestWithContext(ctx, "POST", baseURL+path,
			strings.NewReader(payload))
		if err != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := client.Do(req)
		if err != nil || resp.StatusCode != 200 {
			if resp != nil {
				resp.Body.Close()
			}
			continue
		}

		body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		resp.Body.Close()

		var result struct {
			Result struct {
				Tools []struct {
					Name        string `json:"name"`
					Description string `json:"description"`
				} `json:"tools"`
			} `json:"result"`
		}
		if json.Unmarshal(body, &result) == nil && len(result.Result.Tools) > 0 {
			var tools []AgentTool
			for _, t := range result.Result.Tools {
				risk := inferToolRisk(t.Name, t.Description)
				tools = append(tools, AgentTool{
					Name:        t.Name,
					Description: t.Description,
					RiskClass:   risk,
				})

				// Destructive tools get flagged
				if risk == "destructive" {
					fid := s.fabric.Absorb(ctx, flight.Event{
						Source: "MCPDiscovery", Name: "DESTRUCTIVE_TOOL_EXPOSED",
						Category: flight.CategoryScan, Severity: "warning",
						Detail: map[string]any{"tool": t.Name, "path": path},
					})
					addFinding(ScanFinding{
						ID: "mcp-tool-" + t.Name, Layer: "service", Category: "tool_exposure",
						Severity: "MEDIUM", RiskScore: 5.5,
						Title:        fmt.Sprintf("Destructive MCP tool exposed: %s", t.Name),
						Description:  fmt.Sprintf("Tool %q has destructive risk class and is discoverable without authentication via %s.", t.Name, path),
						Probe:        "MCP tools/list",
						CMCCControls: []string{"AC.L2-3.1.1", "AC.L2-3.1.2"},
						NISTControls: []string{"AC-6", "AC-3"},
						Remediation:  "Require authentication for tools/list. Apply least-privilege tool scoping.",
						FrameID:      fid,
					})
				}
			}
			return AgentTypeMCP, tools
		}
	}
	return AgentTypeUnknown, nil
}

// probeHTTPPaths checks common paths for information disclosure.
func (s *AgentScanner) probeHTTPPaths(
	ctx context.Context,
	client *http.Client,
	baseURL string,
	addFinding func(ScanFinding),
) {
	sensitivePaths := map[string]string{
		"/metrics":                 "Prometheus metrics exposed (may reveal internals)",
		"/.env":                    ".env file accessible (potential secret leakage)",
		"/api/keys":                "API key management endpoint exposed",
		"/openapi.json":            "Full OpenAPI spec exposed (attack surface map)",
		"/swagger.json":            "Swagger spec exposed",
		"/v1/models":               "Model list exposed (OpenAI-compatible)",
		"/api/generate":            "Ollama API exposed without auth",
		"/_health":                 "Health endpoint (may reveal version info)",
		"/debug/pprof":             "Go pprof debugging endpoint exposed — CRITICAL",
		"/debug/vars":              "Go expvar endpoint exposed — HIGH",
		"/.git/config":             "Git repository exposed",
		"/api/v1/chat/completions": "LLM chat endpoint exposed",
	}

	for path, desc := range sensitivePaths {
		select {
		case <-ctx.Done():
			return
		default:
		}

		req, err := http.NewRequestWithContext(ctx, "GET", baseURL+path, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil || resp.StatusCode == 404 {
			if resp != nil {
				resp.Body.Close()
			}
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		resp.Body.Close()

		if resp.StatusCode == 200 || resp.StatusCode == 401 {
			severity := "MEDIUM"
			score := 5.0
			if strings.Contains(path, "debug") || strings.Contains(path, ".env") || strings.Contains(path, ".git") {
				severity = "CRITICAL"
				score = 9.5
			} else if resp.StatusCode == 401 {
				severity = "LOW"
				score = 2.0
				desc = "Endpoint exists but requires auth: " + desc
			}

			// Check response for credential patterns
			leaks := detectSecretLeakage(body)

			fid := s.fabric.Absorb(ctx, flight.Event{
				Source: "HTTPProbe", Name: "SENSITIVE_PATH_" + strings.ToUpper(strings.ReplaceAll(path, "/", "_")),
				Category: flight.CategoryScan, Severity: strings.ToLower(severity),
				Detail: map[string]any{"path": path, "status": resp.StatusCode, "secret_leaks": len(leaks)},
			})

			f := ScanFinding{
				ID:           "http-path-" + strings.ReplaceAll(path, "/", "-"),
				Layer:        "service",
				Category:     "information_disclosure",
				Severity:     severity,
				RiskScore:    score,
				Title:        fmt.Sprintf("Sensitive path accessible: %s (HTTP %d)", path, resp.StatusCode),
				Description:  desc,
				Probe:        "HTTP GET " + path,
				Response:     truncate(string(body), 256),
				Evidence:     map[string]any{"path": path, "status": resp.StatusCode},
				CMCCControls: []string{"AC.L2-3.1.3", "CM.L2-3.4.6"},
				NISTControls: []string{"AC-17", "CM-11"},
				Remediation:  fmt.Sprintf("Restrict %s behind authentication or remove it from production.", path),
				FrameID:      fid,
			}

			if len(leaks) > 0 {
				f.Severity = "CRITICAL"
				f.RiskScore = 9.8
				f.Title = "CREDENTIAL LEAK via " + path
				f.Description = fmt.Sprintf("Response body contains credential patterns: %v", leaks)
				f.CMCCControls = []string{"IA.L2-3.5.10", "IA.L2-3.5.11"}
				f.NISTControls = []string{"IA-5", "SC-28"}
			}

			addFinding(f)
		}
	}
}

// ─── Layer 3: Horus Static Analysis ──────────────────────────────────────────

func (s *AgentScanner) runHorusStatic(
	ctx context.Context,
	target AgentTarget,
	addFinding func(ScanFinding),
	addErr func(string),
) {
	s.log.Info("Horus static analysis", "path", target.RepoPath)

	// Secret detection
	secrets, err := scanners.RunBuiltInSecretScan(target.RepoPath)
	if err != nil {
		addErr(fmt.Sprintf("horus secret scan: %v", err))
	}
	for _, sec := range secrets {
		fid := s.fabric.Absorb(ctx, flight.Event{
			Source: "Horus-Secrets", Name: "SECRET_" + sec.Type,
			Category: flight.CategoryScan, Severity: "catastrophic",
			Detail: map[string]any{"type": sec.Type, "path": sec.File, "entropy": sec.Entropy},
		})
		addFinding(ScanFinding{
			ID: "horus-secret-" + sec.Type, Layer: "horus", Category: "secret",
			Severity:     "CRITICAL",
			RiskScore:    9.8,
			Title:        fmt.Sprintf("Hardcoded secret: %s", sec.Type),
			Description:  fmt.Sprintf("Found %s in %s (entropy: %.2f). Value: %s", sec.Type, sec.File, sec.Entropy, sec.Redacted),
			Evidence:     map[string]any{"file": sec.File, "type": sec.Type, "entropy": sec.Entropy},
			CMCCControls: []string{"IA.L2-3.5.10", "IA.L2-3.5.11"},
			NISTControls: []string{"IA-5", "SC-12"},
			Remediation:  "Remove secrets from source. Use environment variables or a secret manager.",
			FrameID:      fid,
		})
	}

	// Vulnerability scan
	vulns, err := scanners.RunBuiltInVulnerabilityScan(target.RepoPath)
	if err != nil {
		addErr(fmt.Sprintf("horus vuln scan: %v", err))
	}
	for _, v := range vulns {
		fid := s.fabric.Absorb(ctx, flight.Event{
			Source: "Horus-Vuln", Name: v.ID,
			Category: flight.CategoryScan, Severity: strings.ToLower(v.Severity),
		})
		addFinding(ScanFinding{
			ID: "horus-cve-" + v.ID, Layer: "horus", Category: "vulnerability",
			Severity:     v.Severity,
			RiskScore:    7.5, // default CVSS when not available
			Title:        fmt.Sprintf("%s: %s (%s@%s)", v.ID, v.Description, v.Package, v.Version),
			Description:  v.Description,
			Evidence:     map[string]any{"cve": v.ID, "package": v.Package, "fixed_in": v.FixedIn},
			CMCCControls: []string{"SI.L1-3.14.1", "SI.L2-3.14.4"},
			NISTControls: []string{"SI-2", "RA-5"},
			Remediation:  fmt.Sprintf("Upgrade %s to version %s or later.", v.Package, v.FixedIn),
			FrameID:      fid,
		})
	}
}

// ─── Layer 5: KASA Behavioral Analysis ───────────────────────────────────────

// scoreKASABehavior analyzes probe response patterns for behavioral anomalies.
func (s *AgentScanner) scoreKASABehavior(ctx context.Context, responses []ProbeResponse) float64 {
	if len(responses) == 0 {
		return 0.0
	}

	score := 0.0
	signals := 0

	for _, r := range responses {
		// Reflection detection: injected payload echoed back
		if r.Payload != "" && strings.Contains(r.Body, r.Payload) && r.Category == ProbeCatInjection {
			score += 2.0
			signals++
			s.fabric.Absorb(ctx, flight.Event{
				Source: "KASA-Behavioral", Name: "INJECTION_REFLECTION",
				Category: flight.CategoryKASA, Severity: "catastrophic",
				Detail: map[string]any{"probe": r.ProbeName, "payload": truncate(r.Payload, 32)},
			})
		}
		// Error leakage: stack traces, internal paths in responses
		if containsAny(r.Body, []string{"panic", "goroutine", "traceback", "Traceback", "at /home/", "at /app/", "Error stack"}) {
			score += 1.5
			signals++
		}
		// Abnormal response time: >5s to a simple probe = potential DoS
		if r.DurationMs > 5000 {
			score += 0.5
			signals++
		}
		// Successful injection (2xx on a blocked-probe path)
		if r.Category == ProbeCatInjection && r.StatusCode == 200 && r.Body != "" {
			score += 1.0
		}
	}

	// Normalize to 0.0–1.0
	normalized := score / float64(max(signals*3, 1))
	if normalized > 1.0 {
		normalized = 1.0
	}

	s.fabric.Absorb(ctx, flight.Event{
		Source: "KASA-Behavioral", Name: fmt.Sprintf("BEHAVIORAL_SCORE_%.2f", normalized),
		Category: flight.CategoryKASA,
		Detail:   map[string]any{"score": normalized, "signals": signals, "responses": len(responses)},
	})

	return normalized
}

// ─── Layer 6: ERT Multi-lane scan ────────────────────────────────────────────

func (s *AgentScanner) runERTScan(
	ctx context.Context,
	target AgentTarget,
	addErr func(string),
) []ScanFinding {
	if s.ertOrch == nil {
		return nil
	}

	host := extractHost(target.URL)
	req := ert.ScanRequest{
		ImageRef:   host,
		TargetPath: target.RepoPath,
		Lanes:      s.ertOrch.RegisteredLanes(),
	}

	result, err := s.ertOrch.Execute(ctx, req)
	if err != nil {
		addErr(fmt.Sprintf("ert scan: %v", err))
		return nil
	}
	if result == nil {
		return nil
	}

	var findings []ScanFinding
	for _, f := range result.Findings {
		findings = append(findings, ScanFinding{
			ID:          "ert-" + f.ID,
			Layer:       "ert-" + string(f.Source),
			Category:    string(f.Category),
			Severity:    f.Severity,
			RiskScore:   f.CVSSv3,
			Title:       f.Title,
			Description: f.Description,
			Evidence:    f.Evidence,
			Remediation: f.Remediation,
		})
	}
	return findings
}

// ─── Sonar Backbone Scan ──────────────────────────────────────────────────────

// runSonarScan invokes pkg/sonar.UnifiedOrchestrator — the omnipotent backbone scanner.
//
// It runs all scan types in parallel:
//   - TCP port scan          (pkg/scanner + pkg/scanner/network)
//   - Web crawler            (pkg/scanner.RunCrawler)
//   - Horus vuln scan        (pkg/scanners — CVE manifest matching)
//   - Horus secret scan      (pkg/scanners — entropy + regex)
//   - Horus compliance scan  (pkg/scanners — CIS/STIG/NIST checks)
//   - Horus container scan   (pkg/scanners — Dockerfile misconfig)
//
// All results are converted to ScanFindings and absorbed into the Flight Fabric.
func (s *AgentScanner) runSonarScan(
	ctx context.Context,
	target AgentTarget,
	addErr func(string),
) []ScanFinding {
	if s.sonarOrch == nil {
		return nil
	}

	host := extractHost(target.URL)
	if host == "" {
		return nil
	}

	s.log.Info("Sonar backbone scan starting", "host", host)

	scanTypes := []sonar.ScanType{
		sonar.ScanTypePort,
		sonar.ScanTypeVuln,
		sonar.ScanTypeSecrets,
		sonar.ScanTypeCompliance,
		sonar.ScanTypeContainer,
	}
	// Crawler only on pro/enterprise — it actively follows links
	if target.Tier == "pro" || target.Tier == "enterprise" {
		scanTypes = append(scanTypes, sonar.ScanTypeCrawler)
	}

	req := sonar.UnifiedScanRequest{
		Target:      host,
		ScanTypes:   scanTypes,
		Concurrency: 100,
		Timeout:     3 * time.Minute,
		Options: map[string]string{
			"compliance_framework": "cis", // CIS + STIG
		},
	}
	if target.RepoPath != "" {
		// For static analysis lanes, use repo path as target
		req.Target = target.RepoPath
	}

	sonarResult, err := s.sonarOrch.ExecuteScan(ctx, req)
	if err != nil {
		addErr(fmt.Sprintf("sonar scan: %v", err))
		return nil
	}
	if sonarResult == nil {
		return nil
	}

	// Absorb Sonar completion into Fabric
	s.fabric.Absorb(ctx, flight.Event{
		Source:   "SonarBackbone",
		Name:     "SONAR_SCAN_COMPLETE",
		Category: flight.CategoryScan,
		Detail: map[string]any{
			"request_id": sonarResult.RequestID,
			"target":     sonarResult.Target,
			"duration":   sonarResult.Duration.String(),
			"ports":      len(sonarResult.NetworkData),
			"vulns":      len(sonarResult.Vulnerabilities),
			"secrets":    len(sonarResult.Secrets),
			"dag_node":   sonarResult.DAGNodeID,
		},
	})

	var findings []ScanFinding

	// ── Network data → findings ────────────────────────────────────────────
	// NetworkData from pkg/scanner/network: richer than PortResults, includes banners.
	for _, pr := range sonarResult.NetworkData {
		if pr.State != "open" {
			continue
		}
		severity, title := portRisk(pr.Port, pr.Service, pr.Banner)
		if severity == "INFO" {
			continue
		}
		fid := s.fabric.Absorb(ctx, flight.Event{
			Source: "SonarNetwork", Name: fmt.Sprintf("PORT_%d", pr.Port),
			Category: flight.CategoryScan, Severity: strings.ToLower(severity),
			Detail: map[string]any{"port": pr.Port, "service": pr.Service},
		})
		findings = append(findings, ScanFinding{
			ID:           fmt.Sprintf("sonar-net-%d", pr.Port),
			Layer:        "sonar-network",
			Category:     "port_exposure",
			Severity:     severity,
			RiskScore:    portRiskScore(pr.Port),
			Title:        title,
			Description:  fmt.Sprintf("Port %d (%s) open. Banner: %s", pr.Port, pr.Service, truncate(pr.Banner, 64)),
			Evidence:     map[string]any{"port": pr.Port, "service": pr.Service, "banner": pr.Banner},
			CMCCControls: []string{"CM.L2-3.4.1", "SC.L2-3.13.1"},
			NISTControls: []string{"CM-7", "SC-7"},
			Remediation:  fmt.Sprintf("Restrict port %d with firewall rules.", pr.Port),
			FrameID:      fid,
		})
	}

	// ── Vulnerability findings ─────────────────────────────────────────────
	for _, v := range sonarResult.Vulnerabilities {
		fid := s.fabric.Absorb(ctx, flight.Event{
			Source: "SonarHorus-Vuln", Name: v.ID,
			Category: flight.CategoryScan, Severity: strings.ToLower(v.Severity),
			Detail: map[string]any{"cve": v.ID, "package": v.Package},
		})
		findings = append(findings, ScanFinding{
			ID:           "sonar-cve-" + v.ID,
			Layer:        "sonar-horus",
			Category:     "vulnerability",
			Severity:     v.Severity,
			RiskScore:    7.5,
			Title:        fmt.Sprintf("%s in %s@%s", v.ID, v.Package, v.Version),
			Description:  v.Description,
			Evidence:     map[string]any{"cve": v.ID, "package": v.Package, "fixed_in": v.FixedIn},
			CMCCControls: []string{"SI.L1-3.14.1", "SI.L2-3.14.4"},
			NISTControls: []string{"SI-2", "RA-5"},
			Remediation:  fmt.Sprintf("Upgrade %s to %s or later.", v.Package, v.FixedIn),
			FrameID:      fid,
		})
	}

	// ── Secret findings ───────────────────────────────────────────────────
	for _, sec := range sonarResult.Secrets {
		fid := s.fabric.Absorb(ctx, flight.Event{
			Source: "SonarHorus-Secrets", Name: "SECRET_" + sec.Type,
			Category: flight.CategoryScan, Severity: "catastrophic",
			Detail: map[string]any{"type": sec.Type, "file": sec.File, "entropy": sec.Entropy},
		})
		findings = append(findings, ScanFinding{
			ID:           "sonar-secret-" + sec.Type,
			Layer:        "sonar-horus",
			Category:     "secret",
			Severity:     "CRITICAL",
			RiskScore:    9.8,
			Title:        fmt.Sprintf("Hardcoded secret: %s", sec.Type),
			Description:  fmt.Sprintf("%s found in %s (entropy %.2f): %s", sec.Type, sec.File, sec.Entropy, sec.Redacted),
			Evidence:     map[string]any{"file": sec.File, "type": sec.Type, "entropy": sec.Entropy},
			CMCCControls: []string{"IA.L2-3.5.10", "IA.L2-3.5.11"},
			NISTControls: []string{"IA-5", "SC-12"},
			Remediation:  "Remove from source. Use environment variables or a vault.",
			FrameID:      fid,
		})
	}

	// ── Compliance findings ────────────────────────────────────────────────
	if sonarResult.ComplianceReport != nil {
		cr := sonarResult.ComplianceReport
		for i, cf := range cr.Findings {
			if strings.EqualFold(cf.Status, "pass") {
				continue // only surface failures
			}
			safeTitle := strings.ReplaceAll(truncate(cf.Title, 32), " ", "_")
			fid := s.fabric.Absorb(ctx, flight.Event{
				Source: "SonarHorus-Compliance", Name: "CTRL_FAIL_" + safeTitle,
				Category: flight.CategoryScan, Severity: strings.ToLower(cf.Severity),
				Detail: map[string]any{"title": cf.Title, "framework": cr.Framework, "status": cf.Status},
			})
			findings = append(findings, ScanFinding{
				ID:           fmt.Sprintf("sonar-compliance-%d", i),
				Layer:        "sonar-horus",
				Category:     "compliance",
				Severity:     cf.Severity,
				RiskScore:    complianceSeverityScore(cf.Severity),
				Title:        fmt.Sprintf("Compliance failure [%s]: %s", cr.Framework, cf.Title),
				Description:  cf.Description,
				Evidence:     map[string]any{"check": cf.Title, "framework": cr.Framework, "status": cf.Status},
				CMCCControls: []string{cr.Framework},
				NISTControls: []string{cr.Framework},
				Remediation:  cf.Remediation,
				FrameID:      fid,
			})
		}
	}

	// ── Container findings ────────────────────────────────────────────────
	if sonarResult.ContainerFindings != nil {
		for _, m := range sonarResult.ContainerFindings.Misconfigurations {
			fid := s.fabric.Absorb(ctx, flight.Event{
				Source: "SonarHorus-Container", Name: "CONTAINER_MISCONFIG",
				Category: flight.CategoryScan, Severity: "warning",
				Detail: map[string]any{"issue": m},
			})
			findings = append(findings, ScanFinding{
				ID:           fmt.Sprintf("sonar-container-%x", len(m)),
				Layer:        "sonar-horus",
				Category:     "container",
				Severity:     "MEDIUM",
				RiskScore:    5.0,
				Title:        "Container misconfiguration: " + truncate(m, 60),
				Description:  m,
				CMCCControls: []string{"CM.L2-3.4.1", "CM.L2-3.4.2"},
				NISTControls: []string{"CM-6", "CM-7"},
				Remediation:  "Follow CIS Docker Benchmark. Run as non-root, use read-only filesystem.",
				FrameID:      fid,
			})
		}
	}

	// ── Crawler findings ──────────────────────────────────────────────────
	// CrawlerFinding uses SpiderFoot event format: Event/Module/Data/Source/Type
	for _, cf := range sonarResult.CrawlerData {
		// Only flag findings with sensitive data patterns
		data := cf.Data
		if !containsAny(data, []string{"admin", "debug", "internal", ".env", "password", "secret", "token", "key"}) {
			continue
		}
		eventLabel := cf.Event
		if eventLabel == "" {
			eventLabel = cf.Type
		}
		fid := s.fabric.Absorb(ctx, flight.Event{
			Source: "SonarCrawler", Name: "SENSITIVE_FINDING_" + eventLabel,
			Category: flight.CategoryScan, Severity: "warning",
			Detail: map[string]any{"event": cf.Event, "module": cf.Module, "data": truncate(data, 64)},
		})
		findings = append(findings, ScanFinding{
			ID:           fmt.Sprintf("sonar-crawler-%x", len(data)),
			Layer:        "sonar-crawler",
			Category:     "information_disclosure",
			Severity:     "LOW",
			RiskScore:    3.0,
			Title:        fmt.Sprintf("Crawler sensitive finding [%s]: %s", eventLabel, truncate(data, 60)),
			Description:  fmt.Sprintf("Crawler module %s found: %s", cf.Module, data),
			Evidence:     map[string]any{"event": cf.Event, "module": cf.Module, "source": cf.Source},
			CMCCControls: []string{"AC.L2-3.1.3"},
			NISTControls: []string{"AC-17"},
			Remediation:  "Review and restrict access to discovered sensitive paths/resources.",
			FrameID:      fid,
		})
	}

	s.log.Info("Sonar backbone scan complete",
		"findings", len(findings),
		"ports", len(sonarResult.NetworkData),
		"vulns", len(sonarResult.Vulnerabilities),
		"secrets", len(sonarResult.Secrets),
		"duration", sonarResult.Duration,
	)

	return findings
}

// complianceSeverityScore maps compliance check severity to a risk score.
func complianceSeverityScore(severity string) float64 {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return 9.0
	case "HIGH":
		return 7.5
	case "MEDIUM":
		return 5.0
	default:
		return 3.0
	}
}


func probeOpenAI(ctx context.Context, client *http.Client, baseURL string) bool {
	req, _ := http.NewRequestWithContext(ctx, "GET", baseURL+"/v1/models", nil)
	resp, err := client.Do(req)
	if err != nil || resp == nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == 200 || resp.StatusCode == 401
}

func probeOllama(ctx context.Context, client *http.Client, baseURL string) bool {
	req, _ := http.NewRequestWithContext(ctx, "GET", baseURL+"/api/tags", nil)
	resp, err := client.Do(req)
	if err != nil || resp == nil {
		return false
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	return strings.Contains(string(body), "models")
}

func probeLangServe(ctx context.Context, client *http.Client, baseURL string) bool {
	payload := `{"input": "test"}`
	req, _ := http.NewRequestWithContext(ctx, "POST", baseURL+"/invoke",
		strings.NewReader(payload))
	if req == nil {
		return false
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil || resp == nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode != 404
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func httpClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true}, //nolint:gosec — scanner needs to inspect bad certs
			DialContext:         (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
			TLSHandshakeTimeout: 5 * time.Second,
			DisableKeepAlives:   true,
		},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse // don't follow redirects
		},
	}
}

func extractHost(rawURL string) string {
	rawURL = strings.TrimPrefix(rawURL, "https://")
	rawURL = strings.TrimPrefix(rawURL, "http://")
	if idx := strings.Index(rawURL, "/"); idx > 0 {
		rawURL = rawURL[:idx]
	}
	return rawURL
}

func isLocalhost(host string) bool {
	h := host
	if idx := strings.Index(h, ":"); idx > 0 {
		h = h[:idx]
	}
	return h == "localhost" || h == "127.0.0.1" || h == "::1"
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func containsAny(s string, patterns []string) bool {
	for _, p := range patterns {
		if strings.Contains(s, p) {
			return true
		}
	}
	return false
}

func portRisk(port int, service, banner string) (severity, title string) {
	switch port {
	case 22:
		return "INFO", "SSH exposed"
	case 23:
		return "CRITICAL", "Telnet exposed (plaintext protocol)"
	case 21:
		return "HIGH", "FTP exposed (plaintext protocol)"
	case 3306, 5432, 27017, 6379:
		return "CRITICAL", fmt.Sprintf("Database port %d publicly exposed", port)
	case 2375, 2376:
		return "CRITICAL", "Docker daemon API exposed"
	}
	if strings.Contains(strings.ToLower(banner), "password") || strings.Contains(strings.ToLower(banner), "root") {
		return "HIGH", fmt.Sprintf("Sensitive banner on port %d", port)
	}
	return "INFO", fmt.Sprintf("Port %d open (%s)", port, service)
}

func portRiskScore(port int) float64 {
	switch port {
	case 23, 3306, 5432, 27017, 6379, 2375, 2376:
		return 9.5
	case 21:
		return 7.5
	case 22:
		return 3.0
	default:
		return 2.0
	}
}

func inferToolRisk(name, desc string) string {
	n := strings.ToLower(name)
	d := strings.ToLower(desc)
	combined := n + " " + d
	if containsAny(combined, []string{"bash", "exec", "shell", "run", "delete", "rm", "drop", "write", "deploy", "sudo", "admin"}) {
		return "destructive"
	}
	if containsAny(combined, []string{"search", "read", "get", "list", "query", "fetch", "check"}) {
		return "read_only"
	}
	return "sandboxed"
}

func detectSecretLeakage(body []byte) []string {
	patterns := map[string]string{
		"OpenAI key":  `sk-[a-zA-Z0-9]{48}`,
		"GitHub PAT":  `ghp_[a-zA-Z0-9]{36}`,
		"AWS key":     `AKIA[A-Z0-9]{16}`,
		"Slack token": `xoxb-[0-9]{11}-`,
		"PEM key":     "-----BEGIN",
	}
	var found []string
	content := string(body)
	for label, pattern := range patterns {
		if strings.Contains(content, pattern[:min(len(pattern), 10)]) {
			found = append(found, label)
		}
	}
	return found
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("TLS 0x%04x", v)
	}
}

// cvssToScore normalises a raw CVSS score — returns a minimum of 3.0 for
// unscored findings so they still contribute to aggregate risk.
func cvssToScore(cvss float64) float64 {
	if cvss <= 0 {
		return 3.0
	}
	return cvss
}

func computeRiskScore(findings []ScanFinding, kasaScore float64) float64 {
	if len(findings) == 0 {
		return kasaScore * 5.0 // KASA alone
	}
	// Weighted sum of finding risk scores (clamped via cvssToScore), normalised
	total := 0.0
	for _, f := range findings {
		total += cvssToScore(f.RiskScore)
	}
	avg := total / float64(len(findings))
	// Blend with KASA behavioral score
	return min10(avg*0.8 + kasaScore*10*0.2)
}

func min10(v float64) float64 {
	if v > 10.0 {
		return 10.0
	}
	return v
}

func riskLevel(score float64) RiskLevel {
	switch {
	case score >= 9.0:
		return RiskLevelCritical
	case score >= 7.0:
		return RiskLevelHigh
	case score >= 4.0:
		return RiskLevelMedium
	case score > 0:
		return RiskLevelLow
	default:
		return RiskLevelNone
	}
}

func computeScanStats(findings []ScanFinding) ScanStats {
	s := ScanStats{Total: len(findings)}
	for _, f := range findings {
		switch strings.ToUpper(f.Severity) {
		case "CRITICAL":
			s.Critical++
		case "HIGH":
			s.High++
		case "MEDIUM":
			s.Medium++
		case "LOW":
			s.Low++
		default:
			s.Info++
		}
	}
	return s
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// readBody drains and closes an HTTP response body safely.
func readBody(resp *http.Response, limit int64) []byte {
	if resp == nil || resp.Body == nil {
		return nil
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, limit))
	return b
}

var _ = readBody // prevent unused warning; used by probe_suite.go
var _ = bytes.NewReader
