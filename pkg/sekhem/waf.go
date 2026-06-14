// Package sekhem implements the SEKHEM Gateway — divine authority at the perimeter.
// "Power, might — the scepter that commands the boundary between chaos and order."
//
// WAFShield is the Merkaba L7 perimeter guard embedded in the SEKHEM gateway.
// It performs:
//   - Eight WAF rule checks (SQLi, XSS, path traversal, oversized body, UTF-8, host, rate, UA)
//   - Adinkra spectral fingerprinting per request (static symbol FP + dynamic metadata)
//   - Kyber-1024 ephemeral keypair rotation (hourly, forward secrecy for PoW challenges)
//   - Threat event emission to a buffered channel consumed by the Ouroboros WAFEye
//   - Crowdsec LAPI submission for confirmed ban decisions
//   - Health + NPM Docker gateway bypass (no WAF overhead on internal probes)
package sekhem

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/adinkra"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/maat"
)

const (
	// threatChanCap is the buffered channel capacity for WAF threat events.
	// The WAFEye drains this channel each Ouroboros cycle (10 s). At 1000 events
	// the channel is large enough to absorb a burst without blocking request goroutines.
	threatChanCap = 1000

	// maxBodyBytes is the per-request body read limit (10 MiB).
	// Requests exceeding this are blocked by SEKHEM-004 before body parsing.
	maxBodyBytes = 10 * 1024 * 1024

	// keyRotationInterval is how often the Kyber-1024 ephemeral keypair rotates.
	keyRotationInterval = 1 * time.Hour

	// npmGatewayCIDR is the Docker bridge subnet used by NPM to health-probe upstream.
	// Requests from this CIDR bypass the PoW challenge (but not the injection rules).
	npmGatewayCIDR = "172.19.0.0/16"

	// crowdsecDecisionDuration is the default ban duration submitted to Crowdsec.
	crowdsecDecisionDuration = "24h"
)

// WAFMetrics holds counters exposed to the Ouroboros telemetry pipeline.
type WAFMetrics struct {
	mu           sync.Mutex
	TotalChecked int64
	Blocked      int64
	Challenged   int64
	Bypassed     int64
	RuleHits     map[string]int64
}

// WAFSnapshot is a mutex-free point-in-time copy of WAFMetrics.
// Use this type for telemetry, logging, and API responses to avoid
// copying the embedded sync.Mutex inside WAFMetrics.
type WAFSnapshot struct {
	TotalChecked int64
	Blocked      int64
	Challenged   int64
	Bypassed     int64
	RuleHits     map[string]int64
}

func newWAFMetrics() *WAFMetrics {
	return &WAFMetrics{RuleHits: make(map[string]int64)}
}

func (m *WAFMetrics) record(ruleID string, action WAFAction) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.TotalChecked++
	m.RuleHits[ruleID]++
	switch action {
	case WAFActionBlock:
		m.Blocked++
	case WAFActionChallenge:
		m.Challenged++
	case WAFActionBypass:
		m.Bypassed++
	}
}

// Snapshot returns a mutex-free, read-safe copy of current metrics.
func (m *WAFMetrics) Snapshot() WAFSnapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	snap := WAFSnapshot{
		TotalChecked: m.TotalChecked,
		Blocked:      m.Blocked,
		Challenged:   m.Challenged,
		Bypassed:     m.Bypassed,
		RuleHits:     make(map[string]int64, len(m.RuleHits)),
	}
	for k, v := range m.RuleHits {
		snap.RuleHits[k] = v
	}
	return snap
}

// WAFShield is the Merkaba L7 WAF embedded in the SEKHEM gateway.
// It is safe for concurrent use by multiple goroutines.
type WAFShield struct {
	rules      []WAFRule
	metrics    *WAFMetrics
	threatChan chan maat.Isfet // buffered channel → WAFEye drain in Ouroboros cycle

	// Kyber-1024 ephemeral keypair — hourly rotation for forward secrecy.
	// Protected by mu; callers must hold at least RLock for reads.
	mu        sync.RWMutex
	kyberPub  []byte
	kyberPriv []byte

	// Crowdsec LAPI integration
	crowdsecURL    string // e.g. "http://localhost:8080"
	crowdsecAPIKey string // bouncer API key registered in Crowdsec

	// Bypass lists
	bypassPaths []*bypassPath      // exact path prefixes that skip ALL WAF logic
	bypassCIDRs []net.IPNet        // source CIDRs that skip PoW challenge only
	npmCIDR     *net.IPNet         // pre-parsed npmGatewayCIDR

	// Spectral anchor: GetSpectralFingerprint("Eban") cached at construction.
	// Per-request fingerprint = SHA-256(anchor || clientIP || UA || path || timeBucket)
	spectralAnchor []byte

	// cancelRotation stops the keypair rotation goroutine on Close().
	cancelRotation context.CancelFunc
}

type bypassPath struct {
	prefix string
}

// WAFShieldConfig holds all WAFShield constructor parameters.
type WAFShieldConfig struct {
	// CrowdsecURL is the Crowdsec LAPI base URL (default: read from
	// CROWDSEC_LAPI_URL env, fallback "http://localhost:8080").
	CrowdsecURL string
	// CrowdsecAPIKey is the bouncer key (default: CROWDSEC_BOUNCER_KEY env).
	CrowdsecAPIKey string
}

// NewWAFShield constructs and starts the WAFShield.
// It generates the initial Kyber-1024 keypair and starts the rotation goroutine.
// Call Close() to stop background goroutines.
func NewWAFShield(cfg WAFShieldConfig) (*WAFShield, error) {
	// Crowdsec config from env if not provided
	csURL := cfg.CrowdsecURL
	if csURL == "" {
		csURL = os.Getenv("CROWDSEC_LAPI_URL")
		if csURL == "" {
			csURL = "http://localhost:8080"
		}
	}
	csKey := cfg.CrowdsecAPIKey
	if csKey == "" {
		csKey = os.Getenv("CROWDSEC_BOUNCER_KEY")
	}
	if csKey == "" {
		log.Println("[SEKHEM-WAF] WARNING: CROWDSEC_BOUNCER_KEY not set — Crowdsec submission disabled")
	}

	// Parse NPM bypass CIDR
	_, npmNet, err := net.ParseCIDR(npmGatewayCIDR)
	if err != nil {
		return nil, fmt.Errorf("sekhem/waf: parse NPM CIDR: %w", err)
	}

	// Compute spectral anchor: static D₈ fingerprint for the "Eban" symbol.
	anchorHex := adinkra.GetSpectralFingerprint("Eban")
	anchor, err := hex.DecodeString(string(anchorHex))
	if err != nil {
		// If the fingerprint is not hex (e.g. raw bytes), hash it instead.
		h := sha256.Sum256(anchorHex)
		anchor = h[:]
	}

	// Generate initial Kyber-1024 keypair
	pub, priv, err := adinkra.GenerateKyberKey()
	if err != nil {
		return nil, fmt.Errorf("sekhem/waf: initial Kyber keygen: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	shield := &WAFShield{
		metrics:        newWAFMetrics(),
		threatChan:     make(chan maat.Isfet, threatChanCap),
		crowdsecURL:    csURL,
		crowdsecAPIKey: csKey,
		npmCIDR:        npmNet,
		spectralAnchor: anchor,
		kyberPub:       pub,
		kyberPriv:      priv,
		cancelRotation: cancel,
		bypassPaths: []*bypassPath{
			{prefix: "/health"},
			{prefix: "/healthz"},
			{prefix: "/api/v1/onboarding/"},  // Public scan funnel — intentionally unauthenticated
		},
	}
	shield.rules = defaultRules(shield)

	// Start hourly keypair rotation goroutine
	go shield.rotateKeypairLoop(ctx)

	log.Printf("[SEKHEM-WAF] WAFShield online — %d rules, spectral anchor=%s, Crowdsec=%s",
		len(shield.rules), string(anchorHex[:16])+"...", csURL)

	return shield, nil
}

// rotateKeypairLoop replaces the Kyber-1024 keypair every keyRotationInterval.
// Old sessions lose forward secrecy after rotation; this is intentional.
func (ws *WAFShield) rotateKeypairLoop(ctx context.Context) {
	ticker := time.NewTicker(keyRotationInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			pub, priv, err := adinkra.GenerateKyberKey()
			if err != nil {
				log.Printf("[SEKHEM-WAF] Kyber key rotation FAILED: %v — retaining current keypair", err)
				continue
			}
			ws.mu.Lock()
			ws.kyberPub = pub
			ws.kyberPriv = priv
			ws.mu.Unlock()
			log.Println("[SEKHEM-WAF] Kyber-1024 keypair rotated (hourly forward secrecy reset)")
		}
	}
}

// Close stops the keypair rotation goroutine. WAFShield must not be used after Close.
func (ws *WAFShield) Close() {
	ws.cancelRotation()
}

// ThreatChan returns the read-only channel of WAF threat events.
// The Ouroboros WAFEye drains this channel each cycle.
func (ws *WAFShield) ThreatChan() <-chan maat.Isfet {
	return ws.threatChan
}

// Metrics returns a mutex-free snapshot of current WAF metrics.
func (ws *WAFShield) Metrics() WAFSnapshot {
	return ws.metrics.Snapshot()
}

// CurrentKyberPublicKey returns the current ephemeral Kyber-1024 public key.
// Safe to call concurrently.
func (ws *WAFShield) CurrentKyberPublicKey() []byte {
	ws.mu.RLock()
	defer ws.mu.RUnlock()
	out := make([]byte, len(ws.kyberPub))
	copy(out, ws.kyberPub)
	return out
}

// GinHandler returns a gin.HandlerFunc that runs the WAF inspection on every request.
// Middleware ordering must be:
//
//	RecoveryMiddleware → LoggingMiddleware → CORSMiddleware → WAFMiddleware → AuthMiddleware
func (ws *WAFShield) GinHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		clientIP := c.ClientIP()

		// ── Bypass: health probes and NPM Docker gateway ──────────────────────
		if ws.isBypassPath(c.Request.URL.Path) {
			ws.metrics.record("SEKHEM-BYPASS", WAFActionBypass)
			c.Next()
			return
		}

		// ── Body size limit (SEKHEM-004) — read and rebuffer before rule checks ──
		if !ws.readBody(c, clientIP) {
			return
		}

		// ── Spectral fingerprint for this request ─────────────────────────────
		fingerprint := ws.computeFingerprint(clientIP, c.Request)

		// ── Run all WAF rules ─────────────────────────────────────────────────
		for _, rule := range ws.rules {
			result := rule.Inspect(c.Request)
			if result == nil {
				continue
			}
			ws.metrics.record(result.RuleID, result.Action)
			ws.emitThreat(result, clientIP, fingerprint, c.Request.URL.Path)
			if ws.enforceAction(c, result, clientIP) {
				return
			}
		}

		// All rules passed — set fingerprint header for downstream tracing
		c.Header("X-Sekhem-FP", fingerprint[:16])
		c.Next()
	}
}

// readBody enforces the body-size limit (SEKHEM-004) and rebuffers the body
// for downstream handlers. Returns false if the request was blocked.
func (ws *WAFShield) readBody(c *gin.Context, clientIP string) bool {
	if c.Request.Body == nil {
		return true
	}
	limited := http.MaxBytesReader(c.Writer, c.Request.Body, maxBodyBytes)
	body, err := io.ReadAll(limited)
	if err != nil {
		ws.blockRequest(c, "SEKHEM-004", clientIP,
			"request body exceeds maximum allowed size",
			maat.SeveritySevere)
		return false
	}
	// Rebuffer so downstream handlers can read the body again
	c.Request.Body = io.NopCloser(bytes.NewReader(body))
	return true
}

// emitThreat sends a WAF threat event to the Ouroboros channel (non-blocking).
// If the channel is full the event is dropped and logged.
func (ws *WAFShield) emitThreat(result *WAFRuleResult, clientIP, fingerprint, path string) {
	threat := maat.Isfet{
		ID:       result.CorrelationID,
		Severity: result.Severity,
		Source:   clientIP,
		Omens: []maat.Omen{
			{Name: "rule_id", Value: result.RuleID, Malevolence: severityToMalevolence(result.Severity)},
			{Name: "path", Value: path, Malevolence: 0},
			{Name: "fingerprint", Value: fingerprint, Malevolence: 0},
			{Name: "ip", Value: clientIP, Malevolence: severityToMalevolence(result.Severity)},
		},
		Certainty: result.Certainty,
	}
	select {
	case ws.threatChan <- threat:
	default:
		log.Printf("[SEKHEM-WAF] threatChan full — dropping event for %s rule=%s", clientIP, result.RuleID)
	}
}

// enforceAction applies the WAF decision (block or challenge) and returns true
// if the request was terminated so the caller can return early.
func (ws *WAFShield) enforceAction(c *gin.Context, result *WAFRuleResult, clientIP string) bool {
	switch result.Action {
	case WAFActionBlock:
		// Submit to Crowdsec for IP ban on severe/catastrophic events (fire-and-forget)
		if result.Severity == maat.SeveritySevere || result.Severity == maat.SeverityCatastrophic {
			go ws.submitCrowdsecDecision(clientIP, crowdsecDecisionDuration, "ban")
		}
		c.JSON(http.StatusForbidden, gin.H{
			"error":          "forbidden",
			"correlation_id": result.CorrelationID,
		})
		c.Abort()
		return true
	case WAFActionChallenge:
		// Rate-limit challenge: 429 with Retry-After
		c.Header("Retry-After", "60")
		c.JSON(http.StatusTooManyRequests, gin.H{
			"error":          "rate_limit_exceeded",
			"correlation_id": result.CorrelationID,
		})
		c.Abort()
		return true
	}
	return false
}


// isBypassPath returns true if the path matches any configured bypass prefix.
func (ws *WAFShield) isBypassPath(path string) bool {
	for _, bp := range ws.bypassPaths {
		if strings.HasPrefix(path, bp.prefix) {
			return true
		}
	}
	return false
}

// isNPMGateway returns true if the client IP is within the Docker NPM bridge subnet.
func (ws *WAFShield) isNPMGateway(clientIP string) bool {
	ip := net.ParseIP(clientIP)
	if ip == nil {
		return false
	}
	return ws.npmCIDR.Contains(ip)
}

// computeFingerprint derives a per-request spectral fingerprint:
//
//	SHA-256(spectralAnchor || clientIP || userAgent || path || timeBucket)
//
// timeBucket is the Unix minute — requests within the same minute share the same bucket,
// providing stable fingerprinting without per-second jitter.
func (ws *WAFShield) computeFingerprint(clientIP string, r *http.Request) string {
	timeBucket := fmt.Sprintf("%d", time.Now().Unix()/60)
	h := sha256.New()
	h.Write(ws.spectralAnchor)
	h.Write([]byte(clientIP))
	h.Write([]byte(r.UserAgent()))
	h.Write([]byte(r.URL.Path))
	h.Write([]byte(timeBucket))
	return hex.EncodeToString(h.Sum(nil))
}

// blockRequest centralises the block response and threat emission for body-level checks
// that fire before the rule loop (e.g. SEKHEM-004 body limit).
func (ws *WAFShield) blockRequest(c *gin.Context, ruleID, clientIP, reason string, severity maat.Severity) {
	corrID := newCorrelationID()
	ws.metrics.record(ruleID, WAFActionBlock)

	threat := maat.Isfet{
		ID:       corrID,
		Severity: severity,
		Source:   clientIP,
		Omens: []maat.Omen{
			{Name: "rule_id", Value: ruleID, Malevolence: severityToMalevolence(severity)},
			{Name: "reason", Value: reason, Malevolence: 0.8},
			{Name: "ip", Value: clientIP, Malevolence: severityToMalevolence(severity)},
		},
		Certainty: 0.95,
	}
	select {
	case ws.threatChan <- threat:
	default:
	}

	c.JSON(http.StatusForbidden, gin.H{
		"error":          "forbidden",
		"correlation_id": corrID,
	})
	c.Abort()
}

// submitCrowdsecDecision POSTs a ban decision to the Crowdsec LAPI bouncer endpoint.
// Crowdsec is the single enforcement authority for IP blocklists on this VPS.
// SEKHEM is a signal source; Crowdsec is the actuator.
func (ws *WAFShield) submitCrowdsecDecision(ip, duration, decType string) {
	if ws.crowdsecAPIKey == "" {
		log.Printf("[SEKHEM-WAF] Crowdsec key not set — skipping decision for %s", ip)
		return
	}

	body, err := json.Marshal([]map[string]string{
		{
			"duration": duration,
			"scope":    "Ip",
			"type":     decType,
			"value":    ip,
		},
	})
	if err != nil {
		log.Printf("[SEKHEM-WAF] Crowdsec marshal error: %v", err)
		return
	}

	req, err := http.NewRequest(http.MethodPost,
		ws.crowdsecURL+"/v1/decisions",
		bytes.NewReader(body))
	if err != nil {
		log.Printf("[SEKHEM-WAF] Crowdsec request build error: %v", err)
		return
	}
	req.Header.Set("X-Api-Key", ws.crowdsecAPIKey)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[SEKHEM-WAF] Crowdsec submission failed for %s: %v", ip, err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		log.Printf("[SEKHEM-WAF] Crowdsec returned %d for %s: %s", resp.StatusCode, ip, b)
		return
	}
	log.Printf("[SEKHEM-WAF] Crowdsec decision submitted: type=%s ip=%s duration=%s", decType, ip, duration)
}

// newCorrelationID generates a 128-bit random hex correlation ID.
func newCorrelationID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// Extremely unlikely; fall back to a timestamp-based ID
		return fmt.Sprintf("ts-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// severityToMalevolence maps maat.Severity to a malevolence float in [0,1].
func severityToMalevolence(s maat.Severity) float64 {
	switch s {
	case maat.SeverityMinor:
		return 0.3
	case maat.SeverityModerate:
		return 0.55
	case maat.SeveritySevere:
		return 0.8
	case maat.SeverityCatastrophic:
		return 1.0
	default:
		return 0.5
	}
}
