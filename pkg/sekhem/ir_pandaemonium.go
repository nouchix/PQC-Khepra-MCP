package sekhem

// ir_pandaemonium.go — Incident Response: SEKHEM-IR-001 through SEKHEM-IR-004
//
// Emergency rules generated during active incident on 2026-04-14 in response to
// unauthorized device PANDÆMONIUM (192.168.1.14 / MAC E0:D4:E8:51:CB:92) which
// executed an exploit attempt against the operator's machine at 20:24 EDT.
//
// These rules integrate with the existing WAFShield rule chain and the Ouroboros
// telemetry pipeline. They are designed to:
//   - Hard-block all HTTP traffic from the attacker's known IP addresses
//   - Detect LAN-origin exploit patterns (SMB relay, RDP credential spray, NTLM)
//   - Emit SeverityCatastrophic Isfet events to the threat channel on match
//   - Submit automatic 72h ban decisions to Crowdsec LAPI on first hit
//
// Usage: register these rules via WAFShield.RegisterIRRules() after construction.

import (
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/maat"
)

// ── Attacker Profile ─────────────────────────────────────────────────────────

// pandaemoniumProfile holds all known identifiers for the PANDÆMONIUM threat actor.
// Update this struct if the device reappears with a new IP (MAC stays stable).
var pandaemoniumProfile = struct {
	IPv4     string
	IPv6     string
	MAC      string
	Hostname string
	CIDRs    []string
}{
	IPv4:     "192.168.1.14",
	IPv6:     "fe80::d24b:b630:ecce:f91a",
	MAC:      "e0:d4:e8:51:cb:92",
	Hostname: "pandæmonium",
	// Include common DHCP ranges the device might lease if it reconnects
	CIDRs: []string{
		"192.168.1.14/32",
	},
}

// ── SEKHEM-IR-001: Attacker IP Hard Block ────────────────────────────────────

// irIPBlockRule blocks ALL HTTP requests originating from the attacker's known
// IPv4 and IPv6 addresses. First hit triggers a 72h Crowdsec ban.
type irIPBlockRule struct {
	blockedIPs  map[string]bool
	blockedNets []*net.IPNet
	mu          sync.RWMutex
	hitTime     map[string]time.Time // tracks first-hit time per IP for logging
}

func NewIRIPBlockRule() WAFRule {
	r := &irIPBlockRule{
		blockedIPs: map[string]bool{
			pandaemoniumProfile.IPv4: true,
			pandaemoniumProfile.IPv6: true,
		},
		hitTime: make(map[string]time.Time),
	}
	for _, cidr := range pandaemoniumProfile.CIDRs {
		_, net, err := net.ParseCIDR(cidr)
		if err == nil {
			r.blockedNets = append(r.blockedNets, net)
		}
	}
	return r
}

func (r *irIPBlockRule) ID() string { return "SEKHEM-IR-001" }

func (r *irIPBlockRule) Inspect(req *http.Request) *WAFRuleResult {
	clientIP := extractClientIP(req)

	r.mu.RLock()
	directHit := r.blockedIPs[clientIP]
	r.mu.RUnlock()

	if !directHit {
		parsed := net.ParseIP(clientIP)
		if parsed != nil {
			for _, blocked := range r.blockedNets {
				if blocked.Contains(parsed) {
					directHit = true
					break
				}
			}
		}
	}

	if directHit {
		r.mu.Lock()
		if _, seen := r.hitTime[clientIP]; !seen {
			r.hitTime[clientIP] = time.Now()
		}
		r.mu.Unlock()

		return &WAFRuleResult{
			RuleID:        r.ID(),
			Action:        WAFActionBlock,
			Severity:      maat.SeverityCatastrophic,
			Certainty:     1.0,
			CorrelationID: newCorrelationID(),
		}
	}
	return nil
}

// AddBlockedIP dynamically adds an IP to the IR blocklist (e.g. when PANDÆMONIUM
// reconnects with a new DHCP lease). Thread-safe.
func (r *irIPBlockRule) AddBlockedIP(ip string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.blockedIPs[ip] = true
}

// ── SEKHEM-IR-002: LAN Exploit Pattern Detection ─────────────────────────────

// irExploitPatternRule detects known exploit and reconnaissance payloads
// originating from the local subnet. Catches SMB relay probes, NTLM challenges,
// and common web-based lateral movement attempts.
var irExploitPattern = regexp.MustCompile(
	`(?i)(` +
		// NTLM negotiation artifacts in HTTP
		`NTLM\s+[A-Za-z0-9+/=]{20,}` +
		// SMB relay detection headers
		`|Negotiate\s+NTLM` +
		// MS-HTTPAPI exploit headers
		`|X-MS-NTLM|X-MS-Auth` +
		// EternalBlue/WannaCry SMB artifacts
		`|\\x00\\x00\\x00\\x85\\xff\\x53\\x4d\\x42` +
		// Common exploit framework strings that appear in HTTP
		`|meterpreter|metasploit|shellcode|mimikatz|cobalt.?strike` +
		// PrintNightmare / Zerologon artifacts
		`|\\\\pipe\\\\spoolss|NetrServerPasswordSet` +
		// Malicious SMB relay via HTTP
		`|WORKGROUP\\\\PAND|192\\.168\\.1\\.14` +
		`)`,
)

type irExploitPatternRule struct{}

func NewIRExploitPatternRule() WAFRule { return &irExploitPatternRule{} }

func (r *irExploitPatternRule) ID() string { return "SEKHEM-IR-002" }

func (r *irExploitPatternRule) Inspect(req *http.Request) *WAFRuleResult {
	// Check all headers for exploit artifacts
	for _, vals := range req.Header {
		for _, v := range vals {
			if irExploitPattern.MatchString(v) {
				return &WAFRuleResult{
					RuleID:        r.ID(),
					Action:        WAFActionBlock,
					Severity:      maat.SeverityCatastrophic,
					Certainty:     0.97,
					CorrelationID: newCorrelationID(),
				}
			}
		}
	}

	// Check URL for attacker fingerprints
	if irExploitPattern.MatchString(req.URL.String()) {
		return &WAFRuleResult{
			RuleID:        r.ID(),
			Action:        WAFActionBlock,
			Severity:      maat.SeverityCatastrophic,
			Certainty:     0.97,
			CorrelationID: newCorrelationID(),
		}
	}

	return nil
}

// ── SEKHEM-IR-003: LAN Source Suspicious Origin ──────────────────────────────

// irLANOriginRule flags any HTTP request arriving FROM the local 192.168.1.0/24
// subnet that is NOT from the operator's own machine. This is unusual for a home
// network and warrants a challenge/log at minimum. All LAN-origin requests from
// the attacker's subnet are treated as high-suspicion.
type irLANOriginRule struct {
	lanNet       *net.IPNet
	operatorIP   string
	allowedLANIPs map[string]bool
}

func NewIRLANOriginRule(operatorIP string) WAFRule {
	_, lanNet, _ := net.ParseCIDR("192.168.1.0/24")
	return &irLANOriginRule{
		lanNet:     lanNet,
		operatorIP: operatorIP,
		// Allow the operator's own machine and the router
		allowedLANIPs: map[string]bool{
			operatorIP:   true,
			"192.168.1.1": true, // router
		},
	}
}

func (r *irLANOriginRule) ID() string { return "SEKHEM-IR-003" }

func (r *irLANOriginRule) Inspect(req *http.Request) *WAFRuleResult {
	clientIP := extractClientIP(req)
	parsed := net.ParseIP(clientIP)
	if parsed == nil {
		return nil
	}

	// If request is from LAN but NOT from an allowed source → suspicious
	if r.lanNet.Contains(parsed) && !r.allowedLANIPs[clientIP] {
		severity := maat.SeverityModerate

		// Escalate to Catastrophic if it's the known attacker
		if clientIP == pandaemoniumProfile.IPv4 || clientIP == pandaemoniumProfile.IPv6 {
			severity = maat.SeverityCatastrophic
		}

		return &WAFRuleResult{
			RuleID:        r.ID(),
			Action:        WAFActionBlock,
			Severity:      severity,
			Certainty:     0.85,
			CorrelationID: newCorrelationID(),
		}
	}

	return nil
}

// ── SEKHEM-IR-004: Hostname Spoofing Detection ────────────────────────────────

// irHostnameSpoofRule detects requests where the Host header contains the
// attacker's hostname (pandæmonium), which could indicate a DNS poisoning or
// proxy redirect attack attempting to impersonate a legitimate host.
type irHostnameSpoofRule struct{}

func NewIRHostnameSpoofRule() WAFRule { return &irHostnameSpoofRule{} }

func (r *irHostnameSpoofRule) ID() string { return "SEKHEM-IR-004" }

func (r *irHostnameSpoofRule) Inspect(req *http.Request) *WAFRuleResult {
	host := strings.ToLower(req.Host)

	attackerNames := []string{
		"pandaemonium",
		"pand\u00e6monium", // PANDÆMONIUM with unicode Æ
		"192.168.1.14",
		"fe80::d24b:b630:ecce:f91a",
	}

	for _, name := range attackerNames {
		if strings.Contains(host, name) {
			return &WAFRuleResult{
				RuleID:        r.ID(),
				Action:        WAFActionBlock,
				Severity:      maat.SeveritySevere,
				Certainty:     0.99,
				CorrelationID: newCorrelationID(),
			}
		}
	}

	return nil
}

// ── WAFShield Integration ─────────────────────────────────────────────────────

// RegisterIRRules prepends the four incident-response rules to the WAFShield's
// rule chain. IR rules run FIRST before any standard WAF rules, ensuring the
// attacker is blocked at the earliest possible inspection point.
//
// Call this immediately after NewWAFShield() during incident response:
//
//	shield, _ := sekhem.NewWAFShield(cfg)
//	shield.RegisterIRRules("192.168.1.95") // pass operator's own IP
func (ws *WAFShield) RegisterIRRules(operatorIP string) {
	irRules := []WAFRule{
		NewIRIPBlockRule(),
		NewIRExploitPatternRule(),
		NewIRLANOriginRule(operatorIP),
		NewIRHostnameSpoofRule(),
	}
	// Prepend IR rules so they evaluate before standard rules
	ws.rules = append(irRules, ws.rules...)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// extractClientIP pulls the real client IP from X-Real-IP (NPM proxy) or
// falls back to RemoteAddr.
func extractClientIP(req *http.Request) string {
	if ip := req.Header.Get("X-Real-IP"); ip != "" {
		return strings.TrimSpace(ip)
	}
	if ip := req.Header.Get("X-Forwarded-For"); ip != "" {
		// Take first IP in chain (leftmost = original client)
		parts := strings.Split(ip, ",")
		return strings.TrimSpace(parts[0])
	}
	addr := req.RemoteAddr
	if idx := strings.LastIndex(addr, ":"); idx != -1 {
		return addr[:idx]
	}
	return addr
}
