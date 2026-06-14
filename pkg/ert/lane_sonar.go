package ert

// lane_sonar.go — Sonar scan lane for the ERT ScanOrchestrator.
//
// Privacy-first design: ZERO external API calls. Shodan, Censys, and all
// OSINT APIs have been permanently removed. See pkg/scanner/osint/ — deleted.
//
// What this lane does:
//   1. TCP port scan    (pkg/scanner/network — pure stdlib, target-local)
//   2. Horus vuln scan  (pkg/scanners — pure stdlib manifest matching)
//   3. Horus secret scan (pkg/scanners — entropy/regex, no network)
//
// Network scope policy (controlled by KHEPRA_MODE / KHEPRA_NETWORK_POLICY):
//   sovereign / ironbank → LAN only (RFC 1918 + loopback). Internet IPs blocked.
//   edge / hybrid        → Unrestricted (MCP runs on Fly.io, cloud context).
//
// Wiring in production (cmd/khepra-mcp/main.go):
//
//	cfg := config.LoadRuntime()
//	sonarLane := ert.NewSonarLane(ert.SonarLaneConfig{
//	    NetworkPolicy: cfg.NetworkPolicy,
//	})
//	orch.RegisterLane(sonarLane)

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/audit"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/config"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/scanner/network"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/scanners"
)

// LaneSonar is the ERT lane constant for Sonar.
const LaneSonar ScanLane = "sonar"

// SonarLaneConfig configures a SonarLane instance.
type SonarLaneConfig struct {
	// NetworkPolicy controls what targets are reachable.
	// Defaults to NetworkPolicyLAN (safe for sovereign bare-metal deployments).
	NetworkPolicy config.NetworkPolicy

	// Ports overrides the default CommonPorts() list for port scanning.
	// Leave nil to use the defaults from pkg/scanner/network.
	Ports []int

	// ScanTimeout overrides the per-scan dial timeout (default: 2s per port).
	ScanTimeout time.Duration

	// MaxConcurrency limits the TCP connect goroutine fan-out (default: 50).
	MaxConcurrency int
}

// SonarLane performs local network/surface scanning:
//
//  1. TCP port scan    (pkg/scanner/network — pure stdlib)
//  2. Horus vulnerability scan (pkg/scanners — pure stdlib manifest matching)
//  3. Horus secret scan (pkg/scanners — pure stdlib entropy/regex)
//
// No external API calls are ever made. OSINT enrichment has been permanently removed.
// Network scope is enforced by NetworkPolicy — sovereign mode restricts to LAN targets.
type SonarLane struct {
	cfg SonarLaneConfig
}

// NewSonarLane creates a SonarLane with the given configuration.
func NewSonarLane(cfg SonarLaneConfig) *SonarLane {
	if cfg.MaxConcurrency <= 0 {
		cfg.MaxConcurrency = 50
	}
	if cfg.ScanTimeout <= 0 {
		cfg.ScanTimeout = 2 * time.Second
	}
	if cfg.NetworkPolicy == "" {
		cfg.NetworkPolicy = config.NetworkPolicyLAN // safe default
	}
	return &SonarLane{cfg: cfg}
}

// Name returns the lane identifier.
func (l *SonarLane) Name() ScanLane { return LaneSonar }

// Run executes the Sonar scan pipeline.
//
// Target resolution:
//   - req.ImageRef set → treated as a network target (host/IP/URL); port scan runs.
//   - req.TargetPath only → filesystem target; port scan is skipped (Horus only).
func (l *SonarLane) Run(ctx context.Context, req ScanRequest) ([]UnifiedFinding, error) {
	isNetworkTarget := req.ImageRef != ""
	target := req.ImageRef
	if target == "" {
		target = req.TargetPath
	}
	if target == "" {
		return nil, fmt.Errorf("sonar lane: target required")
	}

	// ── Network policy enforcement ────────────────────────────────────────────
	if isNetworkTarget {
		if err := l.enforceNetworkPolicy(target); err != nil {
			return nil, err
		}
	}

	log.Printf("[SONAR-LANE] Starting scan for: %s (network_mode=%v, policy=%s)",
		target, isNetworkTarget, l.cfg.NetworkPolicy)

	var (
		mu       sync.Mutex
		findings []UnifiedFinding
		wg       sync.WaitGroup
	)

	// ── 1. Port scan (network targets only) ──────────────────────────────────
	if isNetworkTarget {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ports := l.cfg.Ports
			if len(ports) == 0 {
				ports = network.CommonPorts()
			}
			scanner := network.NewScanner(target, ports)
			scanner.Timeout = l.cfg.ScanTimeout
			scanner.Threads = l.cfg.MaxConcurrency

			results := scanner.Scan(ctx)
			pf := portResultsToFindings(target, results)
			mu.Lock()
			findings = append(findings, pf...)
			mu.Unlock()
			log.Printf("[SONAR-LANE] Port scan: %d open ports", len(results))
		}()
	}

	// ── 2. Horus vulnerability scan (filesystem path) ────────────────────────
	scanPath := req.TargetPath
	if scanPath != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			vulns, err := scanners.RunBuiltInVulnerabilityScan(scanPath)
			if err != nil {
				log.Printf("[SONAR-LANE] WARN: Horus vuln scan error: %v", err)
				return
			}
			vf := horusVulnsToFindings(vulns, target)
			mu.Lock()
			findings = append(findings, vf...)
			mu.Unlock()
			log.Printf("[SONAR-LANE] Horus vuln: %d findings", len(vulns))
		}()

		// ── 3. Horus secret scan ──────────────────────────────────────────────
		wg.Add(1)
		go func() {
			defer wg.Done()
			secrets, err := scanners.RunBuiltInSecretScan(scanPath)
			if err != nil {
				log.Printf("[SONAR-LANE] WARN: Horus secret scan error: %v", err)
				return
			}
			sf := horusSecretsToFindings(secrets, target)
			mu.Lock()
			findings = append(findings, sf...)
			mu.Unlock()
			log.Printf("[SONAR-LANE] Horus secrets: %d findings", len(secrets))
		}()
	}

	wg.Wait()
	log.Printf("[SONAR-LANE] Complete: %d total findings for %s", len(findings), target)
	return findings, nil
}

// enforceNetworkPolicy blocks internet-routable targets in sovereign/ironbank mode.
// Returns nil if the target is allowed under the configured policy.
func (l *SonarLane) enforceNetworkPolicy(target string) error {
	if l.cfg.NetworkPolicy == config.NetworkPolicyUnrestricted {
		return nil // SaaS mode — no restrictions
	}

	// Resolve the target to an IP for policy evaluation
	host := target
	if h, _, err := net.SplitHostPort(target); err == nil {
		host = h // strip port if present
	}
	// Strip scheme if present (e.g. "http://192.168.1.1")
	if len(host) > 7 && host[:7] == "http://" {
		host = host[7:]
	}
	if len(host) > 8 && host[:8] == "https://" {
		host = host[8:]
	}

	ips, err := net.LookupHost(host)
	if err != nil {
		// If we can't resolve it, allow the attempt — the scan will fail naturally
		return nil
	}

	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}
		if l.cfg.NetworkPolicy == config.NetworkPolicyLocalOnly && !ip.IsLoopback() {
			return fmt.Errorf("[SONAR] sovereign/local-only policy: target %q resolved to %s (non-loopback blocked). Set KHEPRA_NETWORK_POLICY=lan or KHEPRA_MODE=edge to allow LAN/internet targets", target, ip)
		}
		if l.cfg.NetworkPolicy == config.NetworkPolicyLAN && !isPrivateOrLoopback(ip) {
			return fmt.Errorf("[SONAR] sovereign/lan policy: target %q resolved to %s (internet-routable addresses blocked in air-gap mode). Set KHEPRA_NETWORK_POLICY=unrestricted or KHEPRA_MODE=edge for internet targets", target, ip)
		}
	}
	return nil
}

// isPrivateOrLoopback returns true if ip is in RFC 1918, RFC 4193, or loopback.
func isPrivateOrLoopback(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"fc00::/7", // IPv6 ULA
	}
	for _, cidr := range privateRanges {
		_, network, _ := net.ParseCIDR(cidr)
		if network != nil && network.Contains(ip) {
			return true
		}
	}
	return false
}

// ─────────────────────────────────────────────────────────────────────────────
// Conversion helpers — all pure functions, no external imports
// ─────────────────────────────────────────────────────────────────────────────

func portResultsToFindings(host string, results []network.PortResult) []UnifiedFinding {
	now := time.Now().UTC()
	findings := make([]UnifiedFinding, 0, len(results))

	// Skip universally expected ports to reduce noise
	noisePorts := map[int]bool{80: true, 443: true}

	for _, r := range results {
		if noisePorts[r.Port] {
			continue
		}
		sev := portSeverity(r.Port)
		findings = append(findings, UnifiedFinding{
			ID:       fmt.Sprintf("sonar:port:%s:%d", host, r.Port),
			Source:   "sonar",
			Category: CategoryMisconfigure,
			Severity: sev,
			Title:    fmt.Sprintf("Open port %d/%s on %s", r.Port, r.Service, host),
			Description: fmt.Sprintf(
				"Service %q is reachable on %s:%d. Banner: %q",
				r.Service, host, r.Port, truncateBanner(r.Banner, 200)),
			Asset:    host,
			Location: fmt.Sprintf("tcp:%d", r.Port),
			Remediation: fmt.Sprintf(
				"Verify port %d is intentionally exposed. Apply firewall rules per NIST 800-171 3.13.1 / CIS Benchmark.",
				r.Port),
			Evidence: map[string]interface{}{
				"port":    r.Port,
				"service": r.Service,
				"banner":  truncateBanner(r.Banner, 200),
				"state":   r.State,
			},
			Timestamp: now,
			Raw:       r,
		})
	}
	return findings
}

func horusVulnsToFindings(vulns []audit.Vulnerability, networkCtx string) []UnifiedFinding {
	now := time.Now().UTC()
	out := make([]UnifiedFinding, 0, len(vulns))
	for _, v := range vulns {
		out = append(out, UnifiedFinding{
			ID:          fmt.Sprintf("sonar:vuln:%s:%s", v.Package, v.ID),
			Source:      "sonar",
			Category:    CategoryVulnerability,
			Severity:    v.Severity,
			Title:       fmt.Sprintf("%s in %s@%s", v.ID, v.Package, v.Version),
			Description: v.Description,
			Asset:       v.Package,
			Location:    v.Artifact,
			CVEID:       v.ID,
			CVSSv3:      v.CVSS,
			Evidence: map[string]interface{}{
				"version":     v.Version,
				"fixed_in":    v.FixedIn,
				"references":  v.References,
				"network_ctx": networkCtx,
			},
			Timestamp: now,
			Raw:       v,
		})
	}
	return out
}

func horusSecretsToFindings(secrets []audit.SecretFinding, networkCtx string) []UnifiedFinding {
	now := time.Now().UTC()
	out := make([]UnifiedFinding, 0, len(secrets))
	for _, s := range secrets {
		sev := "HIGH"
		if s.Type == "Private Key" || s.Type == "AWS Key" {
			sev = "CRITICAL"
		}
		out = append(out, UnifiedFinding{
			ID:          fmt.Sprintf("sonar:secret:%s:%d", s.File, s.Line),
			Source:      "sonar",
			Category:    CategorySecret,
			Severity:    sev,
			Title:       fmt.Sprintf("%s detected in %s", s.Type, s.File),
			Description: s.Description,
			Asset:       s.File,
			Location:    fmt.Sprintf("line:%d", s.Line),
			SecretType:  s.Type,
			Entropy:     s.Entropy,
			Redacted:    s.Redacted,
			Remediation: "Rotate immediately. Remove from version control. Use a secrets manager.",
			Evidence: map[string]interface{}{
				"file":        s.File,
				"line":        s.Line,
				"type":        s.Type,
				"entropy":     s.Entropy,
				"network_ctx": networkCtx,
			},
			Timestamp: now,
			Raw:       s,
		})
	}
	return out
}

// ─────────────────────────────────────────────────────────────────────────────
// Port risk classification
// ─────────────────────────────────────────────────────────────────────────────

var highRiskSonarPorts = map[int]bool{
	21: true, 23: true, 135: true, 139: true, 445: true,
	1433: true, 1521: true, 3306: true, 3389: true,
	5432: true, 5900: true, 6379: true, 27017: true,
}

var mediumRiskSonarPorts = map[int]bool{
	22: true, 25: true, 53: true,
	8080: true, 8443: true, 8888: true,
	2375: true, 2376: true,
	9200: true, 9300: true, 5601: true,
	6443: true, 2379: true, 2380: true,
}

func portSeverity(port int) string {
	if highRiskSonarPorts[port] {
		return "HIGH"
	}
	if mediumRiskSonarPorts[port] {
		return "MEDIUM"
	}
	return "LOW"
}

func truncateBanner(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
