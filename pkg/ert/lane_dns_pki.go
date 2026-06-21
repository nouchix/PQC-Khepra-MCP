package ert

// lane_dns_pki.go — DNS + PKI visibility scan lane for the ERT ScanOrchestrator.
//
// Privacy-first design: ZERO external API calls (no Shodan/Censys/crt.sh).
// Every record comes from either the system resolver, a minimal native
// RFC 1035 client (pkg/dns), or a direct TLS handshake (pkg/pki).
//
// What this lane does, given a domain/host target (req.ImageRef):
//   1. Full DNS record enumeration  (A/AAAA/CNAME/NS/MX/TXT/SRV/CAA/SOA)
//   2. DNSSEC presence check        (DNSKEY/RRSIG/DS)
//   3. Zone transfer (AXFR) probe   against every authoritative nameserver
//   4. SPF/DMARC/DKIM analysis      (email spoofing exposure)
//   5. Subdomain brute-force        + dangling-CNAME takeover detection
//   6. Live TLS/PKI cert discovery  on the root domain + every resolved
//      subdomain (ports 443/8443) — feeds pkg/crypto's CBOM pipeline
//
// Network scope policy mirrors SonarLane: sovereign/ironbank → LAN only;
// edge/hybrid → unrestricted.

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/nouchix/PQC-Khepra-MCP/pkg/config"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/dns"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/pki"
)

// DNSPKILaneConfig configures a DNSPKILane instance.
type DNSPKILaneConfig struct {
	NetworkPolicy      config.NetworkPolicy
	SubdomainWordlist  []string // extra words appended to the built-in list
	SubdomainConcurrency int
	TLSPorts           []int // ports to probe for TLS/PKI; default 443, 8443
	ScanTimeout        time.Duration
}

// DNSPKILane performs live DNS + PKI surface discovery.
type DNSPKILane struct {
	cfg DNSPKILaneConfig
}

// NewDNSPKILane creates a DNSPKILane with the given configuration.
func NewDNSPKILane(cfg DNSPKILaneConfig) *DNSPKILane {
	if cfg.NetworkPolicy == "" {
		cfg.NetworkPolicy = config.NetworkPolicyLAN
	}
	if cfg.SubdomainConcurrency <= 0 {
		cfg.SubdomainConcurrency = 50
	}
	if len(cfg.TLSPorts) == 0 {
		cfg.TLSPorts = []int{443, 8443}
	}
	if cfg.ScanTimeout <= 0 {
		cfg.ScanTimeout = 6 * time.Second
	}
	return &DNSPKILane{cfg: cfg}
}

// Name returns the lane identifier.
func (l *DNSPKILane) Name() ScanLane { return LaneDNSPKI }

// Run executes the DNS + PKI discovery pipeline against req.ImageRef
// (the domain or host target). Filesystem-only requests (TargetPath set,
// ImageRef empty) produce no findings — this lane is network-only.
func (l *DNSPKILane) Run(ctx context.Context, req ScanRequest) ([]UnifiedFinding, error) {
	domain := req.ImageRef
	if domain == "" {
		return nil, nil // nothing to do for filesystem-only scans
	}

	if err := l.enforceNetworkPolicy(domain); err != nil {
		return nil, err
	}

	log.Printf("[DNS-PKI-LANE] Starting scan for: %s (policy=%s)", domain, l.cfg.NetworkPolicy)

	var (
		mu       sync.Mutex
		findings []UnifiedFinding
	)
	add := func(fs ...UnifiedFinding) {
		mu.Lock()
		findings = append(findings, fs...)
		mu.Unlock()
	}

	resolver := dns.NewResolver()
	resolver.Timeout = l.cfg.ScanTimeout

	// ── 1. DNS record enumeration ─────────────────────────────────────────────
	rs := resolver.Enumerate(ctx, domain)
	add(dnsRecordFindings(domain, rs)...)

	var wg sync.WaitGroup

	// ── 2. DNSSEC presence ────────────────────────────────────────────────────
	wg.Add(1)
	go func() {
		defer wg.Done()
		status := dns.CheckDNSSEC(ctx, domain, rs.NS, l.cfg.ScanTimeout)
		add(dnssecFinding(domain, status))
	}()

	// ── 3. Zone transfer (AXFR) probe ─────────────────────────────────────────
	wg.Add(1)
	go func() {
		defer wg.Done()
		if len(rs.NS) == 0 {
			return
		}
		results := dns.TestZoneTransfer(domain, rs.NS, l.cfg.ScanTimeout)
		add(zoneTransferFindings(domain, results)...)
	}()

	// ── 4. SPF/DMARC/DKIM ──────────────────────────────────────────────────────
	wg.Add(1)
	go func() {
		defer wg.Done()
		report := dns.AnalyzeEmailSecurity(ctx, domain)
		add(emailSecurityFindings(domain, report)...)
	}()

	// ── 5. Subdomain enumeration + takeover detection ────────────────────────
	var subdomains []dns.SubdomainResult
	wg.Add(1)
	go func() {
		defer wg.Done()
		subdomains = dns.EnumerateSubdomains(ctx, domain, l.cfg.SubdomainWordlist, l.cfg.SubdomainConcurrency)
		add(subdomainFindings(domain, subdomains)...)

		takeovers := dns.DetectTakeover(ctx, subdomains, l.cfg.ScanTimeout)
		add(takeoverFindings(domain, takeovers)...)
	}()

	wg.Wait()

	// ── 6. Live TLS/PKI discovery ─────────────────────────────────────────────
	hosts := []string{domain}
	for _, s := range subdomains {
		hosts = append(hosts, s.Subdomain)
	}
	probes := pki.ProbeHosts(hosts, l.cfg.TLSPorts, l.cfg.SubdomainConcurrency, l.cfg.ScanTimeout)
	add(tlsPKIFindings(probes)...)

	log.Printf("[DNS-PKI-LANE] Complete: %d total findings for %s", len(findings), domain)
	return findings, nil
}

// enforceNetworkPolicy mirrors SonarLane's policy check — blocks
// internet-routable targets in sovereign/air-gapped modes.
func (l *DNSPKILane) enforceNetworkPolicy(target string) error {
	if l.cfg.NetworkPolicy == config.NetworkPolicyUnrestricted {
		return nil
	}

	host := target
	if h, _, err := net.SplitHostPort(target); err == nil {
		host = h
	}

	ips, err := net.LookupHost(host)
	if err != nil {
		return nil // unresolvable — let the scan fail naturally downstream
	}

	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}
		if l.cfg.NetworkPolicy == config.NetworkPolicyLocalOnly && !ip.IsLoopback() {
			return fmt.Errorf("[DNS-PKI] sovereign/local-only policy: target %q resolved to %s (non-loopback blocked)", target, ip)
		}
		if l.cfg.NetworkPolicy == config.NetworkPolicyLAN && !isPrivateOrLoopback(ip) {
			return fmt.Errorf("[DNS-PKI] sovereign/lan policy: target %q resolved to %s (internet-routable addresses blocked in air-gap mode). Set KHEPRA_NETWORK_POLICY=unrestricted for internet targets", target, ip)
		}
	}
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Conversion helpers
// ─────────────────────────────────────────────────────────────────────────────

func dnsRecordFindings(domain string, rs *dns.RecordSet) []UnifiedFinding {
	now := time.Now().UTC()
	var out []UnifiedFinding

	if len(rs.CAA) == 0 {
		out = append(out, UnifiedFinding{
			ID:       fmt.Sprintf("dns_pki:caa:%s", domain),
			Source:   "dns_pki",
			Category: CategoryMisconfigure,
			Severity: "LOW",
			Title:    fmt.Sprintf("No CAA record for %s", domain),
			Description: "No Certificate Authority Authorization record found. Any publicly trusted CA can issue certificates for this domain.",
			Asset:    domain,
			Remediation: "Publish a CAA record restricting issuance to your authorized CA(s) (RFC 8659).",
			Timestamp: now,
		})
	}

	if len(rs.NS) < 2 {
		out = append(out, UnifiedFinding{
			ID:       fmt.Sprintf("dns_pki:ns_redundancy:%s", domain),
			Source:   "dns_pki",
			Category: CategoryMisconfigure,
			Severity: "MEDIUM",
			Title:    fmt.Sprintf("Insufficient nameserver redundancy for %s", domain),
			Description: fmt.Sprintf("Only %d authoritative nameserver(s) found. RFC 2182 recommends at least 2 geographically diverse NS.", len(rs.NS)),
			Asset:    domain,
			Remediation: "Add additional authoritative nameservers in diverse network locations.",
			Timestamp: now,
			Evidence: map[string]interface{}{"nameservers": rs.NS},
		})
	}

	for _, errMsg := range rs.Errors {
		out = append(out, UnifiedFinding{
			ID:          fmt.Sprintf("dns_pki:lookup_error:%s:%s", domain, errMsg),
			Source:      "dns_pki",
			Category:    CategoryMisconfigure,
			Severity:    "INFO",
			Title:       fmt.Sprintf("DNS lookup issue for %s", domain),
			Description: errMsg,
			Asset:       domain,
			Timestamp:   now,
		})
	}

	out = append(out, UnifiedFinding{
		ID:        fmt.Sprintf("dns_pki:inventory:%s", domain),
		Source:    "dns_pki",
		Category:  CategoryMisconfigure,
		Severity:  "INFO",
		Title:     fmt.Sprintf("DNS record inventory for %s", domain),
		Description: "Full DNS record set captured for asset inventory and blast-radius analysis.",
		Asset:     domain,
		Timestamp: now,
		Evidence: map[string]interface{}{
			"a": rs.A, "aaaa": rs.AAAA, "cname": rs.CNAME, "ns": rs.NS,
			"mx": rs.MX, "txt": rs.TXT, "srv": rs.SRV, "caa": rs.CAA, "soa": rs.SOA,
		},
		Raw: rs,
	})

	return out
}

func dnssecFinding(domain string, status dns.DNSSECStatus) UnifiedFinding {
	now := time.Now().UTC()
	if status.Enabled {
		return UnifiedFinding{
			ID:        fmt.Sprintf("dns_pki:dnssec:%s", domain),
			Source:    "dns_pki",
			Category:  CategoryCompliance,
			Severity:  "INFO",
			Title:     fmt.Sprintf("DNSSEC enabled for %s", domain),
			Description: "DNSKEY and RRSIG records present.",
			Asset:     domain,
			Framework: "NIST 800-53",
			ControlID: "SC-20",
			Timestamp: now,
		}
	}
	return UnifiedFinding{
		ID:        fmt.Sprintf("dns_pki:dnssec:%s", domain),
		Source:    "dns_pki",
		Category:  CategoryCompliance,
		Severity:  "MEDIUM",
		Title:     fmt.Sprintf("DNSSEC not enabled for %s", domain),
		Description: "No DNSKEY/RRSIG records found. The zone is vulnerable to DNS cache poisoning and response forgery.",
		Asset:     domain,
		Framework: "NIST 800-53",
		ControlID: "SC-20",
		Remediation: "Enable DNSSEC signing at the registrar/DNS provider and publish a DS record with the parent zone.",
		Timestamp: now,
		Evidence:  map[string]interface{}{"error": status.Error},
	}
}

func zoneTransferFindings(domain string, results []dns.ZoneTransferResult) []UnifiedFinding {
	now := time.Now().UTC()
	var out []UnifiedFinding
	for _, r := range results {
		if !r.Vulnerable {
			continue
		}
		out = append(out, UnifiedFinding{
			ID:       fmt.Sprintf("dns_pki:axfr:%s:%s", domain, r.Nameserver),
			Source:   "dns_pki",
			Category: CategoryMisconfigure,
			Severity: "CRITICAL",
			Title:    fmt.Sprintf("Zone transfer (AXFR) allowed on %s", r.Nameserver),
			Description: fmt.Sprintf(
				"Nameserver %s permitted an unauthenticated AXFR zone transfer, leaking %d records including internal hostnames.",
				r.Nameserver, r.RecordCount),
			Asset:    domain,
			Location: r.Nameserver,
			Remediation: "Restrict AXFR to authorized secondary nameservers only (allow-transfer ACL).",
			Framework: "NIST 800-53",
			ControlID: "SC-20",
			Evidence: map[string]interface{}{
				"record_count": r.RecordCount,
				"leaked_names": r.LeakedNames,
			},
			Timestamp: now,
		})
	}
	return out
}

func emailSecurityFindings(domain string, report dns.EmailSecurityReport) []UnifiedFinding {
	now := time.Now().UTC()
	var out []UnifiedFinding
	for _, f := range report.Findings {
		sev := "MEDIUM"
		if !report.HasSPF || !report.HasDMARC {
			sev = "HIGH"
		}
		out = append(out, UnifiedFinding{
			ID:        fmt.Sprintf("dns_pki:email_sec:%s:%d", domain, len(out)),
			Source:    "dns_pki",
			Category:  CategoryMisconfigure,
			Severity:  sev,
			Title:     fmt.Sprintf("Email authentication gap for %s", domain),
			Description: f,
			Asset:     domain,
			Framework: "NIST 800-53",
			ControlID: "SC-8",
			Remediation: "Publish SPF (-all), DMARC (p=reject), and DKIM records for all sending domains.",
			Timestamp: now,
			Evidence: map[string]interface{}{
				"spf_record": report.SPFRecord, "dmarc_record": report.DMARCRecord,
				"dkim_selectors": report.DKIMSelectors,
			},
		})
	}
	return out
}

func subdomainFindings(domain string, results []dns.SubdomainResult) []UnifiedFinding {
	now := time.Now().UTC()
	return []UnifiedFinding{{
		ID:        fmt.Sprintf("dns_pki:subdomains:%s", domain),
		Source:    "dns_pki",
		Category:  CategoryMisconfigure,
		Severity:  "INFO",
		Title:     fmt.Sprintf("%d subdomain(s) discovered for %s", len(results), domain),
		Description: "Subdomains resolved via built-in brute-force wordlist enumeration.",
		Asset:     domain,
		Timestamp: now,
		Evidence:  map[string]interface{}{"subdomains": results},
		Raw:       results,
	}}
}

func takeoverFindings(domain string, takeovers []dns.TakeoverFinding) []UnifiedFinding {
	now := time.Now().UTC()
	var out []UnifiedFinding
	for _, t := range takeovers {
		sev := "HIGH"
		if t.Confidence == "confirmed" {
			sev = "CRITICAL"
		}
		out = append(out, UnifiedFinding{
			ID:       fmt.Sprintf("dns_pki:takeover:%s", t.Subdomain),
			Source:   "dns_pki",
			Category: CategoryMisconfigure,
			Severity: sev,
			Title:    fmt.Sprintf("Possible subdomain takeover: %s -> %s (%s)", t.Subdomain, t.CNAME, t.Provider),
			Description: t.Evidence,
			Asset:    t.Subdomain,
			Location: t.CNAME,
			Remediation: "Remove the dangling CNAME or re-claim the resource at the upstream provider immediately.",
			Framework: "NIST 800-53",
			ControlID: "SC-20",
			Evidence: map[string]interface{}{
				"provider": t.Provider, "confidence": t.Confidence, "cname": t.CNAME,
			},
			Timestamp: now,
		})
	}
	return out
}

func tlsPKIFindings(probes []*pki.TLSProbeResult) []UnifiedFinding {
	now := time.Now().UTC()
	var out []UnifiedFinding
	for _, p := range probes {
		assets := p.ToCryptoAssets()
		for i, asset := range assets {
			sev := riskToSeverity(string(asset.QuantumRisk))
			out = append(out, UnifiedFinding{
				ID:       fmt.Sprintf("dns_pki:cert:%s:%d", p.Target, i),
				Source:   "dns_pki",
				Category: CategoryCompliance,
				Severity: sev,
				Title:    fmt.Sprintf("%s certificate on %s (%s, %d-bit)", asset.Algorithm, p.Target, asset.Algorithm, asset.KeyLength),
				Description: fmt.Sprintf("TLS %s / %s. Migration path: %s.", p.TLSVersion, p.CipherSuite, asset.MigrationPath),
				Asset:    p.Target,
				Framework: "NIST 800-171",
				ControlID: "3.13.11",
				Remediation: asset.MigrationPath,
				Evidence: map[string]interface{}{
					"tls_version": p.TLSVersion, "cipher_suite": p.CipherSuite,
					"self_signed": p.SelfSigned, "hostname_mismatch": p.HostnameMismatch,
					"weak_cipher": p.WeakCipher, "expired": asset.ExpirationDate.Before(now),
				},
				Raw:       asset,
				Timestamp: now,
			})
		}
		if p.WeakCipher {
			out = append(out, UnifiedFinding{
				ID:       fmt.Sprintf("dns_pki:weak_tls:%s", p.Target),
				Source:   "dns_pki",
				Category: CategoryMisconfigure,
				Severity: "HIGH",
				Title:    fmt.Sprintf("Weak TLS configuration on %s", p.Target),
				Description: fmt.Sprintf("Negotiated %s with cipher suite %s.", p.TLSVersion, p.CipherSuite),
				Asset:    p.Target,
				Framework: "NIST 800-53",
				ControlID: "SC-8",
				Remediation: "Disable TLS 1.0/1.1 and legacy cipher suites; require TLS 1.3 with modern AEAD ciphers.",
				Timestamp: now,
			})
		}
	}
	return out
}

func riskToSeverity(risk string) string {
	switch risk {
	case "CRITICAL":
		return "CRITICAL"
	case "HIGH":
		return "HIGH"
	case "MEDIUM":
		return "MEDIUM"
	case "LOW":
		return "LOW"
	case "QUANTUM_SAFE":
		return "INFO"
	default:
		return "MEDIUM"
	}
}
