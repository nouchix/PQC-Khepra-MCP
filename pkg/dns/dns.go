// Package dns provides live DNS visibility: full record-set enumeration,
// subdomain discovery, DNSSEC presence checks, zone-transfer (AXFR) testing,
// dangling-CNAME subdomain-takeover detection, and SPF/DMARC/DKIM email
// security analysis.
//
// Zero external API calls: every lookup goes directly to either the system
// resolver (net.Resolver) or, for record types Go's stdlib does not expose
// (CAA, SOA, NS-targeted AXFR), a minimal RFC 1035 client built on net.Dial.
// No Shodan/Censys/crt.sh/3rd-party SaaS calls — matches the Sonar lane's
// "zero external dependencies" posture.
package dns

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// RecordSet holds every DNS record type collected for a single domain.
type RecordSet struct {
	Domain string   `json:"domain"`
	A      []string `json:"a,omitempty"`
	AAAA   []string `json:"aaaa,omitempty"`
	CNAME  string   `json:"cname,omitempty"`
	NS     []string `json:"ns,omitempty"`
	MX     []MXRecord `json:"mx,omitempty"`
	TXT    []string `json:"txt,omitempty"`
	SRV    []SRVRecord `json:"srv,omitempty"`
	CAA    []CAARecord `json:"caa,omitempty"`
	SOA    *SOARecord `json:"soa,omitempty"`
	Errors []string `json:"errors,omitempty"`
}

// MXRecord is a mail-exchange record.
type MXRecord struct {
	Host string `json:"host"`
	Pref uint16 `json:"pref"`
}

// SRVRecord is a service record.
type SRVRecord struct {
	Target   string `json:"target"`
	Port     uint16 `json:"port"`
	Priority uint16 `json:"priority"`
	Weight   uint16 `json:"weight"`
}

// CAARecord restricts which CAs may issue certs for a domain.
type CAARecord struct {
	Flag  uint8  `json:"flag"`
	Tag   string `json:"tag"`
	Value string `json:"value"`
}

// SOARecord is the start-of-authority record for a zone.
type SOARecord struct {
	PrimaryNS  string `json:"primary_ns"`
	AdminEmail string `json:"admin_email"`
	Serial     uint32 `json:"serial"`
	Refresh    uint32 `json:"refresh"`
	Retry      uint32 `json:"retry"`
	Expire     uint32 `json:"expire"`
	MinimumTTL uint32 `json:"minimum_ttl"`
}

// Resolver performs DNS enumeration against either the system resolver or
// an explicit upstream nameserver (host:port form, e.g. "1.1.1.1:53").
type Resolver struct {
	// Upstream, if set, is queried directly via the raw RFC 1035 client
	// (needed for CAA/SOA and for AXFR against a specific authoritative NS).
	// If empty, A/AAAA/CNAME/NS/MX/TXT/SRV use the system resolver and
	// CAA/SOA fall back to the domain's own authoritative NS.
	Upstream string
	Timeout  time.Duration
}

// NewResolver creates a Resolver with sane defaults.
func NewResolver() *Resolver {
	return &Resolver{Timeout: 5 * time.Second}
}

// Enumerate collects the full record set for domain using the system
// resolver for standard types and the raw client for CAA/SOA.
func (r *Resolver) Enumerate(ctx context.Context, domain string) *RecordSet {
	if r.Timeout <= 0 {
		r.Timeout = 5 * time.Second
	}
	domain = strings.TrimSuffix(domain, ".")
	rs := &RecordSet{Domain: domain}

	sysResolver := net.DefaultResolver
	ctx, cancel := context.WithTimeout(ctx, r.Timeout)
	defer cancel()

	if ips, err := sysResolver.LookupIPAddr(ctx, domain); err == nil {
		for _, ip := range ips {
			if ip.IP.To4() != nil {
				rs.A = append(rs.A, ip.IP.String())
			} else {
				rs.AAAA = append(rs.AAAA, ip.IP.String())
			}
		}
	} else {
		rs.Errors = append(rs.Errors, fmt.Sprintf("A/AAAA lookup: %v", err))
	}

	if cname, err := sysResolver.LookupCNAME(ctx, domain); err == nil {
		cname = strings.TrimSuffix(cname, ".")
		if cname != domain {
			rs.CNAME = cname
		}
	}

	if nss, err := sysResolver.LookupNS(ctx, domain); err == nil {
		for _, ns := range nss {
			rs.NS = append(rs.NS, strings.TrimSuffix(ns.Host, "."))
		}
		sort.Strings(rs.NS)
	} else {
		rs.Errors = append(rs.Errors, fmt.Sprintf("NS lookup: %v", err))
	}

	if mxs, err := sysResolver.LookupMX(ctx, domain); err == nil {
		for _, mx := range mxs {
			rs.MX = append(rs.MX, MXRecord{Host: strings.TrimSuffix(mx.Host, "."), Pref: mx.Pref})
		}
	}

	if txts, err := sysResolver.LookupTXT(ctx, domain); err == nil {
		rs.TXT = txts
	}

	if _, srvs, err := sysResolver.LookupSRV(ctx, "", "", domain); err == nil {
		for _, s := range srvs {
			rs.SRV = append(rs.SRV, SRVRecord{
				Target:   strings.TrimSuffix(s.Target, "."),
				Port:     s.Port,
				Priority: s.Priority,
				Weight:   s.Weight,
			})
		}
	}

	// CAA/SOA require a raw query — stdlib has no LookupCAA/LookupSOA.
	target := r.Upstream
	if target == "" && len(rs.NS) > 0 {
		if addrs, err := sysResolver.LookupHost(ctx, rs.NS[0]); err == nil && len(addrs) > 0 {
			target = net.JoinHostPort(addrs[0], "53")
		}
	}
	if target != "" {
		if caa, err := queryCAA(ctx, target, domain); err == nil {
			rs.CAA = caa
		}
		if soa, err := querySOA(ctx, target, domain); err == nil {
			rs.SOA = soa
		}
	}

	return rs
}

// EnumerateMany runs Enumerate concurrently across multiple domains/hosts.
func (r *Resolver) EnumerateMany(ctx context.Context, domains []string, concurrency int) map[string]*RecordSet {
	if concurrency <= 0 {
		concurrency = 20
	}
	out := make(map[string]*RecordSet, len(domains))
	var mu sync.Mutex
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for _, d := range domains {
		wg.Add(1)
		sem <- struct{}{}
		go func(domain string) {
			defer wg.Done()
			defer func() { <-sem }()
			rs := r.Enumerate(ctx, domain)
			mu.Lock()
			out[domain] = rs
			mu.Unlock()
		}(d)
	}
	wg.Wait()
	return out
}
