package dns

import (
	"context"
	"net"
	"time"
)

const (
	typeDNSKEY = 48
	typeDS     = 43
	typeRRSIG  = 46
)

// DNSSECStatus reports whether a zone publishes DNSSEC signing material.
// This is a presence check (DNSKEY/RRSIG/DS exist), not a full cryptographic
// chain-of-trust validation — that requires walking to the root and is
// flagged separately as a recommendation when DNSSEC is absent.
type DNSSECStatus struct {
	Domain        string `json:"domain"`
	Enabled       bool   `json:"enabled"`
	HasDNSKEY     bool   `json:"has_dnskey"`
	HasRRSIG      bool   `json:"has_rrsig"`
	HasDS         bool   `json:"has_ds"`
	DNSKEYCount   int    `json:"dnskey_count"`
	Error         string `json:"error,omitempty"`
}

// CheckDNSSEC queries domain's authoritative nameserver for DNSKEY/RRSIG/DS.
func CheckDNSSEC(ctx context.Context, domain string, nameservers []string, timeout time.Duration) DNSSECStatus {
	status := DNSSECStatus{Domain: domain}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	var server string
	if len(nameservers) > 0 {
		if addrs, err := net.LookupHost(nameservers[0]); err == nil && len(addrs) > 0 {
			server = net.JoinHostPort(addrs[0], "53")
		}
	}
	if server == "" {
		status.Error = "no nameserver available to query"
		return status
	}

	if msg, _, err := rawQuery(ctx, server, typeDNSKEY, domain, timeout); err == nil {
		for _, rr := range msg.Answers {
			if rr.Type == typeDNSKEY {
				status.HasDNSKEY = true
				status.DNSKEYCount++
			}
		}
	}

	if msg, _, err := rawQuery(ctx, server, typeRRSIG, domain, timeout); err == nil {
		for _, rr := range msg.Answers {
			if rr.Type == typeRRSIG {
				status.HasRRSIG = true
				break
			}
		}
	}

	if msg, _, err := rawQuery(ctx, server, typeDS, domain, timeout); err == nil {
		for _, rr := range msg.Answers {
			if rr.Type == typeDS {
				status.HasDS = true
				break
			}
		}
	}

	status.Enabled = status.HasDNSKEY && status.HasRRSIG
	return status
}
