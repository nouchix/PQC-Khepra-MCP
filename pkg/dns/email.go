package dns

import (
	"context"
	"net"
	"strings"
	"time"
)

// EmailSecurityReport summarizes SPF/DMARC/DKIM posture for a domain.
// Missing or weak email-auth records are a top phishing/spoofing vector and
// map directly to NIST 800-53 SC-8/SC-23 and CMMC SC domain controls.
type EmailSecurityReport struct {
	Domain        string `json:"domain"`
	SPFRecord     string `json:"spf_record,omitempty"`
	SPFPolicy     string `json:"spf_policy,omitempty"` // qualifier on "all": -all, ~all, ?all, +all
	HasSPF        bool   `json:"has_spf"`
	DMARCRecord   string `json:"dmarc_record,omitempty"`
	HasDMARC      bool   `json:"has_dmarc"`
	DMARCPolicy   string `json:"dmarc_policy,omitempty"` // none | quarantine | reject
	DKIMSelectors []string `json:"dkim_selectors_found,omitempty"`
	Findings      []string `json:"findings,omitempty"`
}

// commonDKIMSelectors covers the default selector names used by major ESPs.
var commonDKIMSelectors = []string{
	"default", "google", "selector1", "selector2", "k1", "dkim", "mail",
	"mandrill", "sendgrid", "mailgun", "amazonses", "zoho", "mx",
}

// AnalyzeEmailSecurity checks SPF, DMARC, and common DKIM selectors for domain.
func AnalyzeEmailSecurity(ctx context.Context, domain string) EmailSecurityReport {
	report := EmailSecurityReport{Domain: domain}
	resolver := net.DefaultResolver

	qctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()

	if txts, err := resolver.LookupTXT(qctx, domain); err == nil {
		for _, t := range txts {
			if strings.HasPrefix(t, "v=spf1") {
				report.HasSPF = true
				report.SPFRecord = t
				report.SPFPolicy = spfQualifier(t)
				break
			}
		}
	}
	if !report.HasSPF {
		report.Findings = append(report.Findings, "No SPF record found — domain is vulnerable to email spoofing")
	} else if report.SPFPolicy == "+all" || report.SPFPolicy == "?all" {
		report.Findings = append(report.Findings, "SPF policy is permissive ("+report.SPFPolicy+") — any host can send mail as this domain")
	}

	if txts, err := resolver.LookupTXT(qctx, "_dmarc."+domain); err == nil {
		for _, t := range txts {
			if strings.HasPrefix(t, "v=DMARC1") {
				report.HasDMARC = true
				report.DMARCRecord = t
				report.DMARCPolicy = dmarcPolicy(t)
				break
			}
		}
	}
	if !report.HasDMARC {
		report.Findings = append(report.Findings, "No DMARC record found — spoofed mail will not be rejected/quarantined")
	} else if report.DMARCPolicy == "none" {
		report.Findings = append(report.Findings, "DMARC policy is \"none\" — spoofed mail is reported but not blocked")
	}

	for _, sel := range commonDKIMSelectors {
		name := sel + "._domainkey." + domain
		if txts, err := resolver.LookupTXT(qctx, name); err == nil && len(txts) > 0 {
			report.DKIMSelectors = append(report.DKIMSelectors, sel)
		}
	}
	if len(report.DKIMSelectors) == 0 {
		report.Findings = append(report.Findings, "No DKIM selectors found among common defaults — DKIM may be absent or using a non-standard selector")
	}

	return report
}

func spfQualifier(record string) string {
	for _, mech := range []string{"-all", "~all", "?all", "+all"} {
		if strings.Contains(record, mech) {
			return mech
		}
	}
	return ""
}

func dmarcPolicy(record string) string {
	for _, part := range strings.Split(record, ";") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "p=") {
			return strings.TrimPrefix(part, "p=")
		}
	}
	return ""
}
