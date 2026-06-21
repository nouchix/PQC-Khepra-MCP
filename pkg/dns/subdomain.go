package dns

import (
	"context"
	"net"
	"sort"
	"sync"
	"time"
)

// commonSubdomainWordlist is a built-in brute-force wordlist covering the
// prefixes most frequently seen in enterprise DNS estates. No external
// wordlist download, no CT-log/crt.sh API call — keeps subdomain discovery
// fully self-contained.
var commonSubdomainWordlist = []string{
	"www", "mail", "smtp", "pop", "imap", "webmail", "ftp", "sftp",
	"api", "api-staging", "api-dev", "api-prod", "graphql", "rest",
	"app", "apps", "portal", "dashboard", "console", "admin", "administrator",
	"staging", "stage", "dev", "develop", "development", "test", "testing", "qa", "uat", "preprod", "sandbox",
	"prod", "production", "demo", "beta", "preview", "alpha",
	"vpn", "remote", "gateway", "gw", "router", "firewall", "proxy", "lb", "loadbalancer",
	"ns1", "ns2", "ns3", "ns4", "dns", "dns1", "dns2",
	"cdn", "static", "assets", "media", "img", "images", "files", "downloads", "uploads",
	"git", "gitlab", "github", "bitbucket", "svn", "ci", "cd", "jenkins", "build", "buildkite", "drone",
	"jira", "confluence", "wiki", "docs", "support", "help", "helpdesk", "status", "statuspage",
	"db", "database", "mysql", "postgres", "pg", "mongo", "mongodb", "redis", "elastic", "elasticsearch", "kibana", "grafana", "prometheus",
	"k8s", "kube", "kubernetes", "docker", "registry", "helm",
	"auth", "sso", "login", "id", "idp", "oauth", "identity", "accounts",
	"secure", "security", "vault", "secrets", "kms", "pki", "ca",
	"internal", "intranet", "corp", "corporate", "private", "local", "lan",
	"old", "legacy", "backup", "bak", "archive", "tmp", "temp",
	"shop", "store", "checkout", "payments", "billing", "invoice",
	"blog", "news", "press", "careers", "jobs",
	"m", "mobile", "ios", "android",
	"cpanel", "webdisk", "autodiscover", "autoconfig", "ns", "mx", "mx1", "mx2",
	"jenkins", "sonar", "sonarqube", "nexus", "artifactory", "harbor",
	"vpn1", "vpn2", "office", "remote-access", "citrix", "rdp", "rdweb",
	"webmail2", "exchange", "owa", "lync", "skype", "teams",
	"crm", "erp", "hr", "finance", "accounting", "payroll",
	"monitor", "monitoring", "metrics", "logs", "logging", "syslog", "splunk", "datadog", "newrelic",
}

// SubdomainResult is a resolved subdomain finding.
type SubdomainResult struct {
	Subdomain string   `json:"subdomain"`
	IPs       []string `json:"ips,omitempty"`
	CNAME     string   `json:"cname,omitempty"`
}

// EnumerateSubdomains brute-forces the built-in wordlist (plus any extra
// words supplied) against domain and returns every subdomain that resolves.
func EnumerateSubdomains(ctx context.Context, domain string, extraWords []string, concurrency int) []SubdomainResult {
	if concurrency <= 0 {
		concurrency = 50
	}
	words := make([]string, 0, len(commonSubdomainWordlist)+len(extraWords))
	words = append(words, commonSubdomainWordlist...)
	words = append(words, extraWords...)

	resolver := net.DefaultResolver
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var found []SubdomainResult
	seen := make(map[string]bool)

	for _, w := range words {
		if w == "" || seen[w] {
			continue
		}
		seen[w] = true
		wg.Add(1)
		sem <- struct{}{}
		go func(word string) {
			defer wg.Done()
			defer func() { <-sem }()

			sub := word + "." + domain
			qctx, cancel := context.WithTimeout(ctx, 4*time.Second)
			defer cancel()

			ips, err := resolver.LookupHost(qctx, sub)
			if err != nil || len(ips) == 0 {
				return
			}
			sort.Strings(ips)
			res := SubdomainResult{Subdomain: sub, IPs: ips}
			if cname, cerr := resolver.LookupCNAME(qctx, sub); cerr == nil {
				if c := trimDot(cname); c != trimDot(sub) {
					res.CNAME = c
				}
			}
			mu.Lock()
			found = append(found, res)
			mu.Unlock()
		}(w)
	}
	wg.Wait()

	sort.Slice(found, func(i, j int) bool { return found[i].Subdomain < found[j].Subdomain })
	return found
}

func trimDot(s string) string {
	if len(s) > 0 && s[len(s)-1] == '.' {
		return s[:len(s)-1]
	}
	return s
}
