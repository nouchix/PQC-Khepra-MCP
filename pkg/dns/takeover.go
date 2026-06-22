package dns

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// takeoverSignature fingerprints a cloud provider whose dangling CNAMEs are
// commonly abused for subdomain takeover: the CNAME suffix that identifies
// the provider, and a body/status fingerprint indicating "this resource is
// unclaimed" rather than an active, owned service.
type takeoverSignature struct {
	Provider    string
	CNAMESuffix string
	BodyMarkers []string
}

var takeoverSignatures = []takeoverSignature{
	{"GitHub Pages", "github.io", []string{"There isn't a GitHub Pages site here"}},
	{"Heroku", "herokuapp.com", []string{"no-such-app", "There's nothing here"}},
	{"AWS S3", "s3.amazonaws.com", []string{"NoSuchBucket", "The specified bucket does not exist"}},
	{"AWS S3", "s3-website", []string{"NoSuchBucket", "The specified bucket does not exist"}},
	{"Azure", "azurewebsites.net", []string{"Error 404 - Web app not found", "404 Web Site not found"}},
	{"Azure Cloud", "cloudapp.net", []string{"Error 404 - Web app not found"}},
	{"Fastly", "fastly.net", []string{"Fastly error: unknown domain"}},
	{"Shopify", "myshopify.com", []string{"Sorry, this shop is currently unavailable"}},
	{"Pantheon", "pantheonsite.io", []string{"The gods are wise", "404 error unknown site"}},
	{"WordPress.com", "wordpress.com", []string{"Do you want to register"}},
	{"Zendesk", "zendesk.com", []string{"Help Center Closed"}},
	{"Tumblr", "tumblr.com", []string{"Whatever you were looking for doesn't currently exist"}},
	{"Surge.sh", "surge.sh", []string{"project not found"}},
	{"Netlify", "netlify.app", []string{"Not Found - Request ID"}},
	{"Vercel", "vercel-dns.com", []string{"DEPLOYMENT_NOT_FOUND"}},
	{"Cargo Collective", "cargocollective.com", []string{"404 Not Found"}},
	{"UserVoice", "uservoice.com", []string{"This UserVoice subdomain is currently available"}},
	{"Help Scout", "helpscoutdocs.com", []string{"No settings were found for this company"}},
	{"Bitbucket", "bitbucket.io", []string{"Repository not found"}},
	{"Unbounce", "unbouncepages.com", []string{"The requested URL was not found on this server"}},
	{"Desk", "desk.com", []string{"Sorry, We Couldn't Find That Page"}},
	{"Acquia", "acquia-test.co", []string{"Web Site Not Found"}},
}

// TakeoverFinding flags a subdomain whose CNAME points at a deprovisioned
// or never-claimed cloud resource — an attacker can often register the same
// resource name and serve content under the victim's own domain.
type TakeoverFinding struct {
	Subdomain  string `json:"subdomain"`
	CNAME      string `json:"cname"`
	Provider   string `json:"provider"`
	Confidence string `json:"confidence"` // "confirmed" | "suspected"
	Evidence   string `json:"evidence,omitempty"`
}

// DetectTakeover inspects each resolved subdomain's CNAME against known
// dangling-resource fingerprints and, where the CNAME points at a recognized
// provider, fetches the HTTP response to confirm the resource is unclaimed.
func DetectTakeover(ctx context.Context, results []SubdomainResult, timeout time.Duration) []TakeoverFinding {
	if timeout <= 0 {
		timeout = 6 * time.Second
	}
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			// DialContext re-resolves the host itself and rejects any
			// non-public address immediately before the TCP connection is
			// made — this is the actual SSRF barrier (closes the DNS-
			// rebinding TOCTOU window that a separate pre-check would
			// leave open), not just an early-exit optimization.
			DialContext: safeDialContext,
			// Enforce standard TLS verification (certificate chain and
			// hostname) for HTTPS requests.
			TLSClientConfig: &tls.Config{},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	var findings []TakeoverFinding
	for _, r := range results {
		if r.CNAME == "" {
			continue
		}
		sig := matchSignature(r.CNAME)
		if sig == nil {
			continue
		}

		finding := TakeoverFinding{
			Subdomain:  r.Subdomain,
			CNAME:      r.CNAME,
			Provider:   sig.Provider,
			Confidence: "suspected",
			Evidence:   "CNAME points at " + sig.Provider + " but target hostname does not resolve or NXDOMAINs",
		}

		// CNAME itself doesn't resolve at all -> dangling, high confidence.
		if _, err := net.LookupHost(r.CNAME); err != nil {
			finding.Confidence = "confirmed"
			finding.Evidence = "CNAME target " + r.CNAME + " does not resolve (NXDOMAIN) — classic dangling-CNAME takeover"
			findings = append(findings, finding)
			continue
		}

		// Resolves, but check the body fingerprint over HTTP(S).
		body := fetchBody(ctx, client, r.Subdomain)
		if body == "" {
			findings = append(findings, finding)
			continue
		}
		for _, marker := range sig.BodyMarkers {
			if strings.Contains(body, marker) {
				finding.Confidence = "confirmed"
				finding.Evidence = "HTTP response contains provider marker: " + marker
				break
			}
		}
		findings = append(findings, finding)
	}
	return findings
}

// safeDialContext is an http.Transport.DialContext replacement that blocks
// connections to private, loopback, link-local, or unspecified addresses.
// Validating at dial time (rather than via an earlier net.LookupHost check)
// closes the DNS-rebinding TOCTOU window: the address checked here is the
// exact address the connection is made to, with no gap for the name to
// re-resolve to an internal target in between.
func safeDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	for _, ip := range ips {
		if ip.IP.IsPrivate() || ip.IP.IsLoopback() || ip.IP.IsLinkLocalUnicast() ||
			ip.IP.IsLinkLocalMulticast() || ip.IP.IsUnspecified() {
			return nil, fmt.Errorf("refusing to dial non-public address %s for host %s", ip.IP, host)
		}
	}
	dialer := &net.Dialer{}
	return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].IP.String(), port))
}

func matchSignature(cname string) *takeoverSignature {
	lower := strings.ToLower(cname)
	for i := range takeoverSignatures {
		if strings.Contains(lower, takeoverSignatures[i].CNAMESuffix) {
			return &takeoverSignatures[i]
		}
	}
	return nil
}

// fetchBody issues a confirmation request to a subdomain that was already
// discovered via this package's own enumeration. The client's DialContext
// (safeDialContext) is the actual SSRF barrier — it validates the resolved
// address immediately before connecting.
func fetchBody(ctx context.Context, client *http.Client, host string) string {
	for _, scheme := range []string{"https://", "http://"} {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, scheme+host+"/", nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		buf := make([]byte, 4096)
		n, _ := resp.Body.Read(buf)
		resp.Body.Close()
		if n > 0 {
			return string(buf[:n])
		}
	}
	return ""
}
