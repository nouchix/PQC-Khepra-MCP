package dns

import (
	"context"
	"crypto/tls"
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
	Provider     string
	CNAMESuffix  string
	BodyMarkers  []string
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
	Subdomain   string `json:"subdomain"`
	CNAME       string `json:"cname"`
	Provider    string `json:"provider"`
	Confidence  string `json:"confidence"` // "confirmed" | "suspected"
	Evidence    string `json:"evidence,omitempty"`
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
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // we're probing identity, not trusting the cert
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

func matchSignature(cname string) *takeoverSignature {
	lower := strings.ToLower(cname)
	for i := range takeoverSignatures {
		if strings.Contains(lower, takeoverSignatures[i].CNAMESuffix) {
			return &takeoverSignatures[i]
		}
	}
	return nil
}

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
