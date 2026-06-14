package apiserver

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/compliance"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/connectors"
)

const nemoClawNamePrefix = "NemoClaw @ "

// parseScanTarget returns host and ports to probe from a user-entered target (URL, host, or host:port).
func parseScanTarget(raw string) (host string, ports []int) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", []int{18789}
	}
	if h, p, ok := parseAsURL(raw); ok {
		return h, p
	}
	if h, pStr, err := net.SplitHostPort(raw); err == nil {
		if pn, _ := strconv.Atoi(pStr); pn > 0 {
			return h, []int{pn}
		}
	}
	// Default: common agent gateway + HTTPS (readiness-style surface check)
	return raw, []int{18789, 443}
}

// parseAsURL attempts to parse raw as an HTTP(S) URL and extract host/ports.
func parseAsURL(raw string) (string, []int, bool) {
	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
		return "", nil, false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", nil, false
	}
	h, pStr, err := net.SplitHostPort(u.Host)
	if err != nil {
		// No explicit port in the URL.
		if u.Scheme == "https" {
			return u.Host, []int{443, 18789}, true
		}
		return u.Host, []int{80, 18789}, true
	}
	if pn, _ := strconv.Atoi(pStr); pn > 0 {
		return h, []int{pn}, true
	}
	return h, []int{18789}, true
}

func tcpOpen(host string, port int, d time.Duration) bool {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, d)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// runASAFOnboardingScan completes a scan record using real TCP probes and optional local NemoClaw policy audit.
func runASAFOnboardingScan(scanID string, req ScanRequest) {
	time.Sleep(1200 * time.Millisecond)

	host, ports := parseScanTarget(req.TargetURL)
	if host == "" {
		markScanFailed(scanID, "Invalid or empty target host.")
		return
	}

	findings, gatewayExposed, openCount := probePorts(host, ports)
	findings = append(findings, enrichFromExternalAPIs(host)...)

	platform, totalChecks, passCount, failCount, nemoFindings := auditNemoClawAgents()
	findings = append(findings, nemoFindings...)

	if strings.EqualFold(strings.TrimSpace(req.Profile), "nemoclaw") && platform != "nemoclaw" {
		findings = append(findings, ScanFindingItem{
			Severity: "medium",
			Text:     "Profile NemoClaw requested but no local NemoClaw/OpenShell config was discovered on this host. Run assessment on the machine that holds ~/.nemoclaw (or use a deployed agent) for NMC-001–NMC-009 results.",
		})
	}

	findings = append(findings, ScanFindingItem{
		Severity: "medium",
		Text:     "CMMC / NIST 800-171 readiness: align logs, configuration exports, and change records into a single assessor-ready evidence package (traceability for C3PAO intake).",
	})

	if openCount == 0 && platform != "nemoclaw" {
		findings = append(findings, ScanFindingItem{
			Severity: "low",
			Text:     "Default probe ports (18789 / 443) did not accept TCP from this scanner — validate that scope matches your boundary (internal-only services will not appear as open from an external scanner).",
		})
	}

	risk := computeRiskScore(gatewayExposed, openCount, findings)
	finalizeScan(scanID, req, findings, platform, totalChecks, passCount, failCount, gatewayExposed, openCount, risk)
}

// markScanFailed sets a scan record to the failed state with a single finding.
func markScanFailed(scanID, reason string) {
	commandCenter.mu.Lock()
	defer commandCenter.mu.Unlock()
	s := commandCenter.scans[scanID]
	if s == nil {
		return
	}
	now := time.Now()
	s.EndTime = &now
	s.Status = StatusFailed
	s.PresentationFindings = []ScanFindingItem{
		{Severity: "high", Text: reason},
	}
	s.RiskScore = 0
}

// probePorts performs TCP probes against each port and returns findings plus summary counters.
func probePorts(host string, ports []int) (findings []ScanFindingItem, gatewayExposed bool, openCount int) {
	for _, p := range ports {
		if !tcpOpen(host, p, 2*time.Second) {
			continue
		}
		openCount++
		if p == 18789 {
			gatewayExposed = true
			findings = append(findings, ScanFindingItem{
				Severity: "critical",
				Text: fmt.Sprintf(
					"TCP %s:%d accepted a connection from this scanner — treat as potentially exposed agent-style surface. Verify authentication, binding, and firewall policy before handling CUI.",
					host, p,
				),
			})
		} else {
			findings = append(findings, ScanFindingItem{
				Severity: "high",
				Text:   fmt.Sprintf("Port %d on %s is reachable from the scan origin — confirm intended exposure.", p, host),
			})
		}
	}
	return findings, gatewayExposed, openCount
}

// enrichFromExternalAPIs queries Shodan and APIVoid if the respective API keys are configured.
func enrichFromExternalAPIs(host string) []ScanFindingItem {
	var findings []ScanFindingItem
	if key := os.Getenv("SHODAN_API_KEY"); key != "" {
		findings = append(findings, enrichWithShodan(host, key)...)
	}
	if key := os.Getenv("APIVOID_API_KEY"); key != "" {
		findings = append(findings, enrichWithAPIVoid(host, key)...)
	}
	return findings
}

// auditNemoClawAgents discovers and audits any local NemoClaw agents, returning
// platform type, check counters, and compliance findings.
func auditNemoClawAgents() (platform string, totalChecks, passCount, failCount int, findings []ScanFindingItem) {
	platform = "generic"
	nc := connectors.NewNemoClawConnector()
	agents, _ := nc.DiscoverAgents()
	for _, a := range agents {
		if a.AgentType != "nemoclaw-openshell" {
			continue
		}
		platform = "nemoclaw"
		dir := strings.TrimPrefix(a.Name, nemoClawNamePrefix)
		dir = strings.TrimSpace(dir)
		if dir == "" {
			continue
		}
		rpt, err := compliance.AuditNemoClawDeployment(dir)
		if err != nil || rpt == nil {
			findings = append(findings, nemoClawAuditErrorFinding(dir, err))
			continue
		}
		totalChecks = len(rpt.Results)
		passCount = rpt.PassCount
		failCount = rpt.FailCount
		findings = append(findings, classifyComplianceResults(rpt.Results)...)
	}
	return platform, totalChecks, passCount, failCount, findings
}

// nemoClawAuditErrorFinding builds a finding for a failed NemoClaw audit.
func nemoClawAuditErrorFinding(dir string, err error) ScanFindingItem {
	msg := "unknown error"
	if err != nil {
		msg = err.Error()
	}
	return ScanFindingItem{
		Severity: "medium",
		Text:     fmt.Sprintf("NemoClaw config at %s could not be fully audited: %s", dir, msg),
	}
}

// classifyComplianceResults converts compliance audit results into scan findings.
func classifyComplianceResults(results []compliance.NemoClawAuditResult) []ScanFindingItem {
	var findings []ScanFindingItem
	for _, r := range results {
		switch r.Status {
		case compliance.StatusPass:
			continue
		case compliance.StatusFail:
			findings = append(findings, ScanFindingItem{
				Severity: "high",
				Text:     fmt.Sprintf("%s (%s): %s — %s", r.CheckID, r.Domain, r.Title, r.Detail),
			})
		case compliance.StatusError:
			findings = append(findings, ScanFindingItem{
				Severity: "medium",
				Text:     fmt.Sprintf("%s (%s): %s — %s", r.CheckID, r.Domain, r.Title, r.Detail),
			})
		default:
			findings = append(findings, ScanFindingItem{
				Severity: "medium",
				Text:     fmt.Sprintf("%s: %s", r.CheckID, r.Title),
			})
		}
	}
	return findings
}

// finalizeScan writes the completed results back into the scan registry.
func finalizeScan(scanID string, req ScanRequest, findings []ScanFindingItem,
	platform string, totalChecks, passCount, failCount int,
	gatewayExposed bool, openCount, risk int) {

	commandCenter.mu.Lock()
	defer commandCenter.mu.Unlock()
	s := commandCenter.scans[scanID]
	if s == nil {
		return
	}
	now := time.Now()
	s.EndTime = &now
	s.Status = StatusCompleted
	s.Framework = req.ScanType
	s.TotalChecks = totalChecks
	s.PassedChecks = passCount
	s.FailedChecks = failCount
	s.GatewayExposed = gatewayExposed
	s.RiskScore = risk
	s.AuthWeaknessHeuristic = gatewayExposed
	s.OpenIntegrations = openCount
	s.PresentationFindings = findings
	s.Platform = platform
	s.Certified = false
}

func computeRiskScore(gatewayExposed bool, openCount int, findings []ScanFindingItem) int {
	score := 28
	if gatewayExposed {
		score += 42
	} else if openCount > 0 {
		score += 22
	}
	for _, f := range findings {
		switch f.Severity {
		case "critical":
			score += 12
		case "high":
			score += 8
		case "medium":
			score += 4
		case "low":
			score += 1
		}
	}
	if score > 100 {
		return 100
	}
	if score < 5 {
		return 5
	}
	return score
}

// ── Shodan enrichment ─────────────────────────────────────────────────────────

// shodanHostResponse is the minimal shape of GET https://api.shodan.io/shodan/host/{ip}.
type shodanHostResponse struct {
	IP      string `json:"ip_str"`
	Org     string `json:"org"`
	Country string `json:"country_name"`
	Ports   []int  `json:"ports"`
	Vulns   map[string]struct {
		CVSS    float64 `json:"cvss"`
		Summary string  `json:"summary"`
	} `json:"vulns"`
	Data []struct {
		Port    int    `json:"port"`
		Product string `json:"product"`
		Version string `json:"version"`
		Banner  string `json:"banner"`
	} `json:"data"`
}

// enrichWithShodan fetches Shodan intelligence for the target host and converts
// it to ScanFindingItems. Returns an empty slice on any error (non-fatal).
func enrichWithShodan(host, apiKey string) []ScanFindingItem {
	// Resolve hostname → IP (Shodan requires IP).
	addrs, err := net.LookupHost(host)
	if err != nil || len(addrs) == 0 {
		return nil
	}
	ip := addrs[0]

	data, errFindings := fetchShodanHost(ip, apiKey)
	if data == nil {
		return errFindings
	}

	var findings []ScanFindingItem
	findings = append(findings, shodanPortFindings(host, data)...)
	findings = append(findings, shodanServiceFindings(data)...)
	findings = append(findings, shodanVulnFindings(data)...)
	return findings
}

// fetchShodanHost calls the Shodan API. On success it returns the parsed response;
// on error or non-200, it returns nil data with optional informational findings.
func fetchShodanHost(ip, apiKey string) (*shodanHostResponse, []ScanFindingItem) {
	apiURL := fmt.Sprintf("https://api.shodan.io/shodan/host/%s?key=%s", ip, apiKey)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(apiURL) //nolint:gosec
	if err != nil {
		return nil, []ScanFindingItem{{Severity: "low", Text: fmt.Sprintf("Shodan lookup failed: %v", err)}}
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// continue below
	case http.StatusForbidden, http.StatusUnauthorized:
		return nil, []ScanFindingItem{{Severity: "low", Text: "Shodan API key rejected — check SHODAN_API_KEY."}}
	case http.StatusNotFound:
		return nil, []ScanFindingItem{{Severity: "low", Text: fmt.Sprintf("Shodan: %s has no indexed scan data — host may be new or offline.", ip)}}
	default:
		return nil, nil
	}

	body, _ := io.ReadAll(resp.Body)
	var data shodanHostResponse
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, nil
	}
	return &data, nil
}

// shodanPortFindings builds findings from Shodan's global port scan results.
func shodanPortFindings(host string, data *shodanHostResponse) []ScanFindingItem {
	if len(data.Ports) == 0 {
		return nil
	}
	portStrs := make([]string, len(data.Ports))
	for i, p := range data.Ports {
		portStrs[i] = strconv.Itoa(p)
	}
	return []ScanFindingItem{{
		Severity: "medium",
		Text: fmt.Sprintf("Shodan: %s (%s, %s) has %d internet-visible ports: %s",
			host, data.Org, data.Country, len(data.Ports), strings.Join(portStrs, ", ")),
	}}
}

// shodanServiceFindings builds findings from Shodan service banners.
func shodanServiceFindings(data *shodanHostResponse) []ScanFindingItem {
	var findings []ScanFindingItem
	for _, svc := range data.Data {
		if svc.Product == "" {
			continue
		}
		version := svc.Version
		if version == "" {
			version = "unknown version"
		}
		findings = append(findings, ScanFindingItem{
			Severity: "medium",
			Text: fmt.Sprintf("Shodan: Port %d — %s %s detected. Confirm patch level.",
				svc.Port, svc.Product, version),
		})
	}
	return findings
}

// shodanVulnFindings builds findings from Shodan CVE data.
func shodanVulnFindings(data *shodanHostResponse) []ScanFindingItem {
	var findings []ScanFindingItem
	for cve, vuln := range data.Vulns {
		sev := cvssToSeverity(vuln.CVSS)
		summary := vuln.Summary
		if len(summary) > 120 {
			summary = summary[:120] + "…"
		}
		findings = append(findings, ScanFindingItem{
			Severity: sev,
			Text:     fmt.Sprintf("Shodan CVE %s (CVSS %.1f): %s", cve, vuln.CVSS, summary),
		})
	}
	return findings
}

// cvssToSeverity maps a numeric CVSS score to a severity label.
func cvssToSeverity(cvss float64) string {
	switch {
	case cvss >= 9.0:
		return "critical"
	case cvss >= 7.0:
		return "high"
	default:
		return "medium"
	}
}

// ── APIVoid domain reputation ─────────────────────────────────────────────────

// apiVoidResponse is the minimal shape of APIVoid domain blacklist response.
type apiVoidResponse struct {
	Data struct {
		Report struct {
			Blacklists struct {
				DetectionRate string `json:"detection_rate"`
				Engines       map[string]struct {
					Detected bool   `json:"detected"`
					Name     string `json:"name"`
				} `json:"engines"`
			} `json:"blacklists"`
			ServerDetails struct {
				IP      string `json:"ip"`
				Country string `json:"country_name"`
				ISP     string `json:"isp"`
			} `json:"server_details"`
		} `json:"report"`
	} `json:"data"`
}

// enrichWithAPIVoid checks the domain against APIVoid's blacklist engines.
// Returns an empty slice on any error (non-fatal).
func enrichWithAPIVoid(host, apiKey string) []ScanFindingItem {
	// APIVoid expects a domain, not an IP — strip any port.
	domain := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		domain = h
	}

	data, err := fetchAPIVoidReport(domain, apiKey)
	if err != nil {
		return []ScanFindingItem{{Severity: "low", Text: fmt.Sprintf("APIVoid lookup failed: %v", err)}}
	}
	if data == nil {
		return nil
	}

	var findings []ScanFindingItem
	findings = append(findings, classifyBlacklistHits(domain, data)...)
	findings = append(findings, apiVoidServerFinding(data)...)
	return findings
}

// fetchAPIVoidReport calls the APIVoid endpoint. Returns nil on non-200 or parse error.
func fetchAPIVoidReport(domain, apiKey string) (*apiVoidResponse, error) {
	apiURL := fmt.Sprintf(
		"https://endpoint.apivoid.com/domainbl/v1/pay-as-you-go/?key=%s&host=%s",
		apiKey, url.QueryEscape(domain),
	)
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(apiURL) //nolint:gosec
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, nil
	}

	body, _ := io.ReadAll(resp.Body)
	var data apiVoidResponse
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, nil
	}
	return &data, nil
}

// classifyBlacklistHits converts APIVoid blacklist detections into scan findings.
func classifyBlacklistHits(domain string, data *apiVoidResponse) []ScanFindingItem {
	bl := data.Data.Report.Blacklists

	if bl.DetectionRate == "" || bl.DetectionRate == "0%" {
		return []ScanFindingItem{{
			Severity: "low",
			Text:     fmt.Sprintf("APIVoid: Domain %s is clean across all blacklist engines.", domain),
		}}
	}

	hits, hitNames := countBlacklistDetections(bl.Engines)
	if hits == 0 {
		return nil
	}

	sev := "high"
	if hits >= 5 {
		sev = "critical"
	}
	return []ScanFindingItem{{
		Severity: sev,
		Text: fmt.Sprintf(
			"APIVoid: Domain %s is flagged by %d/%d security engines (%s). Immediate investigation required.",
			domain, hits, len(bl.Engines), strings.Join(hitNames[:min(3, len(hitNames))], ", ")),
	}}
}

// countBlacklistDetections tallies detection hits across APIVoid engines.
func countBlacklistDetections(engines map[string]struct {
	Detected bool   `json:"detected"`
	Name     string `json:"name"`
}) (int, []string) {
	var hits int
	var names []string
	for _, eng := range engines {
		if eng.Detected {
			hits++
			names = append(names, eng.Name)
		}
	}
	return hits, names
}

// apiVoidServerFinding builds a finding from APIVoid server detail metadata.
func apiVoidServerFinding(data *apiVoidResponse) []ScanFindingItem {
	srv := data.Data.Report.ServerDetails
	if srv.IP == "" {
		return nil
	}
	return []ScanFindingItem{{
		Severity: "low",
		Text:     fmt.Sprintf("APIVoid: Server IP %s hosted by %s (%s).", srv.IP, srv.ISP, srv.Country),
	}}
}
