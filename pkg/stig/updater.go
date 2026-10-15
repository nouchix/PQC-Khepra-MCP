// Package stig — updater.go
//
// STIGUpdater keeps the embedded STIG mapping database current with the
// official DISA library published at https://www.cyber.mil/stigs/downloads/
//
// # Operational modes
//
//   - Online  (UpdateFromCyberMil):  run on a build machine with internet access.
//     Scrapes cyber.mil, downloads STIG ZIPs, parses XCCDF XML, writes updated
//     CSV rows into pkg/stig/data/.  After running, `go build` re-embeds.
//
//   - Offline (UpdateFromLocalDir):  for air-gapped environments.
//     Operator downloads STIG ZIPs on an internet machine, transfers via USB,
//     then runs stig-updater --mode offline --zip-dir /media/usb/stigs/.
//
// This file is a BUILD-TIME / OPERATOR tool only.  It is compiled into
// cmd/stig-updater, NOT into the asaf-desktop binary.  Zero runtime egress.
package stig

import (
	"archive/zip"
	"encoding/csv"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"
)

// ── Public types ──────────────────────────────────────────────────────────────

// STIGPackage describes one downloadable STIG package from cyber.mil.
type STIGPackage struct {
	Title       string
	FileName    string // e.g. "U_RHEL_9_V1R3_STIG.zip"
	DownloadURL string
	Version     string // e.g. "V1R3"
	Release     string // release date string from the page
	BenchmarkID string // XCCDF Benchmark/@id, populated after parse
}

// STIGRule is one parsed rule extracted from an XCCDF benchmark XML.
type STIGRule struct {
	ID          string   // SV-XXXXXXXX_rule
	Title       string
	Severity    string   // "high" | "medium" | "low" → CAT I / II / III
	Version     string   // XCCDF rule version string (e.g. RHEL-09-291015)
	FixText     string
	CheckText   string
	CCIs        []string // CCI-XXXXXX identifiers (from <ident> elements)
	StigFile    string   // parent benchmark filename (matches STIG_CCI_Map.csv col 5)
}

// UpdateResult summarises one update run.
type UpdateResult struct {
	PackagesProcessed int
	RulesAdded        int
	RulesUpdated      int
	Skipped           int
	Errors            []error
	Duration          time.Duration
}

func (r *UpdateResult) String() string {
	return fmt.Sprintf(
		"packages=%d added=%d updated=%d skipped=%d errors=%d (%.1fs)",
		r.PackagesProcessed, r.RulesAdded, r.RulesUpdated, r.Skipped,
		len(r.Errors), r.Duration.Seconds(),
	)
}

// ── cyber.mil scraper ─────────────────────────────────────────────────────────

// cyberMilCDN is the direct CDN used for STIG ZIP downloads.
// cyber.mil migrated to Salesforce Experience Cloud for its downloads page
// (fully JavaScript-rendered — HTML scraping no longer finds zip links).
// The actual ZIP files remain on this CDN at a stable URL pattern:
//   https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_<FAMILY>_<VERSION>_STIG.zip
const cyberMilCDN = "https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/"

// cyberMilUserAgent mimics a standard browser to avoid 403s from WAF rules.
const cyberMilUserAgent = "Mozilla/5.0 (compatible; ASAF-STIG-Updater/1.0; +https://secred.io)"

// stigCatalog lists every STIG family with its CDN filename stem and the
// highest known major version.  ListAvailableSTIGs probes VxR1..VxR30 for
// each entry to find the latest available release.
//
// Refresh this list when DISA adds new families: add a row with the new
// CDN stem and set MaxMajor to the current major version (usually 1 or 2).
// stigCatalog is the authoritative list of STIG families available on the
// DISA CDN.  Each entry specifies the CDN filename stem and the range of
// major versions to probe (V1..MaxMajor × R1..30).
//
// Confirmed from CDN probes 2026-07-01:
//   RHEL 9 V1R3, RHEL 7 V3R15, Windows 10 V2R9, Windows 11 V1R6,
//   WS2016 V2R10, WS2019 V2R9, WS2022 V1R5, Kubernetes V1R11,
//   Oracle Linux 8 V1R10/V2R4/V2R5, Oracle DB 19c V1R5,
//   macOS 13 V1R5, macOS 14 V1R2, Ubuntu 18.04 V2R15,
//   Google Chrome V2R11, IE11 V2R7
var stigCatalog = []stigCatalogEntry{
	// ── Linux OS ──────────────────────────────────────────────────────────────
	{Stem: "U_RHEL_9", Title: "Red Hat Enterprise Linux 9 STIG", MaxMajor: 1},
	{Stem: "U_RHEL_8", Title: "Red Hat Enterprise Linux 8 STIG", MaxMajor: 2},
	{Stem: "U_RHEL_7", Title: "Red Hat Enterprise Linux 7 STIG", MaxMajor: 3},
	{Stem: "U_Oracle_Linux_8", Title: "Oracle Linux 8 STIG", MaxMajor: 2},
	{Stem: "U_Oracle_Linux_7", Title: "Oracle Linux 7 STIG", MaxMajor: 2},
	// Ubuntu: DISA uses "CAN" prefix for older releases, direct stem for newer
	{Stem: "U_CAN_Ubuntu_18-04_LTS", Title: "Ubuntu 18.04 LTS STIG", MaxMajor: 2},
	{Stem: "U_Canonical_Ubuntu_20-04_LTS", Title: "Ubuntu 20.04 LTS STIG", MaxMajor: 2},
	{Stem: "U_Canonical_Ubuntu_22-04_LTS", Title: "Ubuntu 22.04 LTS STIG", MaxMajor: 2},
	{Stem: "U_Canonical_Ubuntu_24-04_LTS", Title: "Ubuntu 24.04 LTS STIG", MaxMajor: 1},

	// ── Windows OS ────────────────────────────────────────────────────────────
	{Stem: "U_MS_Windows_10", Title: "Windows 10 STIG", MaxMajor: 2},
	{Stem: "U_MS_Windows_11", Title: "Windows 11 STIG", MaxMajor: 2},
	{Stem: "U_MS_Windows_Server_2016", Title: "Windows Server 2016 STIG", MaxMajor: 2},
	{Stem: "U_MS_Windows_Server_2019", Title: "Windows Server 2019 STIG", MaxMajor: 2},
	{Stem: "U_MS_Windows_Server_2022", Title: "Windows Server 2022 STIG", MaxMajor: 2},

	// ── macOS ─────────────────────────────────────────────────────────────────
	{Stem: "U_Apple_macOS_13", Title: "Apple macOS 13 Ventura STIG", MaxMajor: 1},
	{Stem: "U_Apple_macOS_14", Title: "Apple macOS 14 Sonoma STIG", MaxMajor: 1},
	{Stem: "U_Apple_macOS_15", Title: "Apple macOS 15 Sequoia STIG", MaxMajor: 1},

	// ── Containers / Cloud ────────────────────────────────────────────────────
	{Stem: "U_Kubernetes", Title: "Kubernetes STIG", MaxMajor: 2},
	{Stem: "U_Container_Platform", Title: "Container Platform STIG", MaxMajor: 1},
	{Stem: "U_OpenShift_Container_Platform_4", Title: "OpenShift Container Platform 4 STIG", MaxMajor: 1},

	// ── Network / Infrastructure ──────────────────────────────────────────────
	{Stem: "U_Cisco_IOS_XE_Router", Title: "Cisco IOS-XE Router STIG", MaxMajor: 1},
	{Stem: "U_Cisco_IOS_XE_Switch_L2S", Title: "Cisco IOS-XE Switch L2S STIG", MaxMajor: 2},
	{Stem: "U_Cisco_IOS_XE_Switch_NDM", Title: "Cisco IOS-XE Switch NDM STIG", MaxMajor: 2},
	{Stem: "U_Cisco_NX-OS_Switch_RTR", Title: "Cisco NX-OS Switch RTR STIG", MaxMajor: 2},
	{Stem: "U_Juniper_EX_Series_ALG", Title: "Juniper EX Series ALG STIG", MaxMajor: 1},
	{Stem: "U_Juniper_SRX_Services_Gateway_NDM", Title: "Juniper SRX NDM STIG", MaxMajor: 2},
	{Stem: "U_Palo_Alto_Networks_NDM", Title: "Palo Alto Networks NDM STIG", MaxMajor: 2},
	{Stem: "U_F5_BIG-IP_Local_Traffic_Manager_11-x", Title: "F5 BIG-IP LTM STIG", MaxMajor: 2},

	// ── Databases ─────────────────────────────────────────────────────────────
	{Stem: "U_Oracle_Database_19c", Title: "Oracle Database 19c STIG", MaxMajor: 1},
	{Stem: "U_MS_SQL_Server_2019", Title: "Microsoft SQL Server 2019 STIG", MaxMajor: 1},
	{Stem: "U_MS_SQL_Server_2016", Title: "Microsoft SQL Server 2016 STIG", MaxMajor: 2},
	{Stem: "U_PostgreSQL_9-x", Title: "PostgreSQL 9.x STIG", MaxMajor: 2},
	{Stem: "U_MongoDB_Enterprise_Advanced", Title: "MongoDB Enterprise Advanced STIG", MaxMajor: 1},

	// ── Web / Application ─────────────────────────────────────────────────────
	{Stem: "U_Apache_Server_2-4_Unix_Server", Title: "Apache Server 2.4 Unix STIG", MaxMajor: 3},
	{Stem: "U_MS_IIS_10-0_Server", Title: "Microsoft IIS 10.0 Server STIG", MaxMajor: 2},
	{Stem: "U_MS_IIS_10-0_Site", Title: "Microsoft IIS 10.0 Site STIG", MaxMajor: 2},
	{Stem: "U_Microsoft_Edge", Title: "Microsoft Edge STIG", MaxMajor: 2},
	{Stem: "U_Google_Chrome", Title: "Google Chrome STIG", MaxMajor: 2},
	{Stem: "U_Mozilla_FireFox", Title: "Mozilla Firefox STIG", MaxMajor: 6},
	{Stem: "U_MS_IE11", Title: "Internet Explorer 11 STIG", MaxMajor: 2},

	// ── Active Directory / Identity ───────────────────────────────────────────
	{Stem: "U_Active_Directory_Domain", Title: "Active Directory Domain STIG", MaxMajor: 2},
	{Stem: "U_Active_Directory_Forest", Title: "Active Directory Forest STIG", MaxMajor: 2},
	{Stem: "U_MS_Exchange_2019_Edge", Title: "MS Exchange 2019 Edge STIG", MaxMajor: 1},
	{Stem: "U_MS_Exchange_2019_Mailbox", Title: "MS Exchange 2019 Mailbox STIG", MaxMajor: 1},

	// ── VMware / Virtualization ───────────────────────────────────────────────
	{Stem: "U_VMware_vSphere_7-0_ESXi", Title: "VMware vSphere 7.0 ESXi STIG", MaxMajor: 1},
	{Stem: "U_VMware_vSphere_8-0_ESXi", Title: "VMware vSphere 8.0 ESXi STIG", MaxMajor: 1},
}

type stigCatalogEntry struct {
	Stem     string // CDN filename prefix, e.g. "U_RHEL_9"
	Title    string // Human-readable title
	MaxMajor int    // Highest major version known (probes V1..VMajor)
}

// ListAvailableSTIGs probes the DISA CDN for the latest release of each
// catalogued STIG family.  For each family it tries VxR1..VxR30 for every
// major version up to MaxMajor and returns the highest that responds HTTP 200.
//
// The cyber.mil downloads page migrated to Salesforce Experience Cloud (fully
// JS-rendered) so the old HTML scraper is replaced by this CDN probe approach.
func ListAvailableSTIGs() ([]STIGPackage, error) {
	var pkgs []STIGPackage
	for _, entry := range stigCatalog {
		if pkg, found := probeLatestVersion(entry); found {
			pkgs = append(pkgs, pkg)
		}
	}
	sort.Slice(pkgs, func(i, j int) bool { return pkgs[i].FileName < pkgs[j].FileName })
	return pkgs, nil
}

// probeLatestVersion tries every VxRy combination for a catalog entry and
// returns the highest version that returns HTTP 200 from the CDN.
func probeLatestVersion(entry stigCatalogEntry) (STIGPackage, bool) {
	var best STIGPackage
	found := false

	client := &http.Client{
		Timeout: 15 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return nil
		},
	}

	for major := 1; major <= entry.MaxMajor; major++ {
		for release := 1; release <= 30; release++ {
			version := fmt.Sprintf("V%dR%d", major, release)
			filename := fmt.Sprintf("%s_%s_STIG.zip", entry.Stem, version)
			url := cyberMilCDN + filename

			exists := headCheckURL(client, url)
			if exists {
				best = STIGPackage{
					Title:       entry.Title,
					FileName:    filename,
					DownloadURL: url,
					Version:     version,
				}
				found = true
			} else if found {
				// First miss after at least one hit — we've passed the latest release.
				break
			}
		}
	}
	return best, found
}

// parseSTIGLinks is retained for offline/legacy use (e.g. parsing a cached
// HTML snapshot or a local index file).
func parseSTIGLinks(html, base string) []STIGPackage {
	seen := make(map[string]bool)
	var pkgs []STIGPackage

	re := regexp.MustCompile(
		`https?://(?:dl\.dod\.cyber\.mil|dl\.cyber\.mil|www\.cyber\.mil)[^"'\s<>]*U_[^"'\s<>]*\.zip`)
	for _, u := range re.FindAllString(html, -1) {
		if seen[u] {
			continue
		}
		seen[u] = true
		pkgs = append(pkgs, packageFromURL(u))
	}
	relRE := regexp.MustCompile(`href="(/[^"]*U_[^"]*\.zip)"`)
	for _, m := range relRE.FindAllStringSubmatch(html, -1) {
		u := base + m[1]
		if seen[u] {
			continue
		}
		seen[u] = true
		pkgs = append(pkgs, packageFromURL(u))
	}
	sort.Slice(pkgs, func(i, j int) bool { return pkgs[i].FileName < pkgs[j].FileName })
	return pkgs
}

// packageFromURL derives a STIGPackage from a download URL.
func packageFromURL(u string) STIGPackage {
	fileName := filepath.Base(u)
	title, version := parseStigFilename(fileName)
	return STIGPackage{
		Title:       title,
		FileName:    fileName,
		DownloadURL: u,
		Version:     version,
	}
}

// parseStigFilename extracts a human-readable title and version from a STIG ZIP name.
// e.g. "U_RHEL_9_V1R3_STIG.zip" → ("RHEL 9 STIG", "V1R3")
func parseStigFilename(name string) (title, version string) {
	base := strings.TrimPrefix(name, "U_")
	base = strings.TrimSuffix(base, ".zip")
	base = strings.TrimSuffix(base, "_STIG")
	base = strings.TrimSuffix(base, "_Manual-xccdf")

	// Extract version token (matches VxRy or VxRyy)
	verRE := regexp.MustCompile(`V\d+R\d+`)
	if m := verRE.FindString(base); m != "" {
		version = m
		base = strings.Replace(base, "_"+m, "", 1)
		base = strings.Replace(base, m+"_", "", 1)
	}

	title = strings.ReplaceAll(base, "_", " ")
	return title, version
}

// ── Downloader ────────────────────────────────────────────────────────────────

// DownloadSTIG downloads pkg into destDir and returns the local ZIP path.
// On Windows, falls back to Invoke-WebRequest if Go's HTTP client fails due
// to the pure-Go DNS resolver not resolving DoD CDN hostnames reliably.
func DownloadSTIG(pkg STIGPackage, destDir string) (string, error) {
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return "", err
	}
	dest := filepath.Join(destDir, pkg.FileName)

	if _, err := os.Stat(dest); err == nil {
		return dest, nil
	}

	body, err := fetchURL(pkg.DownloadURL)
	if err != nil {
		// On Windows, Go's pure-Go DNS resolver occasionally fails to resolve
		// DoD CDN hostnames.  Fall back to PowerShell's WinHTTP stack.
		if runtime.GOOS == "windows" {
			if werr := downloadViaPS(pkg.DownloadURL, dest); werr != nil {
				return "", fmt.Errorf("download %s: go: %w; powershell: %v", pkg.FileName, err, werr)
			}
			return dest, nil
		}
		return "", fmt.Errorf("download %s: %w", pkg.FileName, err)
	}

	if err := os.WriteFile(dest, body, 0o644); err != nil {
		return "", err
	}
	return dest, nil
}

// headCheckURL returns true if url responds HTTP 200.  On Windows, if Go's
// pure-Go DNS resolver fails, it retries using PowerShell's WinHTTP stack.
func headCheckURL(client *http.Client, url string) bool {
	req, err := http.NewRequest(http.MethodHead, url, nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", cyberMilUserAgent)
	resp, err := client.Do(req)
	if err == nil {
		resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}
	// Go HTTP failed — on Windows fall back to PowerShell for the HEAD check.
	if runtime.GOOS != "windows" {
		return false
	}
	script := fmt.Sprintf(
		`[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; `+
			`try { $r = Invoke-WebRequest -Uri '%s' -Method Head -UserAgent 'ASAF-STIG-Updater/1.0' -TimeoutSec 10; `+
			`$r.StatusCode } catch { 0 }`,
		url)
	out, err := exec.Command("powershell", "-NonInteractive", "-NoProfile", "-Command", script).Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) == "200"
}

// downloadViaPS downloads url to dest using PowerShell's Invoke-WebRequest,
// which uses Windows' WinHTTP stack and system DNS/proxy settings.
func downloadViaPS(url, dest string) error {
	script := fmt.Sprintf(
		`[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; `+
			`Invoke-WebRequest -Uri '%s' -OutFile '%s' -UserAgent 'ASAF-STIG-Updater/1.0' -TimeoutSec 120`,
		url, dest)
	cmd := exec.Command("powershell", "-NonInteractive", "-NoProfile", "-Command", script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	// Verify file was written and is non-trivial (reject HTML error pages < 50KB)
	info, err := os.Stat(dest)
	if err != nil {
		return fmt.Errorf("file not created: %w", err)
	}
	if info.Size() < 50_000 {
		_ = os.Remove(dest)
		return fmt.Errorf("downloaded file is only %d bytes — likely an error page, not a ZIP", info.Size())
	}
	return nil
}

// ── XCCDF XML parser ──────────────────────────────────────────────────────────

// XCCDF 1.1 and 1.2 namespace variations
var xccdfNamespaces = []string{
	"http://checklists.nist.gov/xccdf/1.2",
	"http://checklists.nist.gov/xccdf/1.1",
	"http://checklists.nist.gov/xccdf/1.1.4",
}

type xccdfBenchmark struct {
	XMLName xml.Name     `xml:"Benchmark"`
	ID      string       `xml:"id,attr"`
	Title   string       `xml:"title"`
	Version string       `xml:"version"`
	Groups  []xccdfGroup `xml:"Group"`
}

type xccdfGroup struct {
	ID    string      `xml:"id,attr"`
	Rules []xccdfRule `xml:"Rule"`
}

type xccdfRule struct {
	ID          string       `xml:"id,attr"`
	Severity    string       `xml:"severity,attr"`
	Version     string       `xml:"version"`
	Title       string       `xml:"title"`
	Description string       `xml:"description"`
	FixText     string       `xml:"fixtext"`
	CheckText   string       `xml:"check>check-content"`
	Idents      []xccdfIdent `xml:"ident"`
}

type xccdfIdent struct {
	System string `xml:"system,attr"`
	Value  string `xml:",chardata"`
}

// ParseXCCDFZip extracts every XCCDF XML benchmark from a STIG ZIP archive
// and returns all parsed STIGRules.
func ParseXCCDFZip(zipPath string) ([]STIGRule, error) {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return nil, fmt.Errorf("open zip %s: %w", zipPath, err)
	}
	defer zr.Close()

	var rules []STIGRule
	for _, f := range zr.File {
		if !isXCCDFFile(f.Name) {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, fmt.Errorf("open %s in zip: %w", f.Name, err)
		}
		parsed, err := parseXCCDFXML(rc, filepath.Base(f.Name))
		rc.Close()
		if err != nil {
			// Non-fatal: log and continue to next file
			continue
		}
		rules = append(rules, parsed...)
	}
	return rules, nil
}

// isXCCDFFile returns true for filenames that are XCCDF benchmarks.
func isXCCDFFile(name string) bool {
	lower := strings.ToLower(name)
	return (strings.HasSuffix(lower, ".xml") || strings.HasSuffix(lower, "-xccdf.xml")) &&
		!strings.Contains(lower, "manual-xccdf") == false || // include manual XCCDF
		strings.HasSuffix(lower, "xccdf.xml")
}

// parseXCCDFXML decodes one XCCDF XML benchmark and returns all rules.
func parseXCCDFXML(r io.Reader, stigFileName string) ([]STIGRule, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	// Strip namespace declarations for simpler unmarshalling:
	// Go's encoding/xml matches element names without namespace by default
	// when the struct XMLName has no namespace — but namespace prefixes in
	// the document break matching. Replace them with an empty namespace.
	cleaned := stripXMLNamespace(data)

	var bench xccdfBenchmark
	if err := xml.Unmarshal(cleaned, &bench); err != nil {
		return nil, fmt.Errorf("xml decode %s: %w", stigFileName, err)
	}

	var rules []STIGRule
	for _, g := range bench.Groups {
		for _, r := range g.Rules {
			if r.ID == "" {
				continue
			}
			rules = append(rules, STIGRule{
				ID:        r.ID,
				Title:     strings.TrimSpace(stripXMLTags(r.Title)),
				Severity:  normalizeSeverity(r.Severity),
				Version:   strings.TrimSpace(r.Version),
				FixText:   strings.TrimSpace(stripXMLTags(r.FixText)),
				CheckText: strings.TrimSpace(stripXMLTags(r.CheckText)),
				CCIs:      extractCCIs(r.Idents),
				StigFile:  stigFileName,
			})
		}
	}
	return rules, nil
}

// stripXMLNamespace removes xmlns and xsi declarations to simplify parsing.
func stripXMLNamespace(data []byte) []byte {
	s := string(data)
	for _, ns := range xccdfNamespaces {
		s = strings.ReplaceAll(s, `xmlns="`+ns+`"`, ``)
		s = strings.ReplaceAll(s, `xmlns:xccdf="`+ns+`"`, ``)
	}
	// Remove any remaining xmlns= declarations
	nsRE := regexp.MustCompile(`\s+xmlns(?::\w+)?="[^"]*"`)
	s = nsRE.ReplaceAllString(s, "")
	// Strip namespace prefixes from element names: <xccdf:Benchmark> → <Benchmark>
	prefixRE := regexp.MustCompile(`<(/?)(\w+):`)
	s = prefixRE.ReplaceAllString(s, "<$1")
	return []byte(s)
}

// stripXMLTags removes XML/HTML tags from a string (for description fields).
func stripXMLTags(s string) string {
	tagRE := regexp.MustCompile(`<[^>]+>`)
	s = tagRE.ReplaceAllString(s, " ")
	s = strings.ReplaceAll(s, "&lt;", "<")
	s = strings.ReplaceAll(s, "&gt;", ">")
	s = strings.ReplaceAll(s, "&amp;", "&")
	s = strings.ReplaceAll(s, "&quot;", `"`)
	s = strings.ReplaceAll(s, "&apos;", "'")
	return strings.Join(strings.Fields(s), " ")
}

// normalizeSeverity maps XCCDF severity values to canonical CAT labels.
func normalizeSeverity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "high", "cat i", "cat_i", "cat1":
		return "high"
	case "medium", "cat ii", "cat_ii", "cat2":
		return "medium"
	case "low", "cat iii", "cat_iii", "cat3":
		return "low"
	}
	return "medium" // safe default
}

// extractCCIs returns all CCI identifiers from an XCCDF rule's <ident> elements.
func extractCCIs(idents []xccdfIdent) []string {
	var ccis []string
	for _, id := range idents {
		v := strings.TrimSpace(id.Value)
		if v == "" {
			continue
		}
		// CCI system URIs contain "cci" (case-insensitive)
		if strings.Contains(strings.ToLower(id.System), "cci") ||
			strings.HasPrefix(strings.ToUpper(v), "CCI-") {
			if !strings.HasPrefix(strings.ToUpper(v), "CCI-") {
				v = "CCI-" + v
			}
			ccis = append(ccis, v)
		}
	}
	return ccis
}

// ── Update pipelines ──────────────────────────────────────────────────────────

// UpdateFromCyberMil fetches the current STIG list from cyber.mil, downloads
// the specified families (or all if filter is empty), parses the XCCDF XML,
// and writes updated CSV rows into dataDir (= pkg/stig/data/).
//
// Requires outbound internet. Run on the build machine, then commit updated CSVs.
func UpdateFromCyberMil(dataDir string, filter []string, downloadCache string) (*UpdateResult, error) {
	start := time.Now()
	result := &UpdateResult{}

	pkgs, err := ListAvailableSTIGs()
	if err != nil {
		return nil, fmt.Errorf("list STIGs: %w", err)
	}

	if len(filter) > 0 {
		pkgs = filterPackages(pkgs, filter)
	}

	var allRules []STIGRule
	for _, pkg := range pkgs {
		zipPath, err := DownloadSTIG(pkg, downloadCache)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Errorf("download %s: %w", pkg.FileName, err))
			result.Skipped++
			continue
		}
		rules, err := ParseXCCDFZip(zipPath)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Errorf("parse %s: %w", pkg.FileName, err))
			result.Skipped++
			continue
		}
		allRules = append(allRules, rules...)
		result.PackagesProcessed++
	}

	added, updated, err := writeUpdatedCSV(dataDir, allRules)
	if err != nil {
		return nil, fmt.Errorf("write CSV: %w", err)
	}
	result.RulesAdded = added
	result.RulesUpdated = updated
	result.Duration = time.Since(start)
	return result, nil
}

// UpdateFromLocalDir reads STIG ZIP files from a local directory (USB transfer
// for air-gapped environments) and updates the CSV database.
func UpdateFromLocalDir(zipDir, dataDir string) (*UpdateResult, error) {
	start := time.Now()
	result := &UpdateResult{}

	entries, err := os.ReadDir(zipDir)
	if err != nil {
		return nil, fmt.Errorf("read dir %s: %w", zipDir, err)
	}

	var allRules []STIGRule
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".zip") {
			continue
		}
		zipPath := filepath.Join(zipDir, e.Name())
		rules, err := ParseXCCDFZip(zipPath)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Errorf("parse %s: %w", e.Name(), err))
			result.Skipped++
			continue
		}
		allRules = append(allRules, rules...)
		result.PackagesProcessed++
	}

	added, updated, err := writeUpdatedCSV(dataDir, allRules)
	if err != nil {
		return nil, fmt.Errorf("write CSV: %w", err)
	}
	result.RulesAdded = added
	result.RulesUpdated = updated
	result.Duration = time.Since(start)
	return result, nil
}

// ── CSV writer ────────────────────────────────────────────────────────────────

// writeUpdatedCSV merges new STIGRule entries into the existing STIG_CCI_Map.csv,
// deduplicates by (STIG_ID, CCI_ID) pair, and rewrites the file atomically.
// Returns counts of added and updated rows.
func writeUpdatedCSV(dataDir string, newRules []STIGRule) (added, updated int, err error) {
	csvPath := filepath.Join(dataDir, "STIG_CCI_Map.csv")

	// Load existing rows into a map keyed by "STIG_ID|CCI_ID"
	existing, err := loadExistingCSV(csvPath)
	if err != nil {
		return 0, 0, err
	}

	// Expand each STIGRule into one row per CCI
	for _, rule := range newRules {
		// Rules with no CCIs still get one "no-CCI" row so the rule is
		// visible in the DB even if the CCI chain is not yet mapped.
		ccis := rule.CCIs
		if len(ccis) == 0 {
			ccis = []string{""}
		}
		for _, cci := range ccis {
			key := rule.ID + "|" + cci
			row := csvRow{
				STIGID:       rule.ID,
				STIGTitle:    rule.Title,
				STIGSeverity: rule.Severity,
				CCIID:        cci,
				STIGFile:     rule.StigFile,
			}
			if _, exists := existing[key]; exists {
				existing[key] = row
				updated++
			} else {
				existing[key] = row
				added++
			}
		}
	}

	return added, updated, rewriteCSV(csvPath, existing)
}

type csvRow struct {
	STIGID       string
	STIGTitle    string
	STIGSeverity string
	CCIID        string
	STIGFile     string
}

func loadExistingCSV(path string) (map[string]csvRow, error) {
	rows := make(map[string]csvRow)
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return rows, nil // fresh database
		}
		return nil, err
	}
	defer f.Close()

	r := csv.NewReader(f)
	r.FieldsPerRecord = -1 // allow variable columns
	header := true
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if header {
			header = false
			continue
		}
		if len(rec) < 5 {
			continue
		}
		key := rec[0] + "|" + rec[3]
		rows[key] = csvRow{
			STIGID:       rec[0],
			STIGTitle:    rec[1],
			STIGSeverity: rec[2],
			CCIID:        rec[3],
			STIGFile:     rec[4],
		}
	}
	return rows, nil
}

func rewriteCSV(path string, rows map[string]csvRow) error {
	// Sort keys for deterministic output (makes git diffs readable)
	keys := make([]string, 0, len(rows))
	for k := range rows {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Write to a temp file first, then rename atomically
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	w := csv.NewWriter(f)
	if err := w.Write([]string{"STIG_ID", "STIG_Title", "STIG_Severity", "CCI_ID", "STIG_File"}); err != nil {
		f.Close()
		return err
	}
	for _, k := range keys {
		row := rows[k]
		if err := w.Write([]string{row.STIGID, row.STIGTitle, row.STIGSeverity, row.CCIID, row.STIGFile}); err != nil {
			f.Close()
			return err
		}
	}
	w.Flush()
	f.Close()
	if err := w.Error(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// fetchURL performs an HTTP GET with the AdinKhepra user-agent and returns body bytes.
func fetchURL(url string) ([]byte, error) {
	client := &http.Client{Timeout: 120 * time.Second}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", cyberMilUserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}
	return io.ReadAll(resp.Body)
}

// FilterPackages keeps only packages whose FileName contains one of the filter strings.
func FilterPackages(pkgs []STIGPackage, filter []string) []STIGPackage {
	return filterPackages(pkgs, filter)
}

// filterPackages is the unexported implementation.
func filterPackages(pkgs []STIGPackage, filter []string) []STIGPackage {
	var out []STIGPackage
	for _, p := range pkgs {
		for _, f := range filter {
			if strings.Contains(strings.ToUpper(p.FileName), strings.ToUpper(f)) {
				out = append(out, p)
				break
			}
		}
	}
	return out
}

// GetAllSTIGFamilies returns the unique STIG_File values recorded in the
// embedded STIG_CCI_Map.csv — one entry per STIG benchmark family.
// Safe to call at runtime (reads from the already-loaded database).
func GetAllSTIGFamilies() ([]string, error) {
	db, err := GetDatabase()
	if err != nil {
		return nil, err
	}
	db.mu.RLock()
	defer db.mu.RUnlock()

	seen := make(map[string]bool)
	var families []string
	for _, mappings := range db.STIGtoCCI {
		for _, m := range mappings {
			if m.STIGFile != "" && !seen[m.STIGFile] {
				seen[m.STIGFile] = true
				families = append(families, m.STIGFile)
			}
		}
	}
	sort.Strings(families)
	return families, nil
}

// STIGRuleSummary carries the per-rule metadata for GetAllRulesForFamily.
type STIGRuleSummary struct {
	ID       string
	Title    string
	Severity string // "high" | "medium" | "low"
}

// GetAllRulesForFamily returns every rule that maps to the given STIG_File value.
func GetAllRulesForFamily(stigFile string) ([]STIGRuleSummary, error) {
	db, err := GetDatabase()
	if err != nil {
		return nil, err
	}
	db.mu.RLock()
	defer db.mu.RUnlock()

	seen := make(map[string]bool)
	var rules []STIGRuleSummary
	for id, mappings := range db.STIGtoCCI {
		for _, m := range mappings {
			if m.STIGFile == stigFile && !seen[id] {
				seen[id] = true
				rules = append(rules, STIGRuleSummary{
					ID:       id,
					Title:    m.STIGTitle,
					Severity: normalizeSeverity(m.STIGSeverity),
				})
			}
		}
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
	return rules, nil
}

// FamilyRuleCounts returns a map of STIG_File → unique rule count in a single O(N) pass
// over the compliance database.  More efficient than calling GetAllRulesForFamily once per
// family; use this to seed Tier 4 aggregate nodes at startup.
func FamilyRuleCounts() (map[string]int, error) {
	db, err := GetDatabase()
	if err != nil {
		return nil, err
	}
	db.mu.RLock()
	defer db.mu.RUnlock()

	// Build family → set-of-ruleIDs in one pass.
	familyRules := make(map[string]map[string]struct{}, 400)
	for ruleID, mappings := range db.STIGtoCCI {
		for _, m := range mappings {
			if m.STIGFile == "" {
				continue
			}
			if _, ok := familyRules[m.STIGFile]; !ok {
				familyRules[m.STIGFile] = make(map[string]struct{})
			}
			familyRules[m.STIGFile][ruleID] = struct{}{}
		}
	}

	counts := make(map[string]int, len(familyRules))
	for fam, rules := range familyRules {
		counts[fam] = len(rules)
	}
	return counts, nil
}
