// Package vuln - Threat Intelligence Feeds Module
//
// "The Scarab's Eyes See All - From the Depths of the Dark Web to the Halls of NIST"
//
// This module aggregates vulnerability and threat intelligence from multiple authoritative sources:
// - NVD (National Vulnerability Database) - NIST's official repository
// - CVE (Common Vulnerabilities and Exposures) - MITRE's vulnerability dictionary
// - OSV (Open Source Vulnerabilities) - Google's open-source vulnerability database
// - InTheWild.io - Real-time exploited vulnerability tracking
// - Zero Day Initiative - Advanced vulnerability research
// - CVEFeed.io - Aggregated CVE RSS feeds
package vuln

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// FeedSource represents a threat intelligence feed
type FeedSource struct {
	Name        string    `json:"name"`
	URL         string    `json:"url"`
	Type        string    `json:"type"` // "json", "rss", "api"
	Description string    `json:"description"`
	Enabled     bool      `json:"enabled"`
	LastFetch   time.Time `json:"last_fetch"`
	Priority    int       `json:"priority"` // Lower = higher priority
}

// ThreatIntel represents enriched vulnerability intelligence
type ThreatIntel struct {
	CVEID            string    `json:"cve_id"`
	GHSAID           string    `json:"ghsa_id,omitempty"`
	Title            string    `json:"title"`
	Description      string    `json:"description"`
	Severity         Severity  `json:"severity"`
	CVSSv3Score      float64   `json:"cvss_v3_score"`
	CVSSv3Vector     string    `json:"cvss_v3_vector,omitempty"`
	ExploitedInWild  bool      `json:"exploited_in_wild"`
	ExploitAvailable bool      `json:"exploit_available"`
	PatchAvailable   bool      `json:"patch_available"`
	AffectedProducts []string  `json:"affected_products"`
	References       []string  `json:"references"`
	PublishedDate    time.Time `json:"published_date"`
	LastModified     time.Time `json:"last_modified"`
	Source           string    `json:"source"`

	// EPSS (Exploit Prediction Scoring System) — AD-003
	EPSSScore      float64 `json:"epss_score"`       // 0.0–1.0 probability of exploitation
	EPSSPercentile float64 `json:"epss_percentile"`  // 0.0–1.0 relative ranking

	// MITRE ATT&CK Mapping
	ATTACKTactics    []string `json:"attack_tactics,omitempty"`
	ATTACKTechniques []string `json:"attack_techniques,omitempty"`
}

// IntelFeedManager manages multiple threat intelligence feeds
type IntelFeedManager struct {
	feeds      []FeedSource
	cache      map[string]*ThreatIntel // CVE ID -> Intel
	cacheMu    sync.RWMutex
	httpClient *http.Client

	// Callbacks
	OnNewIntel func(intel *ThreatIntel)
}

// DefaultFeeds returns the standard threat intelligence feed configuration
func DefaultFeeds() []FeedSource {
	return []FeedSource{
		{
			Name:        "NVD",
			URL:         "https://services.nvd.nist.gov/rest/json/cves/2.0",
			Type:        "api",
			Description: "National Vulnerability Database - NIST's official CVE repository",
			Enabled:     true,
			Priority:    1,
		},
		{
			Name:        "OSV",
			URL:         "https://api.osv.dev/v1/query",
			Type:        "api",
			Description: "Open Source Vulnerabilities - Google's OSS vulnerability database",
			Enabled:     true,
			Priority:    2,
		},
		{
			Name:        "InTheWild",
			URL:         "https://inthewild.io/api/exploited",
			Type:        "api",
			Description: "Real-time tracking of actively exploited vulnerabilities",
			Enabled:     true,
			Priority:    3,
		},
		{
			Name:        "CVEFeed",
			URL:         "https://cvefeed.io/rssfeed/",
			Type:        "rss",
			Description: "Aggregated CVE RSS feed",
			Enabled:     true,
			Priority:    4,
		},
		{
			Name:        "ZDI",
			URL:         "https://www.zerodayinitiative.com/rss/published/",
			Type:        "rss",
			Description: "Zero Day Initiative - Advanced vulnerability research",
			Enabled:     true,
			Priority:    5,
		},
		{
			Name:        "0DayFans",
			URL:         "https://0dayfans.com/feed.rss",
			Type:        "rss",
			Description: "Aggregated vulnerability research and exploit disclosures",
			Enabled:     true,
			Priority:    6,
		},
		{
			Name:        "CISA-KEV",
			URL:         "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
			Type:        "json",
			Description: "CISA Known Exploited Vulnerabilities Catalog",
			Enabled:     true,
			Priority:    1, // High priority - these are confirmed exploited
		},
		{
			Name:        "EPSS",
			URL:         "https://api.first.org/data/v1/epss",
			Type:        "api",
			Description: "FIRST.org Exploit Prediction Scoring System (AD-003: primary exploit probability feed)",
			Enabled:     true,
			Priority:    1, // Critical enrichment source
		},
	}
}

// NewIntelFeedManager creates a new feed manager with default sources
func NewIntelFeedManager() *IntelFeedManager {
	return &IntelFeedManager{
		feeds: DefaultFeeds(),
		cache: make(map[string]*ThreatIntel),
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// AddFeed adds a custom feed source
func (m *IntelFeedManager) AddFeed(feed FeedSource) {
	m.feeds = append(m.feeds, feed)
}

// FetchAll fetches intelligence from all enabled feeds
func (m *IntelFeedManager) FetchAll(ctx context.Context) error {
	var wg sync.WaitGroup
	errChan := make(chan error, len(m.feeds))

	for i := range m.feeds {
		if !m.feeds[i].Enabled {
			continue
		}

		wg.Add(1)
		go func(feed *FeedSource) {
			defer wg.Done()

			log.Printf("[INTEL] Fetching from %s...", feed.Name)

			var err error
			switch feed.Type {
			case "api":
				err = m.fetchAPI(ctx, feed)
			case "rss":
				err = m.fetchRSS(ctx, feed)
			case "json":
				err = m.fetchJSON(ctx, feed)
			}

			if err != nil {
				errChan <- fmt.Errorf("%s: %w", feed.Name, err)
				log.Printf("[INTEL] ERROR fetching %s: %v", feed.Name, err)
			} else {
				feed.LastFetch = time.Now()
				log.Printf("[INTEL] SUCCESS: %s feed updated", feed.Name)
			}
		}(&m.feeds[i])
	}

	wg.Wait()
	close(errChan)

	// Collect errors
	var errors []string
	for err := range errChan {
		errors = append(errors, err.Error())
	}

	if len(errors) > 0 {
		return fmt.Errorf("feed errors: %s", strings.Join(errors, "; "))
	}
	return nil
}

// fetchAPI handles API-based feeds (NVD, OSV, InTheWild, EPSS)
func (m *IntelFeedManager) fetchAPI(ctx context.Context, feed *FeedSource) error {
	switch feed.Name {
	case "NVD":
		return m.fetchNVD(ctx)
	case "OSV":
		// OSV requires package-specific queries, handled elsewhere
		return nil
	case "InTheWild":
		return m.fetchInTheWild(ctx)
	case "CISA-KEV":
		return m.fetchCISAKEV(ctx)
	case "EPSS":
		return m.fetchEPSSBulk(ctx)
	}
	return nil
}

// fetchNVD fetches recent CVEs from NIST's NVD API
func (m *IntelFeedManager) fetchNVD(ctx context.Context) error {
	// Fetch CVEs modified in the last 7 days
	endDate := time.Now().UTC()
	startDate := endDate.AddDate(0, 0, -7)

	url := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0?lastModStartDate=%s&lastModEndDate=%s",
		startDate.Format("2006-01-02T15:04:05.000"),
		endDate.Format("2006-01-02T15:04:05.000"))

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}
	// NVD recommends identifying your application
	req.Header.Set("User-Agent", "KASA-VulnHunter/1.0 (Khepra-Security)")

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("NVD API returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var nvdResp NVDResponse
	if err := json.Unmarshal(body, &nvdResp); err != nil {
		return err
	}

	// Process and cache results
	for _, vuln := range nvdResp.Vulnerabilities {
		intel := m.nvdToThreatIntel(&vuln)
		m.cacheIntel(intel)
	}

	log.Printf("[INTEL] NVD: Processed %d vulnerabilities", len(nvdResp.Vulnerabilities))
	return nil
}

// NVDResponse represents the NVD API response structure
type NVDResponse struct {
	ResultsPerPage  int `json:"resultsPerPage"`
	StartIndex      int `json:"startIndex"`
	TotalResults    int `json:"totalResults"`
	Vulnerabilities []struct {
		CVE struct {
			ID          string `json:"id"`
			Description struct {
				DescriptionData []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"descriptions"`
			} `json:"descriptions"`
			Metrics struct {
				CVSSMetricV31 []struct {
					CVSSData struct {
						Version      string  `json:"version"`
						VectorString string  `json:"vectorString"`
						BaseScore    float64 `json:"baseScore"`
						BaseSeverity string  `json:"baseSeverity"`
					} `json:"cvssData"`
				} `json:"cvssMetricV31"`
			} `json:"metrics"`
			References []struct {
				URL string `json:"url"`
			} `json:"references"`
			Published    string `json:"published"`
			LastModified string `json:"lastModified"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

// nvdToThreatIntel converts NVD response to our internal format
func (m *IntelFeedManager) nvdToThreatIntel(vuln *struct {
	CVE struct {
		ID          string `json:"id"`
		Description struct {
			DescriptionData []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
		} `json:"descriptions"`
		Metrics struct {
			CVSSMetricV31 []struct {
				CVSSData struct {
					Version      string  `json:"version"`
					VectorString string  `json:"vectorString"`
					BaseScore    float64 `json:"baseScore"`
					BaseSeverity string  `json:"baseSeverity"`
				} `json:"cvssData"`
			} `json:"cvssMetricV31"`
		} `json:"metrics"`
		References []struct {
			URL string `json:"url"`
		} `json:"references"`
		Published    string `json:"published"`
		LastModified string `json:"lastModified"`
	} `json:"cve"`
}) *ThreatIntel {
	intel := &ThreatIntel{
		CVEID:  vuln.CVE.ID,
		Source: "NVD",
	}

	// Extract description
	for _, desc := range vuln.CVE.Description.DescriptionData {
		if desc.Lang == "en" {
			intel.Description = desc.Value
			// Use first line as title
			if idx := strings.Index(desc.Value, "."); idx > 0 {
				intel.Title = desc.Value[:idx]
			} else {
				intel.Title = desc.Value
			}
			break
		}
	}

	// Extract CVSS v3.1 metrics
	if len(vuln.CVE.Metrics.CVSSMetricV31) > 0 {
		cvss := vuln.CVE.Metrics.CVSSMetricV31[0].CVSSData
		intel.CVSSv3Score = cvss.BaseScore
		intel.CVSSv3Vector = cvss.VectorString
		intel.Severity = mapCVSSSeverity(cvss.BaseSeverity)
	}

	// Extract references
	for _, ref := range vuln.CVE.References {
		intel.References = append(intel.References, ref.URL)
	}

	// Parse dates
	if t, err := time.Parse("2006-01-02T15:04:05.000", vuln.CVE.Published); err == nil {
		intel.PublishedDate = t
	}
	if t, err := time.Parse("2006-01-02T15:04:05.000", vuln.CVE.LastModified); err == nil {
		intel.LastModified = t
	}

	return intel
}

// mapCVSSSeverity maps CVSS severity string to our Severity type
func mapCVSSSeverity(s string) Severity {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return SeverityCritical
	case "HIGH":
		return SeverityHigh
	case "MEDIUM":
		return SeverityModerate
	default:
		return SeverityLow
	}
}

// fetchInTheWild fetches actively exploited vulnerabilities
func (m *IntelFeedManager) fetchInTheWild(ctx context.Context) error {
	// InTheWild.io provides free API for exploited vulns
	// Their data format may vary, using a generic approach
	req, err := http.NewRequestWithContext(ctx, "GET", "https://inthewild.io/feed", nil)
	if err != nil {
		return err
	}

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("InTheWild API returned %d", resp.StatusCode)
	}

	// Parse response and mark CVEs as exploited
	// This would need to be adapted to their actual API format
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var exploited []struct {
		CVE string `json:"cve"`
	}
	if err := json.Unmarshal(body, &exploited); err != nil {
		// Try alternative format
		return nil
	}

	// Mark cached CVEs as exploited in the wild
	m.cacheMu.Lock()
	for _, e := range exploited {
		if intel, exists := m.cache[e.CVE]; exists {
			intel.ExploitedInWild = true
		} else {
			m.cache[e.CVE] = &ThreatIntel{
				CVEID:           e.CVE,
				ExploitedInWild: true,
				Source:          "InTheWild",
				Severity:        SeverityCritical, // Exploited = Critical
			}
		}
	}
	m.cacheMu.Unlock()

	return nil
}

// fetchCISAKEV fetches CISA's Known Exploited Vulnerabilities catalog
func (m *IntelFeedManager) fetchCISAKEV(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "GET",
		"https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", nil)
	if err != nil {
		return err
	}

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("CISA KEV returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var kevData struct {
		Title           string `json:"title"`
		CatalogVersion  string `json:"catalogVersion"`
		DateReleased    string `json:"dateReleased"`
		Vulnerabilities []struct {
			CVEID             string `json:"cveID"`
			VendorProject     string `json:"vendorProject"`
			Product           string `json:"product"`
			VulnerabilityName string `json:"vulnerabilityName"`
			DateAdded         string `json:"dateAdded"`
			ShortDescription  string `json:"shortDescription"`
			RequiredAction    string `json:"requiredAction"`
			DueDate           string `json:"dueDate"`
		} `json:"vulnerabilities"`
	}

	if err := json.Unmarshal(body, &kevData); err != nil {
		return err
	}

	// Process KEV entries - these are CONFIRMED exploited
	m.cacheMu.Lock()
	for _, kev := range kevData.Vulnerabilities {
		intel := &ThreatIntel{
			CVEID:            kev.CVEID,
			Title:            kev.VulnerabilityName,
			Description:      kev.ShortDescription,
			ExploitedInWild:  true, // KEV = confirmed exploited
			Severity:         SeverityCritical,
			AffectedProducts: []string{fmt.Sprintf("%s %s", kev.VendorProject, kev.Product)},
			Source:           "CISA-KEV",
		}

		if t, err := time.Parse("2006-01-02", kev.DateAdded); err == nil {
			intel.PublishedDate = t
		}

		m.cache[kev.CVEID] = intel
	}
	m.cacheMu.Unlock()

	log.Printf("[INTEL] CISA-KEV: Processed %d known exploited vulnerabilities", len(kevData.Vulnerabilities))
	return nil
}

// ──────────────────────────────────────────────────────────────────────────────
// EPSS Feed (AD-003: Primary exploit probability source)
// ──────────────────────────────────────────────────────────────────────────────

// EPSSResponse represents the FIRST.org EPSS API response.
type EPSSResponse struct {
	Status     string     `json:"status"`
	StatusCode int        `json:"status-code"`
	Version    string     `json:"version"`
	Total      int        `json:"total"`
	Data       []EPSSData `json:"data"`
}

// EPSSData represents a single CVE's EPSS score.
type EPSSData struct {
	CVE        string `json:"cve"`
	EPSS       string `json:"epss"`       // String in API response
	Percentile string `json:"percentile"` // String in API response
	Date       string `json:"date"`
}

// fetchEPSSBulk fetches EPSS scores for all CVEs currently in the cache.
// This is called during FetchAll() to bulk-enrich cached intelligence.
func (m *IntelFeedManager) fetchEPSSBulk(ctx context.Context) error {
	// Collect all CVE IDs from cache
	m.cacheMu.RLock()
	var cveIDs []string
	for cveID := range m.cache {
		if strings.HasPrefix(cveID, "CVE-") {
			cveIDs = append(cveIDs, cveID)
		}
	}
	m.cacheMu.RUnlock()

	if len(cveIDs) == 0 {
		log.Println("[INTEL] EPSS: No CVEs in cache to enrich")
		return nil
	}

	// FIRST.org EPSS API accepts batch queries of up to 30 CVEs per request
	const batchSize = 30
	var totalEnriched int

	for i := 0; i < len(cveIDs); i += batchSize {
		end := i + batchSize
		if end > len(cveIDs) {
			end = len(cveIDs)
		}
		batch := cveIDs[i:end]

		enriched, err := m.fetchEPSSBatch(ctx, batch)
		if err != nil {
			log.Printf("[INTEL] EPSS: Batch %d-%d failed: %v", i, end, err)
			// Continue with remaining batches — don't fail the whole feed
			continue
		}
		totalEnriched += enriched

		// Rate limiting: FIRST.org recommends reasonable request pacing
		if end < len(cveIDs) {
			time.Sleep(500 * time.Millisecond)
		}
	}

	log.Printf("[INTEL] EPSS: Enriched %d/%d CVEs with exploit probability scores", totalEnriched, len(cveIDs))
	return nil
}

// FetchEPSS queries EPSS scores for specific CVE IDs and updates the cache.
// This is the public API for on-demand EPSS lookups (used by the Enricher).
func (m *IntelFeedManager) FetchEPSS(ctx context.Context, cveIDs []string) error {
	if len(cveIDs) == 0 {
		return nil
	}

	// Filter to valid CVE IDs only
	var validIDs []string
	for _, id := range cveIDs {
		if strings.HasPrefix(id, "CVE-") {
			validIDs = append(validIDs, id)
		}
	}

	if len(validIDs) == 0 {
		return nil
	}

	const batchSize = 30
	for i := 0; i < len(validIDs); i += batchSize {
		end := i + batchSize
		if end > len(validIDs) {
			end = len(validIDs)
		}

		if _, err := m.fetchEPSSBatch(ctx, validIDs[i:end]); err != nil {
			return fmt.Errorf("EPSS batch query failed: %w", err)
		}

		if end < len(validIDs) {
			time.Sleep(500 * time.Millisecond)
		}
	}

	return nil
}

// fetchEPSSBatch queries the FIRST.org EPSS API for a batch of CVE IDs.
// Returns the number of CVEs successfully enriched.
func (m *IntelFeedManager) fetchEPSSBatch(ctx context.Context, cveIDs []string) (int, error) {
	// Build query: https://api.first.org/data/v1/epss?cve=CVE-1,CVE-2,...
	url := fmt.Sprintf("https://api.first.org/data/v1/epss?cve=%s", strings.Join(cveIDs, ","))

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", "Khepra-ERT/1.0 (EPSS-enrichment)")

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("EPSS API returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, err
	}

	var epssResp EPSSResponse
	if err := json.Unmarshal(body, &epssResp); err != nil {
		return 0, fmt.Errorf("failed to parse EPSS response: %w", err)
	}

	// Update cache with EPSS scores
	enriched := 0
	m.cacheMu.Lock()
	for _, data := range epssResp.Data {
		epssScore := parseFloat(data.EPSS)
		epssPercentile := parseFloat(data.Percentile)

		if intel, exists := m.cache[data.CVE]; exists {
			intel.EPSSScore = epssScore
			intel.EPSSPercentile = epssPercentile
			enriched++
		} else {
			// Create a minimal entry for CVEs not yet in cache
			m.cache[data.CVE] = &ThreatIntel{
				CVEID:          data.CVE,
				EPSSScore:      epssScore,
				EPSSPercentile: epssPercentile,
				Source:         "EPSS",
			}
			enriched++
		}
	}
	m.cacheMu.Unlock()

	return enriched, nil
}

// LookupEPSS returns EPSS score and percentile for a CVE from the cache.
// Returns (0, 0, false) if not found.
func (m *IntelFeedManager) LookupEPSS(cveID string) (score, percentile float64, found bool) {
	m.cacheMu.RLock()
	defer m.cacheMu.RUnlock()

	if intel, exists := m.cache[cveID]; exists && intel.EPSSScore > 0 {
		return intel.EPSSScore, intel.EPSSPercentile, true
	}
	return 0, 0, false
}

// parseFloat safely converts a string to float64, returning 0.0 on failure.
func parseFloat(s string) float64 {
	var f float64
	fmt.Sscanf(s, "%f", &f)
	return f
}

// fetchRSS handles RSS-based feeds
func (m *IntelFeedManager) fetchRSS(ctx context.Context, feed *FeedSource) error {
	req, err := http.NewRequestWithContext(ctx, "GET", feed.URL, nil)
	if err != nil {
		return err
	}

	resp, err := m.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s RSS returned %d", feed.Name, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	// Parse RSS feed
	var rss RSSFeed
	if err := xml.Unmarshal(body, &rss); err != nil {
		return err
	}

	// Process items
	for _, item := range rss.Channel.Items {
		intel := m.rssItemToThreatIntel(&item, feed.Name)
		if intel.CVEID != "" {
			m.cacheIntel(intel)
		}
	}

	log.Printf("[INTEL] %s: Processed %d RSS items", feed.Name, len(rss.Channel.Items))
	return nil
}

// RSSFeed represents a generic RSS feed structure
type RSSFeed struct {
	XMLName xml.Name `xml:"rss"`
	Channel struct {
		Title       string `xml:"title"`
		Description string `xml:"description"`
		Items       []struct {
			Title       string `xml:"title"`
			Link        string `xml:"link"`
			Description string `xml:"description"`
			PubDate     string `xml:"pubDate"`
			GUID        string `xml:"guid"`
		} `xml:"item"`
	} `xml:"channel"`
}

// rssItemToThreatIntel converts RSS item to ThreatIntel
func (m *IntelFeedManager) rssItemToThreatIntel(item *struct {
	Title       string `xml:"title"`
	Link        string `xml:"link"`
	Description string `xml:"description"`
	PubDate     string `xml:"pubDate"`
	GUID        string `xml:"guid"`
}, source string) *ThreatIntel {
	intel := &ThreatIntel{
		Title:       item.Title,
		Description: item.Description,
		References:  []string{item.Link},
		Source:      source,
	}

	// Try to extract CVE ID from title or description
	if cve := extractCVE(item.Title); cve != "" {
		intel.CVEID = cve
	} else if cve := extractCVE(item.Description); cve != "" {
		intel.CVEID = cve
	}

	// Parse date
	if t, err := time.Parse(time.RFC1123Z, item.PubDate); err == nil {
		intel.PublishedDate = t
	} else if t, err := time.Parse(time.RFC1123, item.PubDate); err == nil {
		intel.PublishedDate = t
	}

	return intel
}

// fetchJSON handles JSON feed sources
func (m *IntelFeedManager) fetchJSON(ctx context.Context, feed *FeedSource) error {
	// Generic JSON fetch - specific handling based on feed name
	switch feed.Name {
	case "CISA-KEV":
		return m.fetchCISAKEV(ctx)
	}
	return nil
}

// cacheIntel stores threat intelligence in the cache
func (m *IntelFeedManager) cacheIntel(intel *ThreatIntel) {
	if intel.CVEID == "" {
		return
	}

	m.cacheMu.Lock()
	defer m.cacheMu.Unlock()

	// Merge with existing if present
	if existing, exists := m.cache[intel.CVEID]; exists {
		// Keep the most complete data
		if intel.Description != "" && existing.Description == "" {
			existing.Description = intel.Description
		}
		if intel.CVSSv3Score > existing.CVSSv3Score {
			existing.CVSSv3Score = intel.CVSSv3Score
			existing.CVSSv3Vector = intel.CVSSv3Vector
		}
		if intel.ExploitedInWild {
			existing.ExploitedInWild = true
		}
		existing.References = append(existing.References, intel.References...)
	} else {
		m.cache[intel.CVEID] = intel

		// Callback for new intel
		if m.OnNewIntel != nil {
			m.OnNewIntel(intel)
		}
	}
}

// LookupCVE retrieves cached intelligence for a CVE
func (m *IntelFeedManager) LookupCVE(cveID string) *ThreatIntel {
	m.cacheMu.RLock()
	defer m.cacheMu.RUnlock()
	return m.cache[cveID]
}

// GetExploitedCVEs returns all CVEs known to be exploited in the wild
func (m *IntelFeedManager) GetExploitedCVEs() []*ThreatIntel {
	m.cacheMu.RLock()
	defer m.cacheMu.RUnlock()

	var exploited []*ThreatIntel
	for _, intel := range m.cache {
		if intel.ExploitedInWild {
			exploited = append(exploited, intel)
		}
	}
	return exploited
}

// GetCriticalCVEs returns all CRITICAL severity CVEs
func (m *IntelFeedManager) GetCriticalCVEs() []*ThreatIntel {
	m.cacheMu.RLock()
	defer m.cacheMu.RUnlock()

	var critical []*ThreatIntel
	for _, intel := range m.cache {
		if intel.Severity == SeverityCritical {
			critical = append(critical, intel)
		}
	}
	return critical
}

// EnrichVulnerability enriches a Vulnerability with threat intelligence
func (m *IntelFeedManager) EnrichVulnerability(v *Vulnerability) {
	// Try to find matching CVE
	var intel *ThreatIntel

	if strings.HasPrefix(v.ID, "CVE-") {
		intel = m.LookupCVE(v.ID)
	} else if strings.HasPrefix(v.ID, "GHSA-") {
		// For GHSA, we might have a CVE reference
		for _, ref := range v.References {
			if cve := extractCVE(ref); cve != "" {
				intel = m.LookupCVE(cve)
				break
			}
		}
	}

	if intel == nil {
		return
	}

	// Enrich the vulnerability
	if intel.CVSSv3Score > 0 {
		v.CVSS = intel.CVSSv3Score
	}
	if intel.Description != "" && v.Description == "" {
		v.Description = intel.Description
	}
	if intel.ExploitedInWild {
		v.Metadata["exploited_in_wild"] = "true"
		// Elevate severity if exploited
		if v.Severity != SeverityCritical {
			v.Severity = SeverityCritical
			v.Metadata["severity_elevated"] = "true"
			v.Metadata["elevation_reason"] = "Active exploitation detected"
		}
	}
	v.References = append(v.References, intel.References...)
}

// extractCVE extracts the first CVE ID (format CVE-YYYY-NNNNN) from a text string.
// Uses index scanning with character boundary detection to handle variable-length IDs.
// Returns empty string if no CVE ID is found.
func extractCVE(text string) string {
	// Scan for "CVE-" prefix, then walk forward while chars are digits or dashes
	if strings.Contains(text, "CVE-") {
		start := strings.Index(text, "CVE-")
		if start >= 0 {
			end := start + 17 // CVE-YYYY-NNNNN is max 17 chars
			if end > len(text) {
				end = len(text)
			}
			candidate := text[start:end]
			// Find where the CVE ID ends
			for i, c := range candidate {
				if i > 3 && c != '-' && (c < '0' || c > '9') {
					return candidate[:i]
				}
			}
			return candidate
		}
	}
	return ""
}

// Stats returns statistics about the cached intelligence
func (m *IntelFeedManager) Stats() map[string]int {
	m.cacheMu.RLock()
	defer m.cacheMu.RUnlock()

	stats := map[string]int{
		"total":     len(m.cache),
		"critical":  0,
		"high":      0,
		"moderate":  0,
		"low":       0,
		"exploited": 0,
	}

	for _, intel := range m.cache {
		switch intel.Severity {
		case SeverityCritical:
			stats["critical"]++
		case SeverityHigh:
			stats["high"]++
		case SeverityModerate:
			stats["moderate"]++
		case SeverityLow:
			stats["low"]++
		}
		if intel.ExploitedInWild {
			stats["exploited"]++
		}
	}

	return stats
}
