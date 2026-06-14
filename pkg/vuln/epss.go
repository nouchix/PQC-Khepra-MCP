// Package vuln — EPSS Client (AD-003: Primary exploit probability source)
//
// EPSSClient provides standalone, cacheable access to the FIRST.org EPSS API.
// It supports batch queries with rate limiting and in-memory caching to avoid
// redundant API calls across multiple enrichment passes.
//
// This client is used by:
//   - IntelFeedManager.FetchEPSS() for bulk enrichment
//   - Enricher.enrichSingle() for on-demand per-CVE lookups
//   - EA fitness functions for threat-weighted evolution

package vuln

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ──────────────────────────────────────────────────────────────────────────────
// Core Types
// ──────────────────────────────────────────────────────────────────────────────

// EPSSRecord represents a single CVE's EPSS score from FIRST.org.
type EPSSRecord struct {
	CVEID      string  `json:"cve"`
	EPSSScore  float64 `json:"epss"`       // 0.0–1.0: probability of exploitation in next 30 days
	Percentile float64 `json:"percentile"` // 0.0–1.0: relative ranking among all CVEs
	Date       string  `json:"date"`       // Date of the EPSS calculation
}

// EPSSRank classifies a CVE's exploit probability for triage.
type EPSSRank string

const (
	EPSSRankCritical EPSSRank = "critical" // ≥ 0.70 — imminent exploitation expected
	EPSSRankHigh     EPSSRank = "high"     // ≥ 0.40 — highly likely to be exploited
	EPSSRankMedium   EPSSRank = "medium"   // ≥ 0.10 — moderate exploitation probability
	EPSSRankLow      EPSSRank = "low"      // < 0.10 — low exploitation probability
)

// RankFromScore returns the EPSSRank for a given EPSS score.
func RankFromScore(score float64) EPSSRank {
	switch {
	case score >= 0.70:
		return EPSSRankCritical
	case score >= 0.40:
		return EPSSRankHigh
	case score >= 0.10:
		return EPSSRankMedium
	default:
		return EPSSRankLow
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// EPSSClient — Production-grade EPSS API client
// ──────────────────────────────────────────────────────────────────────────────

// EPSSClient handles batch queries to the FIRST.org EPSS API with caching
// and rate limiting.
type EPSSClient struct {
	httpClient *http.Client
	baseURL    string

	// In-memory cache: CVE ID → EPSSRecord
	cache   map[string]EPSSRecord
	cacheMu sync.RWMutex

	// Rate limiting state
	lastBatch time.Time
	rateLimit time.Duration // minimum interval between batch API calls

	// Batch configuration
	maxBatchSize int // max CVEs per API request (FIRST.org limit)
}

// NewEPSSClient creates an EPSSClient with production defaults.
func NewEPSSClient() *EPSSClient {
	return &EPSSClient{
		httpClient: &http.Client{Timeout: 15 * time.Second},
		baseURL:    "https://api.first.org/data/v1/epss",
		cache:      make(map[string]EPSSRecord),
		rateLimit:  1200 * time.Millisecond, // Respectful of FIRST.org
		maxBatchSize: 30,                    // API-recommended limit
	}
}

// EPSSClientOption configures EPSSClient behavior.
type EPSSClientOption func(*EPSSClient)

// WithEPSSRateLimit sets the minimum interval between batch API calls.
func WithEPSSRateLimit(d time.Duration) EPSSClientOption {
	return func(c *EPSSClient) { c.rateLimit = d }
}

// WithEPSSBaseURL overrides the API endpoint (useful for testing).
func WithEPSSBaseURL(url string) EPSSClientOption {
	return func(c *EPSSClient) { c.baseURL = url }
}

// WithEPSSHTTPClient overrides the HTTP client (useful for mocking).
func WithEPSSHTTPClient(client *http.Client) EPSSClientOption {
	return func(c *EPSSClient) { c.httpClient = client }
}

// NewEPSSClientWithOptions creates a configured EPSSClient.
func NewEPSSClientWithOptions(opts ...EPSSClientOption) *EPSSClient {
	c := NewEPSSClient()
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// ──────────────────────────────────────────────────────────────────────────────
// Public API
// ──────────────────────────────────────────────────────────────────────────────

// BatchGet fetches EPSS scores for multiple CVEs. It returns only records
// that were successfully retrieved. Cache hits skip the API call.
//
// CVE IDs are deduplicated and filtered for valid "CVE-" prefixes.
// Rate limiting is automatically applied between batches.
func (c *EPSSClient) BatchGet(ctx context.Context, cveIDs []string) (map[string]EPSSRecord, error) {
	if len(cveIDs) == 0 {
		return make(map[string]EPSSRecord), nil
	}

	// Deduplicate and validate
	toFetch := c.getMissing(cveIDs)
	if len(toFetch) == 0 {
		// Everything is cached — return immediately
		return c.getFromCache(cveIDs), nil
	}

	// Batch fetch in chunks
	for i := 0; i < len(toFetch); i += c.maxBatchSize {
		end := i + c.maxBatchSize
		if end > len(toFetch) {
			end = len(toFetch)
		}
		batch := toFetch[i:end]

		// Rate limit
		c.cacheMu.RLock()
		elapsed := time.Since(c.lastBatch)
		c.cacheMu.RUnlock()
		if elapsed < c.rateLimit {
			select {
			case <-time.After(c.rateLimit - elapsed):
			case <-ctx.Done():
				return c.getFromCache(cveIDs), ctx.Err()
			}
		}

		if err := c.fetchBatch(ctx, batch); err != nil {
			// Non-fatal: log and return what we have from cache
			// This is graceful degradation per AD-008
			return c.getFromCache(cveIDs), fmt.Errorf("EPSS batch %d-%d: %w", i, end, err)
		}
	}

	return c.getFromCache(cveIDs), nil
}

// Lookup returns the cached EPSS record for a single CVE.
// Returns (record, true) if found, (zero, false) if not.
func (c *EPSSClient) Lookup(cveID string) (EPSSRecord, bool) {
	c.cacheMu.RLock()
	defer c.cacheMu.RUnlock()
	rec, ok := c.cache[cveID]
	return rec, ok
}

// CacheSize returns the number of cached EPSS records.
func (c *EPSSClient) CacheSize() int {
	c.cacheMu.RLock()
	defer c.cacheMu.RUnlock()
	return len(c.cache)
}

// Invalidate clears the cache for specific CVEs (or all if none specified).
func (c *EPSSClient) Invalidate(cveIDs ...string) {
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()
	if len(cveIDs) == 0 {
		c.cache = make(map[string]EPSSRecord)
		return
	}
	for _, id := range cveIDs {
		delete(c.cache, id)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Internal: API interaction
// ──────────────────────────────────────────────────────────────────────────────

// epssAPIResponse is the raw FIRST.org API response shape.
type epssAPIResponse struct {
	Status     string `json:"status"`
	StatusCode int    `json:"status-code"`
	Version    string `json:"version"`
	Total      int    `json:"total"`
	Data       []struct {
		CVE        string `json:"cve"`
		EPSS       string `json:"epss"`       // String in API response
		Percentile string `json:"percentile"` // String in API response
		Date       string `json:"date"`
	} `json:"data"`
}

// fetchBatch queries the FIRST.org EPSS API for a single batch of CVE IDs.
func (c *EPSSClient) fetchBatch(ctx context.Context, cveIDs []string) error {
	url := fmt.Sprintf("%s?cve=%s", c.baseURL, strings.Join(cveIDs, ","))

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "Khepra-ERT/1.0 (EPSS-enrichment)")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("EPSS API request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("EPSS API returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("EPSS API body read: %w", err)
	}

	var apiResp epssAPIResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return fmt.Errorf("EPSS API parse: %w", err)
	}

	// Update cache with parsed records
	c.cacheMu.Lock()
	for _, d := range apiResp.Data {
		c.cache[d.CVE] = EPSSRecord{
			CVEID:      d.CVE,
			EPSSScore:  parseFloat(d.EPSS),
			Percentile: parseFloat(d.Percentile),
			Date:       d.Date,
		}
	}
	c.lastBatch = time.Now()
	c.cacheMu.Unlock()

	return nil
}

// getMissing returns CVE IDs not already in the cache. Deduplicates and
// filters for valid CVE-prefixed IDs.
func (c *EPSSClient) getMissing(cveIDs []string) []string {
	c.cacheMu.RLock()
	defer c.cacheMu.RUnlock()

	seen := make(map[string]bool, len(cveIDs))
	var missing []string
	for _, id := range cveIDs {
		if !strings.HasPrefix(id, "CVE-") {
			continue
		}
		if seen[id] {
			continue
		}
		seen[id] = true
		if _, cached := c.cache[id]; !cached {
			missing = append(missing, id)
		}
	}
	return missing
}

// getFromCache returns all cached records matching the requested CVE IDs.
func (c *EPSSClient) getFromCache(cveIDs []string) map[string]EPSSRecord {
	c.cacheMu.RLock()
	defer c.cacheMu.RUnlock()

	result := make(map[string]EPSSRecord, len(cveIDs))
	for _, id := range cveIDs {
		if rec, ok := c.cache[id]; ok {
			result[id] = rec
		}
	}
	return result
}
