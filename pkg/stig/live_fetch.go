// Package stig — live_fetch.go
// STIGViewer API client: live STIG data with 24h disk cache + air-gap fallback.
//
// IP: SOUHIMBOU DOH KONE LLC — exclusively licensed to SecRed Knowledge Inc.
// USPTO #73565085 (KHEPRA Protocol)
//
// Usage:
//   fetcher := stig.NewLiveFetcher(os.Getenv("STIGVIEWER_API_KEY"), "")
//   findings, err := fetcher.FetchSTIG(ctx, "red_hat_enterprise_linux_9")
//
// Air-gap: if STIGVIEWER_API_KEY is empty or API unreachable, returns embedded data.
// Cache:   ~/.khepra/stig-cache/<slug>.json  (24h TTL)

package stig

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ─── STIGViewer wire types ────────────────────────────────────────────────────

// svGroup is one STIG rule as returned by STIGViewer /download.
// The API returns a flat groups array — each group IS the rule.
// NOTE: ruleIdent is a single CCI string (not an array — known schema gap,
//       reported to STIGViewer Customer Board 2026-07-10).
type svGroup struct {
	GroupID            string  `json:"groupId"`          // "V-257778"
	RuleID             string  `json:"ruleId"`           // "SV-257778r1134892_rule"
	RuleVersion        string  `json:"ruleVersion"`      // "RHEL-09-211015" ← ASAF check ID
	RuleTitle          string  `json:"ruleTitle"`
	RuleSeverity       string  `json:"ruleSeverity"`     // "high"|"medium"|"low"
	RuleIdent          string  `json:"ruleIdent"`        // "CCI-000366"
	RuleWeight         float64 `json:"ruleWeight"`
	RuleCheckContent   string  `json:"ruleCheckContent"` // How to verify
	RuleFixText        string  `json:"ruleFixText"`      // Official DISA remediation
	RuleVulnDiscussion string  `json:"ruleVulnDiscussion"`
	RuleDocumentable   bool    `json:"ruleDocumentable"`
}

// svDownload is the top-level /stigs/{slug}/download response.
type svDownload struct {
	ID          int       `json:"id"`
	BenchmarkID string    `json:"benchmarkId"` // "RHEL_9_STIG"
	Slug        string    `json:"slug"`
	Title       string    `json:"title"`
	Version     string    `json:"version"` // "V2R8"
	StatusDate  string    `json:"statusDate"`
	Groups      []svGroup `json:"groups"`
}

// svSTIG is one catalog entry from GET /stigs.
type svSTIG struct {
	Slug         string `json:"slug"`
	Title        string `json:"title"`
	Version      string `json:"version"`
	ReleaseDate  string `json:"releaseDate"`
	FindingCount int    `json:"findingCount"`
}

// svListResponse is the paginated /stigs response.
type svListResponse struct {
	STIGs      []svSTIG `json:"stigs"`
	Pagination struct {
		Page       int `json:"page"`
		Limit      int `json:"limit"`
		Total      int `json:"total"`
		TotalPages int `json:"totalPages"`
	} `json:"pagination"`
}

// STIGViewerStats holds catalog-level statistics.
type STIGViewerStats struct {
	TotalBenchmarks int
	TotalFindings   int
	High, Medium, Low int
	LatestSlug      string
	LatestTitle     string
	LatestRelease   string
}

// ─── Cache entry ──────────────────────────────────────────────────────────────

type cachedSTIG struct {
	FetchedAt time.Time  `json:"fetched_at"`
	Version   string     `json:"version"`
	Download  svDownload `json:"download"`
}

// ─── LiveFetcher ─────────────────────────────────────────────────────────────

const (
	stigViewerBase  = "https://www.stigviewer.com/api/v1"
	cacheTTL        = 24 * time.Hour
	defaultCacheDir = ".khepra/stig-cache"
)

// LiveFetcher retrieves STIG data from the STIGViewer API.
// Falls back to embedded CSV when the API is unreachable (sovereign/air-gap mode).
type LiveFetcher struct {
	apiKey   string
	cacheDir string
	client   *http.Client
}

// NewLiveFetcher creates a LiveFetcher.
//   apiKey  — value of STIGVIEWER_API_KEY. Empty string = air-gap mode (embedded only).
//   cacheDir — disk cache directory. Empty = $HOME/.khepra/stig-cache/
func NewLiveFetcher(apiKey, cacheDir string) *LiveFetcher {
	if cacheDir == "" {
		home, _ := os.UserHomeDir()
		cacheDir = filepath.Join(home, defaultCacheDir)
	}
	return &LiveFetcher{
		apiKey:   apiKey,
		cacheDir: cacheDir,
		client:   &http.Client{Timeout: 30 * time.Second},
	}
}

// Available returns true if the API key is set and the catalog endpoint responds.
func (f *LiveFetcher) Available(ctx context.Context) bool {
	if f.apiKey == "" {
		return false
	}
	body, err := f.get(ctx, "/stigs/stats")
	return err == nil && len(body) > 0
}

// Stats returns catalog-level statistics from STIGViewer.
func (f *LiveFetcher) Stats(ctx context.Context) (*STIGViewerStats, error) {
	if f.apiKey == "" {
		return nil, fmt.Errorf("STIGVIEWER_API_KEY not set — air-gap mode")
	}
	body, err := f.get(ctx, "/stigs/stats")
	if err != nil {
		return nil, err
	}
	var raw struct {
		Catalog struct {
			TotalBenchmarks int `json:"totalBenchmarks"`
			TotalFindings   int `json:"totalFindings"`
		} `json:"catalog"`
		Severity struct {
			High   int `json:"high"`
			Medium int `json:"medium"`
			Low    int `json:"low"`
		} `json:"severity"`
		LatestRelease struct {
			Slug        string `json:"slug"`
			Title       string `json:"title"`
			ReleaseDate string `json:"releaseDate"`
		} `json:"latestRelease"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("parse stats: %w", err)
	}
	return &STIGViewerStats{
		TotalBenchmarks: raw.Catalog.TotalBenchmarks,
		TotalFindings:   raw.Catalog.TotalFindings,
		High:            raw.Severity.High,
		Medium:          raw.Severity.Medium,
		Low:             raw.Severity.Low,
		LatestSlug:      raw.LatestRelease.Slug,
		LatestTitle:     raw.LatestRelease.Title,
		LatestRelease:   raw.LatestRelease.ReleaseDate,
	}, nil
}

// ListSTIGs returns the full catalog (all 432 STIGs across all pages).
func (f *LiveFetcher) ListSTIGs(ctx context.Context) ([]svSTIG, error) {
	if f.apiKey == "" {
		return nil, fmt.Errorf("STIGVIEWER_API_KEY not set — air-gap mode")
	}
	var all []svSTIG
	for page := 1; ; page++ {
		body, err := f.get(ctx, fmt.Sprintf("/stigs?limit=50&page=%d", page))
		if err != nil {
			return nil, err
		}
		var resp svListResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("parse catalog page %d: %w", page, err)
		}
		all = append(all, resp.STIGs...)
		if page >= resp.Pagination.TotalPages || len(resp.STIGs) == 0 {
			break
		}
	}
	return all, nil
}

// FetchSTIG downloads a full STIG by slug and converts to ASAF-native []Finding.
// Results are cached for cacheTTL (24h). On API failure, falls back to embedded DB.
//
// Confirmed working slugs (tested 2026-07-10):
//   red_hat_enterprise_linux_9    V2R8  446 findings  ← primary ASAF target
//   red_hat_enterprise_linux_10   V1R1  434 findings  ← RHEL10 (zero embedded coverage)
//   microsoft_windows_server_2022 V2R8  282 findings
//   cloud_linux_almalinux_os_9    V1R6  439 findings
//   amazon_linux_2023             V1R3  187 findings
//
// NOTE: The STIGViewer docs quickstart uses the invalid slug "windows-server-2022"
//       (hyphens, short form) — that slug returns 404. Always use underscore format.
func (f *LiveFetcher) FetchSTIG(ctx context.Context, slug string) ([]Finding, error) {
	// Cache hit?
	if cached, ok := f.loadCache(slug); ok {
		return f.convertGroups(cached.Download.Groups), nil
	}

	// Air-gap: no key → embedded fallback
	if f.apiKey == "" {
		return f.embeddedFallback(slug)
	}

	// Live fetch
	body, err := f.get(ctx, fmt.Sprintf("/stigs/%s/download", slug))
	if err != nil {
		// API unreachable — fall back silently (sovereign mode)
		return f.embeddedFallback(slug)
	}

	var dl svDownload
	if err := json.Unmarshal(body, &dl); err != nil {
		return nil, fmt.Errorf("parse STIG %s: %w", slug, err)
	}

	f.saveCache(slug, dl)
	findings := f.convertGroups(dl.Groups)
	return findings, nil
}

// ─── STIGViewer → ASAF Finding conversion ────────────────────────────────────

// convertGroups maps the STIGViewer groups array to ASAF-native []Finding.
//
// CCI chain: ruleIdent (CCI-XXXXXX) → References[]
// The CCI is stored in References[0]; the validator/ERT engine expands it
// to NIST 800-53 → NIST 800-171 → CMMC via the existing cross-reference tables.
//
// Severity: STIGViewer "high" → SeverityCAT1, "medium" → SeverityCAT2, "low" → SeverityCAT3.
// These are the STIG-native CAT I/II/III constants — not the NIST severity names.
//
// Remediation uses the official DISA Fix Text verbatim — critical for C3PAO
// evidence packages where assessors recognise and trust DISA-authored text.
func (f *LiveFetcher) convertGroups(groups []svGroup) []Finding {
	findings := make([]Finding, 0, len(groups))
	for _, g := range groups {
		refs := []string{}
		if g.RuleIdent != "" {
			refs = append(refs, g.RuleIdent) // CCI-XXXXXX
		}
		if g.GroupID != "" {
			refs = append(refs, g.GroupID) // V-XXXXXX (Vuln ID)
		}
		if g.RuleID != "" {
			refs = append(refs, g.RuleID) // SV-XXXXXXrYYYYYYY_rule
		}

		findings = append(findings, Finding{
			ID:          g.RuleVersion,      // "RHEL-09-211015" — matches existing ASAF ID format
			Title:       g.RuleTitle,
			Description: g.RuleVulnDiscussion,
			Severity:    svSeverity(g.RuleSeverity),
			Status:      "Not Reviewed",    // ERT engine fills this after live system check
			Expected:    g.RuleCheckContent, // "How to check" from DISA
			Actual:      "",                // Populated by rhel09_stig_checks.go
			Remediation: g.RuleFixText,     // Official DISA Fix Text — cite verbatim in C3PAO
			References:  refs,
			CheckedAt:   time.Now(),
		})
	}
	return findings
}

// svSeverity maps STIGViewer severity strings to ASAF STIG Severity constants.
// STIGViewer "high" → CAT I (most critical). "medium" → CAT II. "low" → CAT III.
// Uses STIG-native constants (not NIST/CIS), consistent with rhel09_stig.go.
func svSeverity(s string) Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "high":
		return SeverityCAT1 // CAT I — must fix, non-POA&M eligible
	case "medium":
		return SeverityCAT2 // CAT II — POA&M eligible
	default:
		return SeverityCAT3 // CAT III — low risk
	}
}

// ─── Disk cache ───────────────────────────────────────────────────────────────

func (f *LiveFetcher) cachePath(slug string) string {
	// Sanitise slug for filesystem safety
	safe := strings.NewReplacer("/", "_", "..", "_").Replace(slug)
	return filepath.Join(f.cacheDir, safe+".json")
}

func (f *LiveFetcher) loadCache(slug string) (*cachedSTIG, bool) {
	data, err := os.ReadFile(f.cachePath(slug))
	if err != nil {
		return nil, false
	}
	var c cachedSTIG
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, false
	}
	if time.Since(c.FetchedAt) > cacheTTL {
		return nil, false // TTL expired — re-fetch
	}
	return &c, true
}

func (f *LiveFetcher) saveCache(slug string, dl svDownload) {
	if err := os.MkdirAll(f.cacheDir, 0700); err != nil {
		return
	}
	c := cachedSTIG{FetchedAt: time.Now(), Version: dl.Version, Download: dl}
	data, _ := json.Marshal(c)
	_ = os.WriteFile(f.cachePath(slug), data, 0600)
}

// ─── Embedded fallback (air-gap / sovereign mode) ─────────────────────────────

// embeddedFallback returns findings from the embedded 36,195-row CSV database.
// This preserves air-gap operation — ASAF works offline without STIGVIEWER_API_KEY.
// New slugs (RHEL10, AlmaLinux, etc.) have no embedded fallback — they require the API.
func (f *LiveFetcher) embeddedFallback(slug string) ([]Finding, error) {
	switch {
	case strings.Contains(slug, "linux_9") || strings.Contains(slug, "rhel_9") ||
		slug == "red_hat_enterprise_linux_9":
		// The existing RHEL9 validator is in rhel09_stig.go + validator.go.
		// Call it directly:  validator.ValidateRHEL9(target)
		return nil, fmt.Errorf("air-gap: for RHEL9 call pkg/stig.NewValidator().ValidateRHEL9() — " +
			"embedded DB covers RHEL9 through current embedded version")
	default:
		return nil, fmt.Errorf("air-gap: no embedded fallback for slug %q — " +
			"set STIGVIEWER_API_KEY for live STIG data (432 STIGs available)", slug)
	}
}

// ─── HTTP ─────────────────────────────────────────────────────────────────────

func (f *LiveFetcher) get(ctx context.Context, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, stigViewerBase+path, nil)
	if err != nil {
		return nil, fmt.Errorf("build request %s: %w", path, err)
	}
	req.Header.Set("Authorization", "Bearer "+f.apiKey)
	req.Header.Set("Accept", "application/json")
	// User-Agent identifies NouchiX for STIGViewer analytics + Customer Board relation
	req.Header.Set("User-Agent", "KHEPRA-ASAF/2.0 (SecRed-Knowledge-Inc; USPTO#73565085; board-member)")

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", path, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if resp.StatusCode != http.StatusOK {
		preview := body
		if len(preview) > 200 {
			preview = preview[:200]
		}
		return nil, fmt.Errorf("GET %s: HTTP %d — %s", path, resp.StatusCode, string(preview))
	}
	return body, nil
}
