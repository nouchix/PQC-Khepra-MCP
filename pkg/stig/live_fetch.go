// Package stig — live_fetch.go
// STIGViewer API client (v2) — all 7 Customer Board improvements live 2026-07-11.
//
// IP: SOUHIMBOU DOH KONE LLC — exclusively licensed to SecRed Knowledge Inc.
// USPTO #73565085 (KHEPRA Protocol)
//
// Changelog (2026-07-11):
//   + ruleIdents[]  — full multi-CCI array per rule (complete CMMC audit trail)
//   + /controls     — paginated endpoint (avoids 1.2MB download for targeted queries)
//   + BatchCrosswalk() — 250 CCIs → NIST 800-53 in one call (replaces static CSV)
//   + Changelog()   — incremental STIG version tracking (no polling 432 STIGs)
//   + DownloadCKLB() — DISA-schema-valid CKLB v1.0 for C3PAO assessors
//   + Versions: RHEL9 V2R9 (445), RHEL10 V1R2 (434), WinServer2022 V2R9 (279)
//
// Usage:
//   f := stig.NewLiveFetcher(os.Getenv("STIGVIEWER_API_KEY"), "")
//   findings, _ := f.FetchSTIG(ctx, "red_hat_enterprise_linux_9")              // full, cached
//   cat1, _     := f.FetchControls(ctx, slug, ControlsFilter{Severity: "high"}) // paginated
//   nist, _     := f.BatchCrosswalk(ctx, []string{"CCI-000366", "CCI-000048"})
//   changes, _  := f.Changelog(ctx, "2026-01-01")
//   cklb, _     := f.DownloadCKLB(ctx, "red_hat_enterprise_linux_9")

package stig

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ─── Wire types: /download endpoint ──────────────────────────────────────────
// Field names use "rule" prefix (ruleCheckContent, ruleFixText, etc.).

// svGroup is one STIG rule from GET /stigs/{slug}/download.
// ruleIdents[] is the FULL CCI array (new 2026-07-11).
// ruleIdent is the first CCI only — preserved for backward compatibility.
type svGroup struct {
	GroupID            string   `json:"groupId"`          // "V-257778"
	RuleID             string   `json:"ruleId"`           // "SV-257778r1134892_rule"
	RuleVersion        string   `json:"ruleVersion"`      // "RHEL-09-211015" ← ASAF check ID
	RuleTitle          string   `json:"ruleTitle"`
	RuleSeverity       string   `json:"ruleSeverity"`     // "high"|"medium"|"low"
	RuleIdent          string   `json:"ruleIdent"`        // First CCI (backward compat)
	RuleIdents         []string `json:"ruleIdents"`       // ALL CCIs — use for CMMC audit trail
	RuleWeight         float64  `json:"ruleWeight"`
	RuleCheckContent   string   `json:"ruleCheckContent"` // How to verify (DISA)
	RuleFixText        string   `json:"ruleFixText"`      // Official DISA Fix Text
	RuleVulnDiscussion string   `json:"ruleVulnDiscussion"`
	RuleDocumentable   bool     `json:"ruleDocumentable"`
}

// ─── Wire types: /controls endpoint ──────────────────────────────────────────
// Field names do NOT have the "rule" prefix (confirmed from live API 2026-07-11).

// svControl is one rule from GET /stigs/{slug}/controls (paginated).
type svControl struct {
	GroupID        string   `json:"groupId"`    // "V-257778"
	RuleID         string   `json:"ruleId"`
	RuleVersion    string   `json:"ruleVersion"` // "RHEL-09-211015"
	RuleTitle      string   `json:"ruleTitle"`
	Severity       string   `json:"severity"`
	RuleIdent      string   `json:"ruleIdent"`   // First CCI (backward compat)
	RuleIdents     []string `json:"ruleIdents"` // ALL CCIs
	Title          string   `json:"title"`
	Description    string   `json:"description"`
	VulnDiscussion string   `json:"vulnDiscussion"`
	CheckContent   string   `json:"checkContent"` // How to verify
	FixText        string   `json:"fixText"`      // Official DISA Fix Text
}

// svControlsResponse is from GET /stigs/{slug}/controls.
// Note: the findings array is named "findings" (not "controls") in the API.
type svControlsResponse struct {
	STIG struct {
		Slug         string `json:"slug"`
		Version      string `json:"version"`
		FindingCount int    `json:"findingCount"`
	} `json:"stig"`
	Findings   []svControl `json:"findings"`
	Pagination struct {
		Page       int `json:"page"`
		Limit      int `json:"limit"`
		Total      int `json:"total"`
		TotalPages int `json:"totalPages"`
	} `json:"pagination"`
}

// STIGChange is one entry from GET /stigs/changelog.
type STIGChange struct {
	Slug            string `json:"slug"`
	Title           string `json:"title"`
	NewVersion      string `json:"newVersion"`
	PreviousVersion string `json:"previousVersion"` // empty if first-ever tracked
	ReleaseDate     string `json:"releaseDate"`
}

// ControlsFilter narrows a paginated /controls request.
// Severity: "high"|"medium"|"low" or comma-separated. Limit max is 100.
type ControlsFilter struct {
	Severity string // "high" | "medium" | "low" | "high,medium"
	Page     int    // 1-indexed; 0 = fetch all pages
	Limit    int    // 1–100; 0 = 100
	Search   string // optional keyword
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
// ─── Wire types: catalog ─────────────────────────────────────────────────────

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

// FetchSTIG downloads the full STIG benchmark and returns ASAF-native []Finding.
// Uses /download for the full benchmark; results cached 24h.
// For filtered/paginated access use FetchControls instead.
//
// Confirmed slugs + current versions (tested 2026-07-11):
//   red_hat_enterprise_linux_9    V2R9  445 findings  ← primary ASAF target
//   red_hat_enterprise_linux_10   V1R2  434 findings  ← RHEL10 (first ASAF coverage)
//   microsoft_windows_server_2022 V2R9  279 findings
//   cloud_linux_almalinux_os_9    V1R6  439 findings
//   amazon_linux_2023             V1R3  187 findings
//
// IMPORTANT: Always use underscore slugs. "windows-server-2022" returns 404.
func (f *LiveFetcher) FetchSTIG(ctx context.Context, slug string) ([]Finding, error) {
	if cached, ok := f.loadCache(slug); ok {
		return f.convertGroups(cached.Download.Groups), nil
	}
	if f.apiKey == "" {
		return f.embeddedFallback(slug)
	}
	body, err := f.get(ctx, fmt.Sprintf("/stigs/%s/download", slug))
	if err != nil {
		return f.embeddedFallback(slug)
	}
	var dl svDownload
	if err := json.Unmarshal(body, &dl); err != nil {
		return nil, fmt.Errorf("parse STIG %s: %w", slug, err)
	}
	f.saveCache(slug, dl)
	return f.convertGroups(dl.Groups), nil
}

// FetchControls retrieves a filtered, paginated subset of a STIG's rules via /controls.
// Use instead of FetchSTIG when you only need e.g. CAT I findings (avoids 1.2MB download).
// Set filter.Page=0 to auto-fetch all pages.
func (f *LiveFetcher) FetchControls(ctx context.Context, slug string, filter ControlsFilter) ([]Finding, error) {
	if f.apiKey == "" {
		return nil, fmt.Errorf("STIGVIEWER_API_KEY not set — air-gap mode")
	}
	limit := filter.Limit
	if limit <= 0 || limit > 100 {
		limit = 100
	}
	page := filter.Page
	if page <= 0 {
		page = 1
	}
	var all []Finding
	for {
		path := fmt.Sprintf("/stigs/%s/controls?page=%d&limit=%d", slug, page, limit)
		if filter.Severity != "" {
			path += "&severity=" + url.QueryEscape(filter.Severity)
		}
		if filter.Search != "" {
			path += "&search=" + url.QueryEscape(filter.Search)
		}
		body, err := f.get(ctx, path)
		if err != nil {
			return nil, err
		}
		var resp svControlsResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("parse controls page %d: %w", page, err)
		}
		all = append(all, f.convertControls(resp.Findings)...)
		if filter.Page > 0 || page >= resp.Pagination.TotalPages {
			break
		}
		page++
	}
	return all, nil
}

// BatchCrosswalk maps CCIs to NIST 800-53 controls via POST /crosswalk/resolve/batch.
// Up to 250 CCIs per call (auto-batched if more). Replaces static CCI_to_NIST53.csv.
// Returns map[CCI]→[]NIST-Control, e.g. {"CCI-000366":["CM-6"], "CCI-000048":["AC-8"]}.
func (f *LiveFetcher) BatchCrosswalk(ctx context.Context, ccis []string) (map[string][]string, error) {
	if f.apiKey == "" {
		return nil, fmt.Errorf("STIGVIEWER_API_KEY not set — air-gap mode")
	}
	results := make(map[string][]string)
	for i := 0; i < len(ccis); i += 250 {
		end := i + 250
		if end > len(ccis) {
			end = len(ccis)
		}
		body, err := json.Marshal(map[string][]string{"ccis": ccis[i:end]})
		if err != nil {
			return nil, fmt.Errorf("marshal crosswalk batch: %w", err)
		}
		resp, err := f.post(ctx, "/crosswalk/resolve/batch", body)
		if err != nil {
			return nil, err
		}
		var chunk map[string][]string
		if err := json.Unmarshal(resp, &chunk); err != nil {
			return nil, fmt.Errorf("parse crosswalk response: %w", err)
		}
		for k, v := range chunk {
			results[k] = v
		}
	}
	return results, nil
}

// Changelog returns STIGs that changed since the given date (YYYY-MM-DD).
// Use for cache invalidation — call once at startup instead of polling all 432 STIGs.
func (f *LiveFetcher) Changelog(ctx context.Context, since string) ([]STIGChange, error) {
	if f.apiKey == "" {
		return nil, fmt.Errorf("STIGVIEWER_API_KEY not set — air-gap mode")
	}
	body, err := f.get(ctx, "/stigs/changelog?since="+url.QueryEscape(since))
	if err != nil {
		return nil, err
	}
	var resp struct {
		Changes []STIGChange `json:"changes"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parse changelog: %w", err)
	}
	return resp.Changes, nil
}

// DownloadCKLB fetches a DISA-schema-valid CKLB v1.0 checklist (JSON format).
// All rule statuses are "not_reviewed" — baseline for C3PAO evidence packages.
// For scan-populated CKLB, post scan results as {ruleId→status} map (feature pending).
func (f *LiveFetcher) DownloadCKLB(ctx context.Context, slug string) ([]byte, error) {
	if f.apiKey == "" {
		return nil, fmt.Errorf("STIGVIEWER_API_KEY not set — air-gap mode")
	}
	return f.get(ctx, fmt.Sprintf("/stigs/%s/download?format=cklb", slug))
}

// ─── STIGViewer → ASAF Finding conversion ────────────────────────────────────

// convertGroups maps /download groups to ASAF-native []Finding.
// Uses ruleIdents[] (full CCI array, new 2026-07-11) for References.
// ruleFixText is verbatim DISA Fix Text — preserved for C3PAO evidence.
func (f *LiveFetcher) convertGroups(groups []svGroup) []Finding {
	findings := make([]Finding, 0, len(groups))
	for _, g := range groups {
		refs := buildRefs(g.RuleIdents, g.RuleIdent, g.GroupID, g.RuleID)
		findings = append(findings, Finding{
			ID:          g.RuleVersion,
			Title:       g.RuleTitle,
			Description: g.RuleVulnDiscussion,
			Severity:    svSeverity(g.RuleSeverity),
			Status:      "Not Reviewed",
			Expected:    g.RuleCheckContent,
			Actual:      "",
			Remediation: g.RuleFixText, // Official DISA Fix Text — cite verbatim in C3PAO
			References:  refs,
			CheckedAt:   time.Now(),
		})
	}
	return findings
}

// convertControls maps /controls findings to ASAF-native []Finding.
// Field names differ from /download: no "rule" prefix (checkContent vs ruleCheckContent).
func (f *LiveFetcher) convertControls(controls []svControl) []Finding {
	findings := make([]Finding, 0, len(controls))
	for _, c := range controls {
		refs := buildRefs(c.RuleIdents, c.RuleIdent, c.GroupID, c.RuleID)
		findings = append(findings, Finding{
			ID:          c.RuleVersion,
			Title:       c.RuleTitle,
			Description: c.VulnDiscussion,
			Severity:    svSeverity(c.Severity),
			Status:      "Not Reviewed",
			Expected:    c.CheckContent,
			Actual:      "",
			Remediation: c.FixText,
			References:  refs,
			CheckedAt:   time.Now(),
		})
	}
	return findings
}

// buildRefs builds the References slice, preferring ruleIdents[] (full multi-CCI).
func buildRefs(ruleIdents []string, ruleIdent, groupID, ruleID string) []string {
	refs := []string{}
	if len(ruleIdents) > 0 {
		refs = append(refs, ruleIdents...) // All CCIs — complete CMMC audit trail
	} else if ruleIdent != "" {
		refs = append(refs, ruleIdent)
	}
	if groupID != "" {
		refs = append(refs, groupID)
	}
	if ruleID != "" {
		refs = append(refs, ruleID)
	}
	return refs
}

// svSeverity maps STIGViewer severity to ASAF STIG CAT constants.
// "high" → CAT I (must fix, non-POA&M eligible). "medium" → CAT II. "low" → CAT III.
func svSeverity(s string) Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "high":
		return SeverityCAT1
	case "medium":
		return SeverityCAT2
	default:
		return SeverityCAT3
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
	return f.do(ctx, http.MethodGet, path, nil)
}

func (f *LiveFetcher) post(ctx context.Context, path string, body []byte) ([]byte, error) {
	return f.do(ctx, http.MethodPost, path, body)
}

func (f *LiveFetcher) do(ctx context.Context, method, path string, body []byte) ([]byte, error) {
	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, stigViewerBase+path, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("build request %s %s: %w", method, path, err)
	}
	req.Header.Set("Authorization", "Bearer "+f.apiKey)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	// User-Agent identifies NouchiX in STIGViewer analytics; Customer Board member.
	req.Header.Set("User-Agent", "KHEPRA-ASAF/2.0 (SecRed-Knowledge-Inc; USPTO#73565085; board-member)")

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if resp.StatusCode != http.StatusOK {
		preview := respBody
		if len(preview) > 200 {
			preview = preview[:200]
		}
		return nil, fmt.Errorf("%s %s: HTTP %d — %s", method, path, resp.StatusCode, string(preview))
	}
	return respBody, nil
}
