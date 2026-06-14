package ironbank

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	// HarborAPIBase is the Harbor v2 REST API base path on registry1.dso.mil.
	HarborAPIBase = "https://registry1.dso.mil/api/v2.0"
)

// Client is the Iron Bank Harbor v2 REST client.
// All requests are routed through the PQCTransport (AdinKhepra Firewall).
type Client struct {
	http     *http.Client
	username string
	secret   string // CLI secret (not password) — used as HTTP Basic Auth password
}

// NewClient creates a new Iron Bank client reading credentials from environment.
// Required env vars:
//
//	IRONBANK_USERNAME    — your registry1.dso.mil login
//	IRONBANK_CLI_SECRET  — your CLI secret (from registry1.dso.mil profile)
func NewClient() (*Client, error) {
	username := os.Getenv("IRONBANK_USERNAME")
	secret := os.Getenv("IRONBANK_CLI_SECRET")

	if username == "" {
		return nil, fmt.Errorf("ironbank: IRONBANK_USERNAME env var not set")
	}
	if secret == "" {
		return nil, fmt.Errorf("ironbank: IRONBANK_CLI_SECRET env var not set")
	}

	return NewClientWithCredentials(username, secret)
}

// NewClientWithCredentials creates a client with explicit credentials.
// Prefer NewClient() which reads from environment.
func NewClientWithCredentials(username, cliSecret string) (*Client, error) {
	if username == "" || cliSecret == "" {
		return nil, fmt.Errorf("ironbank: username and CLI secret are required")
	}

	transport, err := NewPQCTransport()
	if err != nil {
		return nil, fmt.Errorf("ironbank: failed to initialize PQC transport: %w", err)
	}

	return &Client{
		http: &http.Client{
			Transport: transport,
			Timeout:   requestTimeout,
		},
		username: username,
		secret:   cliSecret,
	}, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Harbor v2 API Methods
// ─────────────────────────────────────────────────────────────────────────────

// TriggerScan initiates a vulnerability scan on an artifact.
// targetURI format: "project/repository:tag" or "project/repository@sha256:..."
func (c *Client) TriggerScan(ctx context.Context, targetURI string) (string, error) {
	project, repo, ref, err := parseTargetURI(targetURI)
	if err != nil {
		return "", err
	}

	path := fmt.Sprintf("/projects/%s/repositories/%s/artifacts/%s/scan",
		url.PathEscape(project), url.PathEscape(repo), url.PathEscape(ref))

	resp, err := c.do(ctx, http.MethodPost, path, nil)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusAccepted || resp.StatusCode == http.StatusOK {
		// Harbor returns 202 Accepted with an operation header
		scanID := resp.Header.Get("X-Request-Id")
		if scanID == "" {
			scanID = fmt.Sprintf("scan-%d", time.Now().UnixNano())
		}
		return scanID, nil
	}

	return "", harborError(resp)
}

// GetScanOverview retrieves the vulnerability summary for an artifact.
func (c *Client) GetScanOverview(ctx context.Context, targetURI string) (*ScanOverview, error) {
	project, repo, ref, err := parseTargetURI(targetURI)
	if err != nil {
		return nil, err
	}

	path := fmt.Sprintf("/projects/%s/repositories/%s/artifacts/%s?with_scan_overview=true",
		url.PathEscape(project), url.PathEscape(repo), url.PathEscape(ref))

	resp, err := c.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, harborError(resp)
	}

	var artifact struct {
		ScanOverview map[string]*ScanOverview `json:"scan_overview"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&artifact); err != nil {
		return nil, fmt.Errorf("ironbank: failed to parse scan overview: %w", err)
	}

	// Return the first scanner's overview (usually only one)
	for _, overview := range artifact.ScanOverview {
		return overview, nil
	}
	return &ScanOverview{ScanStatus: "not_started"}, nil
}

// ListVulnerabilities retrieves vulnerabilities for an artifact from Harbor.
func (c *Client) ListVulnerabilities(ctx context.Context, targetURI string) ([]*HarborVulnerability, error) {
	project, repo, ref, err := parseTargetURI(targetURI)
	if err != nil {
		return nil, err
	}

	path := fmt.Sprintf("/projects/%s/repositories/%s/artifacts/%s/additions/vulnerabilities",
		url.PathEscape(project), url.PathEscape(repo), url.PathEscape(ref))

	resp, err := c.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, harborError(resp)
	}

	// Harbor returns: {"application/vnd.security.vulnerability.report; version=1.1": {"vulnerabilities": [...]}}
	var raw map[string]struct {
		Vulnerabilities []*HarborVulnerability `json:"vulnerabilities"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("ironbank: failed to parse vulnerability list: %w", err)
	}

	for _, report := range raw {
		return report.Vulnerabilities, nil
	}
	return []*HarborVulnerability{}, nil
}

// GetSBOM retrieves the SBOM addition for an artifact.
// format: "cyclonedx-json" (default) or "spdx-json"
func (c *Client) GetSBOM(ctx context.Context, targetURI, format string) ([]byte, error) {
	project, repo, ref, err := parseTargetURI(targetURI)
	if err != nil {
		return nil, err
	}

	if format == "" {
		format = "cyclonedx-json"
	}

	// Harbor SBOM endpoint (with media type negotiation)
	path := fmt.Sprintf("/projects/%s/repositories/%s/artifacts/%s/additions/sbom",
		url.PathEscape(project), url.PathEscape(repo), url.PathEscape(ref))

	req, err := c.newRequest(context.Background(), http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	// Set Accept header for SBOM format
	switch format {
	case "spdx-json":
		req.Header.Set("Accept", "application/vnd.spdx+json")
	default:
		req.Header.Set("Accept", "application/vnd.cyclonedx+json")
	}

	resp, err := c.http.Do(req.WithContext(ctx))
	if err != nil {
		return nil, fmt.Errorf("ironbank: SBOM request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, harborError(resp)
	}

	return io.ReadAll(resp.Body)
}

// ListProjects lists accessible Harbor projects (verifies connectivity).
func (c *Client) ListProjects(ctx context.Context) ([]*HarborProject, error) {
	resp, err := c.do(ctx, http.MethodGet, "/projects?page=1&page_size=50", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, harborError(resp)
	}

	var projects []*HarborProject
	if err := json.NewDecoder(resp.Body).Decode(&projects); err != nil {
		return nil, fmt.Errorf("ironbank: failed to parse projects: %w", err)
	}
	return projects, nil
}

// Ping verifies the Iron Bank connection and PQC transport are functional.
func (c *Client) Ping(ctx context.Context) error {
	resp, err := c.do(ctx, http.MethodGet, "/ping", nil)
	if err != nil {
		return fmt.Errorf("ironbank: ping failed — check IRONBANK_USERNAME/IRONBANK_CLI_SECRET: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ironbank: ping returned %d — credentials may be invalid", resp.StatusCode)
	}
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

func (c *Client) do(ctx context.Context, method, path string, body io.Reader) (*http.Response, error) {
	req, err := c.newRequest(ctx, method, path, body)
	if err != nil {
		return nil, err
	}
	return c.http.Do(req)
}

func (c *Client) newRequest(ctx context.Context, method, path string, body io.Reader) (*http.Request, error) {
	u := HarborAPIBase + path
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return nil, fmt.Errorf("ironbank: failed to build request: %w", err)
	}
	req.SetBasicAuth(c.username, c.secret)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return req, nil
}

// parseTargetURI splits "project/repository:tag" or "project/repository@sha256:..."
// into (project, repository, reference).
func parseTargetURI(targetURI string) (project, repo, ref string, err error) {
	if targetURI == "" {
		return "", "", "", fmt.Errorf("ironbank: targetURI is empty")
	}

	// Strip registry prefix if present
	if strings.HasPrefix(targetURI, "registry1.dso.mil/") {
		targetURI = strings.TrimPrefix(targetURI, "registry1.dso.mil/")
	}

	// Split digest reference: project/repo@sha256:abc → ref = "sha256:abc"
	if idx := strings.Index(targetURI, "@"); idx != -1 {
		ref = targetURI[idx+1:]
		targetURI = targetURI[:idx]
	}

	// Split tag: project/repo:tag → ref = "tag"
	if ref == "" {
		if idx := strings.LastIndex(targetURI, ":"); idx != -1 && !strings.Contains(targetURI[:idx], ":") {
			ref = targetURI[idx+1:]
			targetURI = targetURI[:idx]
		}
	}

	if ref == "" {
		ref = "latest"
	}

	// Split project/repo
	parts := strings.SplitN(targetURI, "/", 2)
	if len(parts) < 2 {
		return "", "", "", fmt.Errorf("ironbank: targetURI %q must be in format project/repository[:tag|@digest]", targetURI)
	}
	return parts[0], parts[1], ref, nil
}

// harborError reads a Harbor error response and returns a structured error.
func harborError(resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	var harborErr struct {
		Errors []struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"errors"`
	}
	if json.Unmarshal(body, &harborErr) == nil && len(harborErr.Errors) > 0 {
		return fmt.Errorf("ironbank: Harbor %d — %s: %s",
			resp.StatusCode, harborErr.Errors[0].Code, harborErr.Errors[0].Message)
	}
	return fmt.Errorf("ironbank: Harbor HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
}

// ─────────────────────────────────────────────────────────────────────────────
// Harbor v2 Types
// ─────────────────────────────────────────────────────────────────────────────

// ScanOverview represents Harbor's scan_overview for an artifact.
type ScanOverview struct {
	ScanStatus      string  `json:"scan_status"`
	Severity        string  `json:"severity"`
	Total           int     `json:"total"`
	Fixable         int     `json:"fixable"`
	Critical        int     `json:"critical"`
	High            int     `json:"high"`
	Medium          int     `json:"medium"`
	Low             int     `json:"low"`
	None            int     `json:"none"`
	Unknown         int     `json:"unknown"`
	ComplianceScore float64 `json:"compliance_score,omitempty"`
}

// HarborVulnerability represents a single CVE finding from Harbor.
type HarborVulnerability struct {
	ID          string   `json:"id"`
	Package     string   `json:"package"`
	Version     string   `json:"version"`
	FixVersion  string   `json:"fix_version"`
	Severity    string   `json:"severity"`
	CVSS3Score  float64  `json:"cvss3_score"`
	Description string   `json:"description"`
	Links       []string `json:"links"`
}

// HarborProject represents a Harbor project.
type HarborProject struct {
	Name      string `json:"name"`
	ProjectID int    `json:"project_id"`
	Public    bool   `json:"metadata.public"`
}
