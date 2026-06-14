//go:build saas

// Package supabase provides a lightweight Go client for Supabase REST API,
// enabling Go-based agents (KASA/DEMARC) to persist DAG nodes, scan results,
// compliance events, and MCP tool call audit logs to Supabase Postgres.
//
// Architecture role: The Supabase client is the "Long-Term Persistent Memory"
// layer — complementing the in-memory DAG (short-term memory) with durable,
// queryable storage backed by Supabase Postgres + Realtime.
//
// Integration points:
//   - pkg/dag        → persist DAG nodes to supabase (mcp_dag_nodes table)
//   - pkg/gateway    → persist MCP tool call audit logs
//   - pkg/apiserver  → persist scan results, compliance scores
//   - services/ml_anomaly → read/write anomaly detections via REST
package supabase

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client is a Supabase REST API client with PQC-aware service authentication.
type Client struct {
	projectURL string
	anonKey    string
	serviceKey string
	httpClient *http.Client
	schema     string
}

// Config holds Supabase connection settings.
type Config struct {
	ProjectURL     string        // e.g. "https://xjknkjbrjgljuovaazeu.supabase.co"
	AnonKey        string        // Public anon key
	ServiceRoleKey string        // Service role key (server-side only, never in browser)
	Timeout        time.Duration // HTTP timeout (default: 15s)
}

// NewClient creates a new Supabase REST client.
// Use ServiceRoleKey on the backend — it bypasses Row-Level Security.
func NewClient(cfg Config) *Client {
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 15 * time.Second
	}
	return &Client{
		projectURL: strings.TrimSuffix(cfg.ProjectURL, "/"),
		anonKey:    cfg.AnonKey,
		serviceKey: cfg.ServiceRoleKey,
		httpClient: &http.Client{Timeout: timeout},
		schema:     "public",
	}
}

// ─── Low-level REST helpers ────────────────────────────────────────────────────

func (c *Client) authHeader() string {
	if c.serviceKey != "" {
		return "Bearer " + c.serviceKey
	}
	return "Bearer " + c.anonKey
}

func (c *Client) apiKey() string {
	if c.serviceKey != "" {
		return c.serviceKey
	}
	return c.anonKey
}

func (c *Client) restURL(table string) string {
	return c.projectURL + "/rest/v1/" + table
}

func (c *Client) do(req *http.Request) ([]byte, int, error) {
	req.Header.Set("Authorization", c.authHeader())
	req.Header.Set("apikey", c.apiKey())
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Prefer", "return=representation")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("supabase http: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("supabase read body: %w", err)
	}

	if resp.StatusCode >= 400 {
		return body, resp.StatusCode, fmt.Errorf("supabase error %d: %s", resp.StatusCode, string(body))
	}

	return body, resp.StatusCode, nil
}

// Insert inserts one or more rows into a table. rows must be a slice of structs
// or maps that marshal to JSON objects. Returns the inserted rows.
func (c *Client) Insert(ctx context.Context, table string, rows interface{}) ([]byte, error) {
	data, err := json.Marshal(rows)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.restURL(table), bytes.NewBuffer(data))
	if err != nil {
		return nil, err
	}

	body, _, err := c.do(req)
	return body, err
}

// Select queries rows from a table. filter is a PostgREST filter string,
// e.g. "id=eq.123&status=eq.active". Pass "" to select all rows.
func (c *Client) Select(ctx context.Context, table string, filter string, columns string) ([]byte, error) {
	url := c.restURL(table)
	if columns != "" {
		url += "?select=" + columns
		if filter != "" {
			url += "&" + filter
		}
	} else if filter != "" {
		url += "?" + filter
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	body, _, err := c.do(req)
	return body, err
}

// Upsert inserts or updates rows. onConflict specifies the conflict column(s).
func (c *Client) Upsert(ctx context.Context, table string, rows interface{}, onConflict string) ([]byte, error) {
	data, err := json.Marshal(rows)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}

	url := c.restURL(table)
	if onConflict != "" {
		url += "?on_conflict=" + onConflict
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Prefer", "resolution=merge-duplicates,return=representation")

	body, _, err := c.do(req)
	return body, err
}

// Update updates rows matching filter. patch is a struct/map of fields to update.
func (c *Client) Update(ctx context.Context, table string, filter string, patch interface{}) ([]byte, error) {
	data, err := json.Marshal(patch)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}

	url := c.restURL(table)
	if filter != "" {
		url += "?" + filter
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, url, bytes.NewBuffer(data))
	if err != nil {
		return nil, err
	}

	body, _, err := c.do(req)
	return body, err
}

// Delete removes rows matching filter.
func (c *Client) Delete(ctx context.Context, table string, filter string) error {
	url := c.restURL(table)
	if filter != "" {
		url += "?" + filter
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return err
	}

	_, _, err = c.do(req)
	return err
}

// RPC calls a Supabase stored procedure (Postgres function) via PostgREST.
func (c *Client) RPC(ctx context.Context, fnName string, params interface{}) ([]byte, error) {
	data, err := json.Marshal(params)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}

	url := c.projectURL + "/rest/v1/rpc/" + fnName

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(data))
	if err != nil {
		return nil, err
	}

	body, _, err := c.do(req)
	return body, err
}

// ─── Health Check ──────────────────────────────────────────────────────────────

// Ping verifies connectivity to the Supabase project.
func (c *Client) Ping(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.projectURL+"/rest/v1/", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", c.authHeader())
	req.Header.Set("apikey", c.apiKey())

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("supabase unreachable: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNotFound {
		return nil
	}
	return fmt.Errorf("supabase ping: unexpected status %d", resp.StatusCode)
}
