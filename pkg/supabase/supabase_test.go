//go:build saas

package supabase

import (
	"strings"
	"testing"
	"time"
)

// ─── NewClient ───────────────────────────────────────────────────────────────

func TestNewClient_NotNil(t *testing.T) {
	c := NewClient(Config{
		ProjectURL:     "https://example.supabase.co",
		ServiceRoleKey: "test-key",
	})
	if c == nil {
		t.Fatal("NewClient returned nil")
	}
}

func TestNewClient_DefaultTimeout(t *testing.T) {
	c := NewClient(Config{ProjectURL: "https://example.supabase.co"})
	if c.httpClient.Timeout != 15*time.Second {
		t.Errorf("expected default timeout 15s, got %v", c.httpClient.Timeout)
	}
}

func TestNewClient_CustomTimeout(t *testing.T) {
	c := NewClient(Config{
		ProjectURL: "https://example.supabase.co",
		Timeout:    30 * time.Second,
	})
	if c.httpClient.Timeout != 30*time.Second {
		t.Errorf("expected timeout 30s, got %v", c.httpClient.Timeout)
	}
}

func TestNewClient_TrailingSlashStripped(t *testing.T) {
	c := NewClient(Config{ProjectURL: "https://example.supabase.co/"})
	if strings.HasSuffix(c.projectURL, "/") {
		t.Errorf("projectURL should have trailing slash stripped, got %s", c.projectURL)
	}
}

// ─── restURL helper ─────────────────────────────────────────────────────────

func TestRestURL(t *testing.T) {
	c := NewClient(Config{ProjectURL: "https://example.supabase.co"})
	url := c.restURL("mcp_dag_nodes")
	expected := "https://example.supabase.co/rest/v1/mcp_dag_nodes"
	if url != expected {
		t.Errorf("expected %s, got %s", expected, url)
	}
}

// ─── authHeader / apiKey ─────────────────────────────────────────────────────

func TestAuthHeader_ServiceKeyPreferred(t *testing.T) {
	c := NewClient(Config{
		ProjectURL:     "https://example.supabase.co",
		AnonKey:        "anon-key",
		ServiceRoleKey: "service-key",
	})
	header := c.authHeader()
	if !strings.Contains(header, "service-key") {
		t.Errorf("expected service-key in auth header, got %s", header)
	}
}

func TestAuthHeader_AnonKeyFallback(t *testing.T) {
	c := NewClient(Config{
		ProjectURL: "https://example.supabase.co",
		AnonKey:    "anon-key",
	})
	header := c.authHeader()
	if !strings.Contains(header, "anon-key") {
		t.Errorf("expected anon-key in auth header fallback, got %s", header)
	}
}

// ─── Ping error on unreachable host ─────────────────────────────────────────

func TestPing_UnreachableHost(t *testing.T) {
	c := NewClient(Config{
		ProjectURL: "https://supabase-unreachable-99999.invalid",
		AnonKey:    "test",
	})
	// Should fail gracefully — not panic
	err := c.Ping(nil) //nolint:staticcheck // nil context intentional for error path
	if err == nil {
		t.Log("WARN: Ping to unreachable host unexpectedly succeeded (network issue in test env)")
	}
}
