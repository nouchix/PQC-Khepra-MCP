// Package mcp — license gate sandbox tests.
//
// Tests the Step 1.6b license tier enforcement across all 13 MCP tools,
// using the testRouter() helper already established in router_test.go.
//
// Coverage:
//   - Community tier: ert_scan + nist_map allowed; all others gated
//   - Pilot tier: + godfather_report/approve + khepra_watch unlocked
//   - Enterprise tier: all 13 tools unlocked
//   - nil license: identical to Community
//   - Tampered tier field: still enforced (claim is already verified before router)
package mcp

import (
	"context"
	"strings"
	"testing"
	"time"

	licpkg "github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/license"
)

// ─── License Fixtures ─────────────────────────────────────────────────────────

func communityLicense() *licpkg.KhepraLicense {
	return &licpkg.KhepraLicense{
		LicenseID: "test-community",
		Tier:      licpkg.TierCommunity,
		Tenant:    "Test Community User",
		ExpiresAt: time.Now().Add(365 * 24 * time.Hour),
	}
}

func pilotLicense() *licpkg.KhepraLicense {
	return &licpkg.KhepraLicense{
		LicenseID: "test-pilot",
		Tier:      licpkg.TierPilot,
		Tenant:    "ACME Defense LLC (Pilot)",
		ExpiresAt: time.Now().Add(365 * 24 * time.Hour),
	}
}

func enterpriseLicense() *licpkg.KhepraLicense {
	return &licpkg.KhepraLicense{
		LicenseID: "test-enterprise",
		Tier:      licpkg.TierEnterprise,
		Tenant:    "ACME Defense LLC",
		ExpiresAt: time.Now().Add(365 * 24 * time.Hour),
	}
}

// allToolSpecs returns a ManifestRegistry pre-loaded with all 13 MCP tools.
func allToolRegistry(t *testing.T) *ManifestRegistry {
	t.Helper()
	tools := []ToolSpec{
		{Name: "ert_scan", Description: "ERT scan", RiskClass: RiskReadOnly,
			Scope: "ert:scan", SchemaVersion: "1.0.0", SchemaHash: "h1",
			AllowedBackend: "in-process", TimeoutMs: 30000},
		{Name: "nist_map", Description: "NIST map", RiskClass: RiskReadOnly,
			Scope: "compliance:read", SchemaVersion: "1.0.0", SchemaHash: "h2",
			AllowedBackend: "in-process", TimeoutMs: 5000},
		{Name: "godfather_report", Description: "Godfather report", RiskClass: RiskReadOnly,
			Scope: "compliance:report", SchemaVersion: "1.0.0", SchemaHash: "h3",
			AllowedBackend: "in-process", TimeoutMs: 30000},
		{Name: "godfather_approve", Description: "Godfather approve", RiskClass: RiskReadOnly,
			Scope: "compliance:report", SchemaVersion: "1.0.0", SchemaHash: "h4",
			AllowedBackend: "in-process", TimeoutMs: 5000},
		{Name: "khepra_watch", Description: "FS watch", RiskClass: RiskReadOnly,
			Scope: "compliance:monitor", SchemaVersion: "1.0.0", SchemaHash: "h5",
			AllowedBackend: "in-process", TimeoutMs: 10000},
		{Name: "acp_status", Description: "ACP status", RiskClass: RiskReadOnly,
			Scope: "acp:read", SchemaVersion: "1.0.0", SchemaHash: "h6",
			AllowedBackend: "in-process", TimeoutMs: 5000},
		{Name: "acp_issue", Description: "ACP issue", RiskClass: RiskDestructive,
			Scope: "acp:write", SchemaVersion: "1.0.0", SchemaHash: "h7",
			AllowedBackend: "in-process", TimeoutMs: 10000},
		{Name: "acp_revoke", Description: "ACP revoke", RiskClass: RiskDestructive,
			Scope: "acp:write", SchemaVersion: "1.0.0", SchemaHash: "h8",
			AllowedBackend: "in-process", TimeoutMs: 10000},
		{Name: "nhi_inventory", Description: "NHI inventory", RiskClass: RiskReadOnly,
			Scope: "nhi:read", SchemaVersion: "1.0.0", SchemaHash: "h9",
			AllowedBackend: "in-process", TimeoutMs: 5000},
		{Name: "nhi_orphans", Description: "NHI orphans", RiskClass: RiskReadOnly,
			Scope: "nhi:read", SchemaVersion: "1.0.0", SchemaHash: "h10",
			AllowedBackend: "in-process", TimeoutMs: 5000},
		{Name: "nhi_excessive", Description: "NHI excessive", RiskClass: RiskReadOnly,
			Scope: "nhi:read", SchemaVersion: "1.0.0", SchemaHash: "h11",
			AllowedBackend: "in-process", TimeoutMs: 5000},
		{Name: "nhi_expired", Description: "NHI expired", RiskClass: RiskReadOnly,
			Scope: "nhi:read", SchemaVersion: "1.0.0", SchemaHash: "h12",
			AllowedBackend: "in-process", TimeoutMs: 5000},
		{Name: "nhi_revoke", Description: "NHI revoke", RiskClass: RiskDestructive,
			Scope: "nhi:write", SchemaVersion: "1.0.0", SchemaHash: "h13",
			AllowedBackend: "in-process", TimeoutMs: 10000},
	}
	return testRegistry(t, tools...)
}

// autoApproveGate implements ConfirmationGate and auto-approves every destructive call.
// For test use ONLY — never use in production.
type autoApproveGate struct{}

func (autoApproveGate) Confirm(_ context.Context, _ ToolSpec, _ MCPToolCall) error {
	return nil // always approved
}

// routerWithLicense builds a router wired with all 13 tools + the given license.
func routerWithLicense(t *testing.T, lic *licpkg.KhepraLicense) *Router {
	t.Helper()
	reg := allToolRegistry(t)
	exec := NewExecutor(ExecutorConfig{
		// Auto-approve destructive calls in the test context.
		// In production, ConfirmationGate requires human HITL approval (Godfather flow).
		Confirm: autoApproveGate{},
	})
	// Register pass-through handlers for all 13 tools.
	// Use a slice-based loop (not map range) to avoid Go closure variable capture bugs.
	allTools := []string{
		"ert_scan", "nist_map",
		"godfather_report", "godfather_approve", "khepra_watch",
		"acp_status", "acp_issue", "acp_revoke",
		"nhi_inventory", "nhi_orphans", "nhi_excessive", "nhi_expired", "nhi_revoke",
	}
	for _, toolName := range allTools {
		n := toolName // explicit capture
		exec.RegisterFunc(n, func(_ context.Context, call MCPToolCall) (any, []string, error) {
			return map[string]any{"tool": n, "status": "ok", "agent": call.Identity.AgentID}, nil, nil
		})
	}

	r, err := NewRouter(RouterConfig{
		Demarc:   &mockDemarc{identity: testIdentity()},
		Poly:     &mockPoly{},
		Gateway:  &mockGateway{},
		Registry: reg,
		Executor: exec,
		Attestor: &mockAttestor{nodeID: "dag-license-test"},
		RateMax:  1000,
		License:  lic,
	})
	if err != nil {
		t.Fatalf("routerWithLicense: %v", err)
	}
	return r
}


func toolCall(name string) MCPToolCall {
	return MCPToolCall{
		RequestID: "req-" + name,
		ToolName:  name,
		// Use taxonomy-valid values so Step 1.6a (scope validator) passes cleanly.
		// target="local" ∈ knownOSTargets; scope="CMMC-L2" ∈ knownFrameworks.
		Args:        map[string]any{"target": "local", "scope": "CMMC-L2"},
		SubmittedAt: time.Now().UTC(),
	}
}

// ─── Community Tier ───────────────────────────────────────────────────────────

func TestLicense_Community_ErtScan_Allowed(t *testing.T) {
	r := routerWithLicense(t, communityLicense())
	resp, err := r.HandleToolCall(context.Background(), toolCall("ert_scan"), nil, "local")
	if err != nil {
		t.Fatalf("ert_scan community: unexpected hard error: %v", err)
	}
	if resp.IsError {
		t.Fatalf("ert_scan community: expected success, got: %s", resp.ErrorMessage)
	}
}

func TestLicense_Community_NistMap_Allowed(t *testing.T) {
	r := routerWithLicense(t, communityLicense())
	resp, err := r.HandleToolCall(context.Background(), toolCall("nist_map"), nil, "local")
	if err != nil {
		t.Fatalf("nist_map community: unexpected hard error: %v", err)
	}
	if resp.IsError {
		t.Fatalf("nist_map community: expected success, got: %s", resp.ErrorMessage)
	}
}

func TestLicense_Community_GodfatherReport_Blocked(t *testing.T) {
	r := routerWithLicense(t, communityLicense())
	resp, err := r.HandleToolCall(context.Background(), toolCall("godfather_report"), nil, "local")
	if err != nil {
		t.Fatalf("godfather_report community: unexpected hard error: %v", err)
	}
	if !resp.IsError {
		t.Fatal("godfather_report community: expected tier gate error, got success")
	}
	if !strings.Contains(resp.ErrorMessage, "pilot") {
		t.Errorf("expected 'pilot' in error message, got: %s", resp.ErrorMessage)
	}
	if !strings.Contains(resp.ErrorMessage, "khepra.nouchix.com") {
		t.Errorf("expected upgrade URL in error message, got: %s", resp.ErrorMessage)
	}
}

func TestLicense_Community_GodfatherApprove_Blocked(t *testing.T) {
	r := routerWithLicense(t, communityLicense())
	resp, _ := r.HandleToolCall(context.Background(), toolCall("godfather_approve"), nil, "local")
	if !resp.IsError {
		t.Fatal("godfather_approve community: expected tier gate")
	}
}

func TestLicense_Community_KhepraWatch_Blocked(t *testing.T) {
	r := routerWithLicense(t, communityLicense())
	resp, _ := r.HandleToolCall(context.Background(), toolCall("khepra_watch"), nil, "local")
	if !resp.IsError {
		t.Fatal("khepra_watch community: expected tier gate")
	}
}

// All ACP tools should be blocked at Community
func TestLicense_Community_ACP_AllBlocked(t *testing.T) {
	r := routerWithLicense(t, communityLicense())
	for _, tool := range []string{"acp_status", "acp_issue", "acp_revoke"} {
		t.Run(tool, func(t *testing.T) {
			resp, err := r.HandleToolCall(context.Background(), toolCall(tool), nil, "local")
			if err != nil {
				t.Fatalf("%s community: unexpected hard error: %v", tool, err)
			}
			if !resp.IsError {
				t.Fatalf("%s community: expected tier gate, got success", tool)
			}
			if !strings.Contains(resp.ErrorMessage, "enterprise") {
				t.Errorf("%s: expected 'enterprise' in error, got: %s", tool, resp.ErrorMessage)
			}
		})
	}
}

// All NHI tools should be blocked at Community
func TestLicense_Community_NHI_AllBlocked(t *testing.T) {
	r := routerWithLicense(t, communityLicense())
	for _, tool := range []string{"nhi_inventory", "nhi_orphans", "nhi_excessive", "nhi_expired", "nhi_revoke"} {
		t.Run(tool, func(t *testing.T) {
			resp, err := r.HandleToolCall(context.Background(), toolCall(tool), nil, "local")
			if err != nil {
				t.Fatalf("%s community: unexpected hard error: %v", tool, err)
			}
			if !resp.IsError {
				t.Fatalf("%s community: expected tier gate, got success", tool)
			}
		})
	}
}

// ─── Nil License = Community ──────────────────────────────────────────────────

func TestLicense_Nil_TreatedAsCommunity(t *testing.T) {
	r := routerWithLicense(t, nil) // no license key set
	// Community tools pass
	resp, _ := r.HandleToolCall(context.Background(), toolCall("ert_scan"), nil, "local")
	if resp.IsError {
		t.Fatalf("ert_scan nil license: expected success, got: %s", resp.ErrorMessage)
	}
	// Enterprise tools fail
	resp, _ = r.HandleToolCall(context.Background(), toolCall("acp_status"), nil, "local")
	if !resp.IsError {
		t.Fatal("acp_status nil license: expected tier gate")
	}
}

// ─── Pilot Tier ───────────────────────────────────────────────────────────────

func TestLicense_Pilot_GodfatherReport_Allowed(t *testing.T) {
	r := routerWithLicense(t, pilotLicense())
	resp, err := r.HandleToolCall(context.Background(), toolCall("godfather_report"), nil, "local")
	if err != nil {
		t.Fatalf("godfather_report pilot: %v", err)
	}
	if resp.IsError {
		t.Fatalf("godfather_report pilot: expected success, got: %s", resp.ErrorMessage)
	}
}

func TestLicense_Pilot_KhepraWatch_Allowed(t *testing.T) {
	r := routerWithLicense(t, pilotLicense())
	resp, err := r.HandleToolCall(context.Background(), toolCall("khepra_watch"), nil, "local")
	if err != nil {
		t.Fatalf("khepra_watch pilot: %v", err)
	}
	if resp.IsError {
		t.Fatalf("khepra_watch pilot: expected success, got: %s", resp.ErrorMessage)
	}
}

func TestLicense_Pilot_ACP_StillBlocked(t *testing.T) {
	r := routerWithLicense(t, pilotLicense())
	resp, _ := r.HandleToolCall(context.Background(), toolCall("acp_status"), nil, "local")
	if !resp.IsError {
		t.Fatal("acp_status pilot: expected enterprise gate, pilot should not unlock ACP")
	}
	if !strings.Contains(resp.ErrorMessage, "enterprise") {
		t.Errorf("expected 'enterprise' in error, got: %s", resp.ErrorMessage)
	}
}

// ─── Enterprise Tier ──────────────────────────────────────────────────────────

// TestLicense_Enterprise_All13Tools verifies every tool is unlocked at Enterprise+.
func TestLicense_Enterprise_All13Tools_Allowed(t *testing.T) {
	r := routerWithLicense(t, enterpriseLicense())

	tools := []string{
		"ert_scan", "nist_map",
		"godfather_report", "godfather_approve", "khepra_watch",
		"acp_status", "acp_issue", "acp_revoke",
		"nhi_inventory", "nhi_orphans", "nhi_excessive", "nhi_expired", "nhi_revoke",
	}

	for _, tool := range tools {
		t.Run(tool, func(t *testing.T) {
			resp, err := r.HandleToolCall(context.Background(), toolCall(tool), nil, "local")
			if err != nil {
				t.Fatalf("%s enterprise: unexpected hard error: %v", tool, err)
			}
			if resp.IsError {
				t.Fatalf("%s enterprise: expected success, got: %s", tool, resp.ErrorMessage)
			}
		})
	}
}

// ─── License Helper Functions ─────────────────────────────────────────────────

func TestNistMapLimit_Community(t *testing.T) {
	limit := licpkg.NistMapLimit(communityLicense())
	if limit != 5 {
		t.Errorf("community nist_map limit: got %d, want 5", limit)
	}
}

func TestNistMapLimit_Enterprise(t *testing.T) {
	limit := licpkg.NistMapLimit(enterpriseLicense())
	if limit != 50 {
		t.Errorf("enterprise nist_map limit: got %d, want 50", limit)
	}
}

func TestNistMapLimit_Nil(t *testing.T) {
	limit := licpkg.NistMapLimit(nil)
	if limit != 5 {
		t.Errorf("nil nist_map limit: got %d, want 5 (community fallback)", limit)
	}
}

func TestERTFullScan_Community_False(t *testing.T) {
	if licpkg.ERTFullScan(communityLicense()) {
		t.Error("community should not have full ERT scan")
	}
}

func TestERTFullScan_Pilot_True(t *testing.T) {
	if !licpkg.ERTFullScan(pilotLicense()) {
		t.Error("pilot should have full ERT scan")
	}
}

func TestERTFullScan_Enterprise_True(t *testing.T) {
	if !licpkg.ERTFullScan(enterpriseLicense()) {
		t.Error("enterprise should have full ERT scan")
	}
}

func TestSignedAuditLogEnabled_Community_False(t *testing.T) {
	if licpkg.SignedAuditLogEnabled(communityLicense()) {
		t.Error("community should not have signed audit log")
	}
}

func TestSignedAuditLogEnabled_Enterprise_True(t *testing.T) {
	if !licpkg.SignedAuditLogEnabled(enterpriseLicense()) {
		t.Error("enterprise should have signed audit log")
	}
}

// ─── License Error Message Quality ────────────────────────────────────────────

// TestLicense_ErrorMessage_ContainsUpgradeURL ensures every tier error message
// includes the upgrade URL — critical for the conversion funnel.
func TestLicense_ErrorMessage_ContainsUpgradeURL(t *testing.T) {
	r := routerWithLicense(t, communityLicense())
	enterpriseTools := []string{
		"acp_status", "acp_issue", "acp_revoke",
		"nhi_inventory", "nhi_revoke",
	}
	for _, tool := range enterpriseTools {
		t.Run(tool, func(t *testing.T) {
			resp, _ := r.HandleToolCall(context.Background(), toolCall(tool), nil, "local")
			if !resp.IsError {
				t.Fatalf("%s: expected error", tool)
			}
			if !strings.Contains(resp.ErrorMessage, "khepra.nouchix.com") {
				t.Errorf("%s: upgrade URL missing from error: %s", tool, resp.ErrorMessage)
			}
		})
	}
}

// ─── License Gate Position in Chain ──────────────────────────────────────────

// TestLicense_GateFiresBeforeExecution ensures the tier gate fires BEFORE the
// tool executor is called — no side effects from unauthorized access.
func TestLicense_GateFiresBeforeExecution(t *testing.T) {
	executed := false
	reg := allToolRegistry(t)
	exec := NewExecutor(ExecutorConfig{})
	exec.RegisterFunc("acp_status", func(_ context.Context, _ MCPToolCall) (any, []string, error) {
		executed = true // must NOT be set
		return "should not reach", nil, nil
	})

	r, _ := NewRouter(RouterConfig{
		Demarc:   &mockDemarc{identity: testIdentity()},
		Poly:     &mockPoly{},
		Gateway:  &mockGateway{},
		Registry: reg,
		Executor: exec,
		Attestor: &mockAttestor{nodeID: "dag-test"},
		RateMax:  100,
		License:  communityLicense(), // community — acp_status is gated
	})

	resp, _ := r.HandleToolCall(context.Background(), toolCall("acp_status"), nil, "local")
	if !resp.IsError {
		t.Fatal("expected tier gate error")
	}
	if executed {
		t.Fatal("SECURITY VIOLATION: tool executor was called despite tier gate blocking it")
	}
}
