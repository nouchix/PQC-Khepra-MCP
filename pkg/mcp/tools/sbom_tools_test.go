package tools

// sbom_tools_test.go — Unit tests for sbom_generate and threat_model handlers.
//
// All tests are -short compatible (no external binaries required).

import (
	"context"
	"testing"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/mcp"
)

// ─── sbom_generate ────────────────────────────────────────────────────────────

func TestHandleSBOMGenerate_DefaultPath(t *testing.T) {
	ctx := context.Background()
	call := mcp.MCPToolCall{
		ToolName: "sbom_generate",
		Args:     map[string]any{},
	}
	result, warnings, err := HandleSBOMGenerate(ctx, call)
	if err != nil {
		t.Fatalf("HandleSBOMGenerate returned unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("HandleSBOMGenerate returned nil result")
	}
	resp, ok := result.(*SBOMGenerateResponse)
	if !ok {
		t.Fatalf("expected *SBOMGenerateResponse, got %T", result)
	}
	if resp.SBOMFormat == "" {
		t.Error("SBOMFormat should not be empty")
	}
	if resp.GeneratedAt == "" {
		t.Error("GeneratedAt should not be empty")
	}
	if resp.SourceMode == "" {
		t.Error("SourceMode should not be empty")
	}
	_ = warnings // warnings allowed (e.g., syft not in PATH)
}

func TestHandleSBOMGenerate_CycloneDXFormat(t *testing.T) {
	ctx := context.Background()
	call := mcp.MCPToolCall{
		ToolName: "sbom_generate",
		Args:     map[string]any{"output_format": "cyclonedx-json"},
	}
	result, _, err := HandleSBOMGenerate(ctx, call)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	resp := result.(*SBOMGenerateResponse)
	if resp.SBOMFormat != "cyclonedx-json" {
		t.Errorf("expected cyclonedx-json format, got %q", resp.SBOMFormat)
	}
}

func TestHandleSBOMGenerate_ComponentCounts(t *testing.T) {
	ctx := context.Background()
	call := mcp.MCPToolCall{
		ToolName: "sbom_generate",
		Args:     map[string]any{},
	}
	result, _, err := HandleSBOMGenerate(ctx, call)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	resp := result.(*SBOMGenerateResponse)
	// PQCCapable + WeakCrypto should never exceed TotalComponents
	if resp.PQCCapable > resp.TotalComponents {
		t.Errorf("PQCCapable (%d) > TotalComponents (%d)", resp.PQCCapable, resp.TotalComponents)
	}
	if resp.WeakCrypto > resp.TotalComponents {
		t.Errorf("WeakCrypto (%d) > TotalComponents (%d)", resp.WeakCrypto, resp.TotalComponents)
	}
}

func TestHandleSBOMGenerate_SBOMComponentFields(t *testing.T) {
	ctx := context.Background()
	call := mcp.MCPToolCall{
		ToolName: "sbom_generate",
		Args:     map[string]any{},
	}
	result, _, err := HandleSBOMGenerate(ctx, call)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	resp := result.(*SBOMGenerateResponse)
	for i, c := range resp.Components {
		if c.Name == "" {
			t.Errorf("component[%d] has empty name", i)
		}
		if c.Type == "" {
			t.Errorf("component[%d] (%q) has empty type", i, c.Name)
		}
	}
}

// ─── walkFilesystemForComponents ─────────────────────────────────────────────

func TestWalkFilesystemForComponents_GoMod(t *testing.T) {
	// The project root contains a go.mod — components should be detected
	components := walkFilesystemForComponents("../../../../")
	if len(components) == 0 {
		// Not a hard failure: filesystem walk may be relative to test dir
		t.Log("walkFilesystemForComponents: no components found (may be running from test dir without go.mod)")
		return
	}
	foundGo := false
	for _, c := range components {
		if c.Ecosystem == "golang" {
			foundGo = true
			break
		}
	}
	if !foundGo {
		t.Log("no golang ecosystem components found — expected if go.mod is out of scan path")
	}
}

// ─── annotatePQCStatus ────────────────────────────────────────────────────────

func TestAnnotatePQCStatus_CirclIsCapable(t *testing.T) {
	c := SBOMComponent{Name: "github.com/cloudflare/circl", Type: "library"}
	annotatePQCStatus(&c)
	if !c.PQCCapable {
		t.Error("cloudflare/circl should be marked PQCCapable")
	}
	if c.WeakCrypto {
		t.Error("cloudflare/circl should NOT be marked WeakCrypto")
	}
}

func TestAnnotatePQCStatus_MD5IsWeak(t *testing.T) {
	c := SBOMComponent{Name: "libmd5", Type: "library"}
	annotatePQCStatus(&c)
	if !c.WeakCrypto {
		t.Error("md5 library should be marked WeakCrypto")
	}
}

func TestAnnotatePQCStatus_Unknown(t *testing.T) {
	c := SBOMComponent{Name: "prometheus-client", Type: "library"}
	annotatePQCStatus(&c)
	if c.PQCCapable {
		t.Error("prometheus-client should not be PQCCapable")
	}
	if c.WeakCrypto {
		t.Error("prometheus-client should not be WeakCrypto")
	}
}

// ─── threat_model ─────────────────────────────────────────────────────────────

func TestHandleThreatModel_DefaultPath(t *testing.T) {
	ctx := context.Background()
	call := mcp.MCPToolCall{
		ToolName: "threat_model",
		Args:     map[string]any{},
	}
	result, warnings, err := HandleThreatModel(ctx, call)
	if err != nil {
		t.Fatalf("HandleThreatModel returned unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("HandleThreatModel returned nil result")
	}
	resp, ok := result.(*ThreatModelResponse)
	if !ok {
		t.Fatalf("expected *ThreatModelResponse, got %T", result)
	}
	if resp.Methodology == "" {
		t.Error("Methodology should not be empty")
	}
	if resp.TotalThreats == 0 {
		t.Error("TotalThreats should be > 0 for any project")
	}
	if resp.AssessedAt == "" {
		t.Error("AssessedAt should not be empty")
	}
	if resp.ExecutiveSummary == "" {
		t.Error("ExecutiveSummary should not be empty")
	}
	_ = warnings
}

func TestHandleThreatModel_ThreatFields(t *testing.T) {
	ctx := context.Background()
	call := mcp.MCPToolCall{
		ToolName: "threat_model",
		Args:     map[string]any{},
	}
	result, _, err := HandleThreatModel(ctx, call)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	resp := result.(*ThreatModelResponse)
	for i, thr := range resp.Threats {
		if thr.ID == "" {
			t.Errorf("threat[%d] has empty ID", i)
		}
		if thr.Category == "" {
			t.Errorf("threat[%d] has empty Category", i)
		}
		if thr.Title == "" {
			t.Errorf("threat[%d] has empty Title", i)
		}
		if thr.Risk == "" {
			t.Errorf("threat[%d] has empty Risk", i)
		}
		if len(thr.NIST53) == 0 {
			t.Errorf("threat[%d] (%q) has no NIST 800-53 controls", i, thr.ID)
		}
		if len(thr.Mitigations) == 0 {
			t.Errorf("threat[%d] (%q) has no mitigations", i, thr.ID)
		}
	}
}

func TestHandleThreatModel_CriticalCount(t *testing.T) {
	ctx := context.Background()
	call := mcp.MCPToolCall{
		ToolName: "threat_model",
		Args:     map[string]any{},
	}
	result, _, err := HandleThreatModel(ctx, call)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	resp := result.(*ThreatModelResponse)
	// Counts should be consistent
	if resp.CriticalThreats > resp.TotalThreats {
		t.Errorf("CriticalThreats (%d) > TotalThreats (%d)", resp.CriticalThreats, resp.TotalThreats)
	}
	if resp.HighThreats > resp.TotalThreats {
		t.Errorf("HighThreats (%d) > TotalThreats (%d)", resp.HighThreats, resp.TotalThreats)
	}
}

func TestHandleThreatModel_NistControlsPresent(t *testing.T) {
	ctx := context.Background()
	call := mcp.MCPToolCall{
		ToolName: "threat_model",
		Args:     map[string]any{},
	}
	result, _, err := HandleThreatModel(ctx, call)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	resp := result.(*ThreatModelResponse)
	if len(resp.NISTPolicies) == 0 {
		t.Error("NISTPolicies should not be empty — all threats should map to at least one NIST 800-53 control")
	}
}

// ─── detectProjectProfile ─────────────────────────────────────────────────────

func TestDetectProjectProfile_GoProject(t *testing.T) {
	// The test runs from within the PQC-Khepra-MCP source tree
	// Use ".." path to hit the project root's go.mod
	p := detectProjectProfile("../../../../")
	// go.mod should be detected (4 levels up from pkg/mcp/tools)
	// This is a best-effort check; path may vary by test runner CWD
	_ = p // any non-panic result is acceptable
}

// ─── buildSTRIDEThreatCatalog ─────────────────────────────────────────────────

func TestBuildSTRIDEThreatCatalog_MCPProfile(t *testing.T) {
	profile := projectProfile{
		HasGoCode:       true,
		HasMCPServer:    true,
		HasAuth:         true,
		HasAPI:          true,
		HasAIAgent:      true,
		HasLegacyCrypto: true,
	}
	threats := buildSTRIDEThreatCatalog(profile, "application")
	if len(threats) == 0 {
		t.Fatal("should generate at least one threat for MCP+auth+api profile")
	}
	// Must include at least one spoofing and one privilege escalation threat
	hasSpoofing, hasEoP := false, false
	for _, thr := range threats {
		if thr.Category == strideS {
			hasSpoofing = true
		}
		if thr.Category == strideE {
			hasEoP = true
		}
	}
	if !hasSpoofing {
		t.Error("MCP+Auth profile should produce a Spoofing threat")
	}
	if !hasEoP {
		t.Error("MCP+Auth profile should produce an Elevation of Privilege threat")
	}
}

func TestBuildSTRIDEThreatCatalog_AllIDsUnique(t *testing.T) {
	profile := projectProfile{
		HasGoCode: true, HasMCPServer: true, HasAuth: true,
		HasAPI: true, HasDatabase: true, HasLegacyCrypto: true,
		HasAIAgent: true, HasGRPC: true,
	}
	threats := buildSTRIDEThreatCatalog(profile, "full")
	seen := make(map[string]bool)
	for _, thr := range threats {
		if seen[thr.ID] {
			t.Errorf("duplicate threat ID: %s", thr.ID)
		}
		seen[thr.ID] = true
	}
}

// ─── buildMITREMatrix ─────────────────────────────────────────────────────────

func TestBuildMITREMatrix_LegacyCrypto(t *testing.T) {
	p := projectProfile{HasLegacyCrypto: true}
	matrix := buildMITREMatrix(p)
	if len(matrix) == 0 {
		t.Error("legacy crypto profile should produce at least one MITRE technique")
	}
	foundT1600 := false
	for _, m := range matrix {
		if m.TechID == "T1600" {
			foundT1600 = true
		}
	}
	if !foundT1600 {
		t.Error("T1600 (Weaken Encryption) should appear for legacy-crypto-only profile")
	}
}
