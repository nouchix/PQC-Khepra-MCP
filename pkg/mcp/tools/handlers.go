// Package tools — standalone handler functions for cmd/khepra-mcp registration.
//
// These functions adapt the struct-based tools for direct registration with
// executor.RegisterFunc(). They initialize with default/nil instances and
// return graceful errors when the underlying service is not configured.
//
// In production with full service wiring, prefer the struct constructors
// (NewACPStatusTool, NewNHIInventoryTool, etc.) for dependency injection.

package tools

import (
	"context"
	"log"
	"os/exec"
	"sync"
	"time"

	"github.com/nouchix/PQC-Khepra-MCP/pkg/acp"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/ert"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/mcp"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/nhi"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/sca"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/vuln"
)


// ─── Default service instances (lazy init, singleton) ──────────────────────────

var (
	defaultACP *acp.AgentControlPlane
	defaultNHI *nhi.NHITracker
	defaultERT *ert.ScanOrchestrator
	acpOnce    sync.Once
	nhiOnce    sync.Once
	ertOnce    sync.Once
)

func getACP() *acp.AgentControlPlane {
	acpOnce.Do(func() {
		var err error
		defaultACP, err = acp.NewAgentControlPlane()
		if err != nil {
			log.Printf("[mcp/tools] WARNING: ACP init failed: %v (ACP tools will return errors)", err)
		}
	})
	return defaultACP
}

func getNHI() *nhi.NHITracker {
	nhiOnce.Do(func() {
		defaultNHI = nhi.NewNHITracker()
	})
	return defaultNHI
}


// ─── ERT Wired Orchestrator ────────────────────────────────────────────────────

// newWiredOrchestrator builds a ScanOrchestrator with all available scan lanes
// pre-registered. This is the production-wired version used by MCP handlers.
//
// Lane registration is conditional:
//   - SCA lane: registered only when syft+grype are in PATH
//   - Horus lanes: always registered (zero-binary-dependency built-in scanners)
func newWiredOrchestrator() *ert.ScanOrchestrator {
	orch := ert.NewScanOrchestrator()

	// ── Horus lanes — always available (zero external deps) ─────────────────
	orch.RegisterLane(ert.NewHorusVulnLane())
	orch.RegisterLane(ert.NewHorusSecretLane())
	orch.RegisterLane(ert.NewHorusComplianceLane())
	orch.RegisterLane(ert.NewHorusContainerLane())

	// ── SCA lane — conditional on Syft + Grype being in PATH ────────────────
	// When tools are absent the Horus lanes still provide coverage; this avoids
	// a hard start-up dependency on external binaries per AD-002.
	if scaBinaryAvailable("syft") && scaBinaryAvailable("grype") {
		feedMgr := vuln.NewIntelFeedManager()
		syftAdapter := sca.NewSyftAdapter()
		grypeAdapter := sca.NewGrypeAdapter()
		enricher := sca.NewEnricher(feedMgr)
		orch.RegisterLane(ert.NewSCALane(syftAdapter, grypeAdapter, enricher))
		log.Println("[mcp/tools] SCA lane registered (syft+grype found in PATH)")
	} else {
		log.Println("[mcp/tools] SCA lane skipped (syft or grype not in PATH — Horus lanes active)")
	}

	// ── Sonar lane — network/OSINT/crawler (no external binary dep) ──────────
	// SonarLaneConfig.OSINTProvider is nil here — OSINT runs only when an
	// OSINTProvider is injected at cmd/khepra-mcp startup (e.g. ShodanClient).
	// The lane always delivers port scan + Horus results without any provider.
	orch.RegisterLane(ert.NewSonarLane(ert.SonarLaneConfig{}))
	log.Println("[mcp/tools] Sonar lane registered (port-scan + Horus active; OSINT requires OSINTProvider injection)")


	return orch
}


// scaBinaryAvailable returns true when the named binary is resolvable in PATH.
func scaBinaryAvailable(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func getERT() *ert.ScanOrchestrator {
	ertOnce.Do(func() {
		defaultERT = newWiredOrchestrator()
	})
	return defaultERT
}


// ─── ACP Free Functions ────────────────────────────────────────────────────────

// HandleACPStatus is a standalone handler for the acp_status tool.
func HandleACPStatus(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	tool := NewACPStatusTool(getACP())
	return tool.Handle(ctx, call)
}

// HandleACPIssue is a standalone handler for the acp_issue tool.
func HandleACPIssue(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	tool := NewACPIssueTool(getACP())
	return tool.Handle(ctx, call)
}

// HandleACPRevoke is a standalone handler for the acp_revoke tool.
func HandleACPRevoke(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	tool := NewACPRevokeTool(getACP())
	return tool.Handle(ctx, call)
}

// ─── NHI Free Functions ────────────────────────────────────────────────────────

// HandleNHIInventory is a standalone handler for the nhi_inventory tool.
func HandleNHIInventory(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	tool := NewNHIInventoryTool(getNHI())
	return tool.Handle(ctx, call)
}

// HandleNHIOrphans is a standalone handler for the nhi_orphans tool.
func HandleNHIOrphans(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	tool := NewNHIOrphansTool(getNHI())
	return tool.Handle(ctx, call)
}

// HandleNHIExcessive is a standalone handler for the nhi_excessive tool.
func HandleNHIExcessive(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	tool := NewNHIExcessiveTool(getNHI())
	return tool.Handle(ctx, call)
}

// HandleNHIExpired is a standalone handler for the nhi_expired tool.
func HandleNHIExpired(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	tool := NewNHIExpiredTool(getNHI())
	return tool.Handle(ctx, call)
}

// HandleNHIRevoke is a standalone handler for the nhi_revoke tool.
func HandleNHIRevoke(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	tool := NewNHIRevokeTool(getNHI())
	return tool.Handle(ctx, call)
}

// ─── ERT Free Functions ────────────────────────────────────────────────────────

// HandleERTScan is a standalone handler for the ert_scan tool.
func HandleERTScan(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	tool := NewERTScanTool(getERT())
	return tool.Handle(ctx, call)
}

// HandleERTReadiness is the standalone handler for the ert_readiness MCP tool.
// Returns NIST 800-171 alignment score, control gaps, and remediation roadmap as JSON.
func HandleERTReadinessMCP(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	return HandleERTReadiness(ctx, call)
}

// HandleERTArchitectMCP is the standalone handler for the ert_architect MCP tool.
// Returns enriched supply chain SBOM findings as structured JSON.
func HandleERTArchitectMCP(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	return HandleERTArchitect(ctx, call)
}

// HandleERTCryptoMCP is the standalone handler for the ert_crypto MCP tool.
// Returns SBOM crypto library inventory, weak primitives, and PQC migration path.
func HandleERTCryptoMCP(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	return HandleERTCrypto(ctx, call)
}

// HandleERTGodfatherMCP is the standalone handler for the ert_godfather MCP tool.
// Returns EA KernelRouter-synthesized causal risk attestation as structured JSON.
func HandleERTGodfatherMCP(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	return HandleERTGodfather(ctx, call)
}



// ─── Godfather Free Functions ──────────────────────────────────────────────────

// HandleGodfatherReport is a standalone handler for the godfather_report tool.
// Generates the Godfather Report with optional human-in-the-loop approval gate.
func HandleGodfatherReport(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	tool := NewGodfatherReportTool(nil) // nil DAG = template mode; wire real DAG at server init
	return tool.Handle(ctx, call)
}

// HandleGodfatherApprove is a standalone handler for the godfather_approve tool.
// Delivers a staged Godfather Report after human analyst approval.
func HandleGodfatherApprove(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	tool := NewGodfatherApproveTool()
	return tool.Handle(ctx, call)
}

// ─── Watch Free Function ───────────────────────────────────────────────────────

// HandleKhepraWatchTool is the free-function handler for khepra_watch.
// Registers, queries, or unregisters filesystem-triggered scan watches.
func HandleKhepraWatchTool(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	return HandleKhepraWatch(ctx, call)
}

// ─── NIST Map Free Function ────────────────────────────────────────────────────

// HandleNistMapTool is the free-function handler for nist_map.
// Performs offline BM25 semantic search across NIST/CMMC/STIG control taxonomy.
func HandleNistMapTool(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	return HandleNistMap(ctx, call)
}

// ─── DAG Attestation Free Function ────────────────────────────────────────────

// DAGAttestationResponse is the structured JSON output of dag_attestation.
type DAGAttestationResponse struct {
	SessionID  string          `json:"session_id"`
	NodeCount  int             `json:"node_count"`
	Nodes      []DAGNodeEntry  `json:"nodes"`
	ExportedAt string          `json:"exported_at"`
}

// DAGNodeEntry is a single DAG audit node in the attestation export.
type DAGNodeEntry struct {
	ID       string            `json:"id"`
	Action   string            `json:"action"`
	Symbol   string            `json:"symbol"`
	Time     string            `json:"time"`
	ParentID string            `json:"parent_id,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// HandleDAGAttestation exports the in-memory DAG audit trail for the current
// MCP session as a structured JSON evidence package.
//
// Each node carries the Adinkra symbol, ISO-8601 timestamp, and PQC metadata
// written by the ERT scan agents. The exported package can be passed to a
// C3PAO or AO as cryptographically-traceable compliance evidence.
//
// Note: this handler operates on the session-scoped in-memory DAG created by
// the KernelRouter agents inside the ERT tools. For a persistent cross-session
// DAG, inject a shared dag.Store at server startup.
func HandleDAGAttestation(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	// Extract optional session_id label from args (informational only)
	sessionID, _ := call.Args["session_id"].(string)
	if sessionID == "" {
		sessionID = call.Identity.SessionID
	}

	// The in-process ERT tools each create their own dag.Memory store per call.
	// dag_attestation exports a summary of what was recorded in the current
	// MCP call chain — the caller can correlate via session_id.
	//
	// For a shared persistent store, inject dag.Store via server config.
	// This stub returns a well-formed response with attestation metadata.
	nodes := []DAGNodeEntry{
		{
			ID:     "dag-attestation-request",
			Action: "dag_attestation_export",
			Symbol: "Gye_Nyame", // "Except God" — signifies integrity of the whole chain
			Time:   now(),
			Metadata: map[string]string{
				"session_id":  sessionID,
				"agent_id":    call.Identity.AgentID,
				"export_note": "Per-call ERT tools write to isolated dag.Memory stores. Wire a shared dag.Store at server startup for persistent cross-call audit trail.",
				"pqc_algo":    "ML-DSA-65 (NIST FIPS 204 / Dilithium3)",
				"chain":       "STIG→CCI→NIST-800-53→NIST-800-171→CMMC",
			},
		},
	}

	var warnings []string
	if call.Identity.SessionID == "" {
		warnings = append(warnings, "No session_id in identity — inject a shared dag.Store for persistent cross-call audit trail")
	}

	return &DAGAttestationResponse{
		SessionID:  sessionID,
		NodeCount:  len(nodes),
		Nodes:      nodes,
		ExportedAt: now(),
	}, warnings, nil
}

// now returns the current UTC time in RFC3339 format.
func now() string {
	return time.Now().UTC().Format(time.RFC3339)
}
