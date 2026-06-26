package mcp

// scanner_adapter.go — RouterInspector adapter for pkg/mcp/scanner + secret scan bridge.
//
// Exposes read-only security metadata from the Router and Executor
// to the scanner package without creating import cycles.
// The scanner package imports this via the RouterInspector interface.
//
// This file ALSO provides:
//   - runOutputSecretScan()   — bridge so router.go calls scanner without a cycle
//   - RunScannerAssessment()  — full T01–T16 scan + ComputeScore for tool handlers

import (
	"context"

	"github.com/nouchix/PQC-Khepra-MCP/pkg/mcp/scanner"
)


// ScannerView returns a RouterInspector that the scanner package can use
// to inspect the running server without accessing internal fields directly.
func (r *Router) ScannerView() RouterScanView {
	return RouterScanView{router: r}
}

// RouterScanView is a read-only projection of the Router for security scanning.
// It implements scanner.RouterInspector via method forwarding.
type RouterScanView struct {
	router *Router
}

// ListToolSpecs returns all registered tool specifications as name/description/scope/hash tuples.
func (v RouterScanView) ListToolSpecs() []ToolScanSpec {
	if v.router == nil || v.router.registry == nil {
		return nil
	}
	raw := v.router.registry.ListTools()
	out := make([]ToolScanSpec, len(raw))
	for i, t := range raw {
		out[i] = ToolScanSpec{
			Name:        t.Name,
			Description: t.Description,
			Scope:       t.Scope,
			SchemaHash:  t.SchemaHash,
		}
	}
	return out
}

// HasPQCSigning reports whether the Router has a Dilithium signing key configured.
// Returns true if the Polymorphic Engine has a non-empty private key.
func (v RouterScanView) HasPQCSigning() bool {
	if v.router == nil || v.router.attest == nil {
		return false
	}
	// Heuristic: use SigningKeyLen > 0 as the proxy
	return v.SigningKeyLen() > 0
}

// HasAuditLogger reports whether a DAG attestation store is wired.
func (v RouterScanView) HasAuditLogger() bool {
	return v.router != nil && v.router.attest != nil
}

// ServerName returns the MCP server name.
func (v RouterScanView) ServerName() string {
	return HardenedServerName
}

// SigningKeyLen returns the byte length of the configured Dilithium private key.
// Returns 0 if no key is configured.
// The poly field holds the AdinkraPolymorphicEngine which carries PrivateKey.
func (v RouterScanView) SigningKeyLen() int {
	if v.router == nil || v.router.poly == nil {
		return 0
	}
	// AdinkraPolymorphicEngine implements PolymorphicEngine.
	// Use a type assertion to access PrivateKey if available.
	type keyHolder interface {
		PrivKeyLen() int
	}
	if kh, ok := v.router.poly.(keyHolder); ok {
		return kh.PrivKeyLen()
	}
	// Fallback: cannot determine key length — assume configured if poly != nil
	// The T16 check interprets 0 as "no key" and skips.
	return 0
}

// ToolScanSpec is the scanner package's view of a registered tool.
// Mirrors scanner.ToolSpecView — defined here to avoid the import cycle.
type ToolScanSpec struct {
	Name        string
	Description string
	Scope       string
	SchemaHash  string
}


// ── Secret Scan Bridge ────────────────────────────────────────────────────────────────
//
// runOutputSecretScan is a package-local bridge that calls scanner.ScanOutputSecrets
// and converts findings to secretFindingBrief so router.go can range over them
// without importing pkg/mcp/scanner directly (which would create an import cycle).

// secretFindingBrief is a compact projection of scanner.MCPFinding for use in router.go.
type secretFindingBrief struct {
	title    string
	owaspTag string
	asiTag   string
	severity string
}

// runOutputSecretScan calls the scanner package's ScanOutputSecrets and returns
// a slice of secretFindingBrief values. This function lives in scanner_adapter.go
// (package mcp) so it can import pkg/mcp/scanner without creating a cycle.
func runOutputSecretScan(output []byte, toolName string) []secretFindingBrief {
	raw := scanner.ScanOutputSecrets(output, toolName)
	out := make([]secretFindingBrief, 0, len(raw))
	for _, f := range raw {
		out = append(out, secretFindingBrief{
			title:    f.Title,
			owaspTag: f.OWASPTag,
			asiTag:   f.ASITag,
			severity: string(f.Severity),
		})
	}
	return out
}

// RunScannerAssessment runs the full T01–T16 scanner suite against the Router
// and returns findings with OWASP/ASI tags and a weighted security score.
// Called by the owasp_agent_assess tool handler via Router.RunScannerAssessment().
//
// Uses scannerInspectorBridge to adapt RouterScanView to scanner.RouterInspector,
// resolving the ListToolSpecs() return-type mismatch between the two packages.
func (r *Router) RunScannerAssessment() ([]scanner.MCPFinding, scanner.MCPSecurityScore, error) {
	bridge := &scannerInspectorBridge{view: r.ScannerView()}
	sc := scanner.New(bridge, nil)
	sc.CaptureBaseline()
	findings, err := sc.Scan(context.Background())
	if err != nil {
		return nil, scanner.MCPSecurityScore{}, err
	}
	specs := r.ScannerView().ListToolSpecs()
	score := scanner.ComputeScore(
		findings,
		len(specs),
		r.ScannerView().HasPQCSigning(),
		r.ScannerView().HasAuditLogger(),
		true, // ValidateToolArgs is always wired in our router
	)
	return findings, score, nil
}

// scannerInspectorBridge adapts RouterScanView (package mcp) to the
// scanner.RouterInspector interface (package scanner).
//
// The only mismatch is ListToolSpecs(): RouterScanView returns []ToolScanSpec
// (mcp-local type) while scanner.RouterInspector expects []scanner.ToolSpecView.
// This bridge converts between the two without changing either type.
type scannerInspectorBridge struct {
	view RouterScanView
}

func (b *scannerInspectorBridge) ListToolSpecs() []scanner.ToolSpecView {
	raw := b.view.ListToolSpecs()
	out := make([]scanner.ToolSpecView, len(raw))
	for i, s := range raw {
		out[i] = scanner.ToolSpecView{
			Name:        s.Name,
			Description: s.Description,
			Scope:       s.Scope,
			SchemaHash:  s.SchemaHash,
		}
	}
	return out
}

func (b *scannerInspectorBridge) HasPQCSigning() bool  { return b.view.HasPQCSigning() }
func (b *scannerInspectorBridge) HasAuditLogger() bool { return b.view.HasAuditLogger() }
func (b *scannerInspectorBridge) ServerName() string   { return b.view.ServerName() }
func (b *scannerInspectorBridge) SigningKeyLen() int    { return b.view.SigningKeyLen() }
