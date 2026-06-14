package mcp

// scanner_adapter.go — RouterInspector adapter for pkg/mcp/scanner.
//
// Exposes read-only security metadata from the Router and Executor
// to the scanner package without creating import cycles.
// The scanner package imports this via the RouterInspector interface.

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
