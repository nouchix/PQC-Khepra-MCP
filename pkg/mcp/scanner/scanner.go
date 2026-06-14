package scanner

// scanner.go — MCP Security Scanner entry point.
//
// Implements T01–T16 threat detection against a live Router/Registry.
// Self-contained: does not require Supabase, HTTP, or external services.
//
// Usage:
//
//	sc := scanner.New(router, registry, acpPlane)
//	sc.CaptureBaseline()          // call once after all tools registered
//	findings, err := sc.Scan(ctx) // run on-demand or via Scheduler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
)

// RouterInspector is a read-only view of the MCP Router exposed to the scanner.
// Implemented by *mcp.Router via ScannerView().
type RouterInspector interface {
	// ListToolSpecs returns all registered tool specifications.
	ListToolSpecs() []ToolSpecView
	// HasPQCSigning reports whether a Dilithium signing key is configured.
	HasPQCSigning() bool
	// HasAuditLogger reports whether a DAG audit logger is wired.
	HasAuditLogger() bool
	// ServerName returns the MCP server name.
	ServerName() string
	// SigningKeyLen returns the byte length of the configured signing key (0 = none).
	SigningKeyLen() int
}

// ToolSpecView is a read-only projection of a tool spec for scanning.
type ToolSpecView struct {
	Name        string
	Description string
	Scope       string
	SchemaHash  string
}

// ACPInspector provides read access to the Agent Control Plane for T11 checks.
// Implemented by *acp.AgentControlPlane.
type ACPInspector interface {
	// ListCredentials returns all active credentials with their expiry timestamps.
	ListCredentials() []CredentialView
}

// CredentialView is the scanner's view of an ACP credential.
type CredentialView struct {
	ID        string
	Subject   string
	ExpiresAt time.Time
}

// SnapshotManifest captures a point-in-time hash of all registered tools for drift detection.
type SnapshotManifest struct {
	ServerName   string            `json:"server_name"`
	CapturedAt   time.Time         `json:"captured_at"`
	ToolHashes   map[string]string `json:"tool_hashes"`   // toolName → SHA-256(name+desc+schema)
	ManifestHash string            `json:"manifest_hash"` // SHA-256 over sorted entries
}

// Scanner orchestrates T01–T16 threat checks against a running MCP server.
type Scanner struct {
	router   RouterInspector
	acp      ACPInspector // nil = ACP checks skipped
	baseline *SnapshotManifest
}

// New creates a Scanner. acpPlane may be nil — T11 checks are skipped when absent.
func New(router RouterInspector, acpPlane ACPInspector) *Scanner {
	return &Scanner{router: router, acp: acpPlane}
}

// CaptureBaseline computes and stores the current tool manifest snapshot.
// Must be called once after all tools are registered. Subsequent Scan() calls
// use this snapshot for T03 (manifest rug pull) and T10 (schema drift) detection.
func (s *Scanner) CaptureBaseline() {
	s.baseline = s.computeSnapshot()
}

// SetBaseline injects a pre-computed baseline (e.g. loaded from persistent store).
func (s *Scanner) SetBaseline(m *SnapshotManifest) { s.baseline = m }

// Scan runs all active threat checks and returns consolidated findings.
// Respects context cancellation between checks.
func (s *Scanner) Scan(ctx context.Context) ([]MCPFinding, error) {
	var findings []MCPFinding
	type checkFn func(ctx context.Context) ([]MCPFinding, error)

	checks := []checkFn{
		s.checkToolPoisoning,
		s.checkManifestRugPull,
		s.checkUnsignedResponse,
		s.checkDAGGap,
		s.checkSchemaDrift,
		s.checkStaleCredential,
		s.checkPQCDowngrade,
	}

	for i, check := range checks {
		select {
		case <-ctx.Done():
			return findings, fmt.Errorf("scanner: scan cancelled after %d/%d checks: %w", i, len(checks), ctx.Err())
		default:
		}
		results, err := check(ctx)
		if err != nil {
			// Non-fatal: record as internal info finding and continue
			findings = append(findings, MCPFinding{
				ID:          fmt.Sprintf("INT-%03d", i),
				ThreatClass: "INTERNAL",
				Severity:    SeverityInfo,
				Title:       "Check execution error",
				Detail:      err.Error(),
				DetectedAt:  time.Now(),
			})
			continue
		}
		findings = append(findings, results...)
	}
	return findings, nil
}

// computeSnapshot builds a deterministic manifest hash of all registered tools.
func (s *Scanner) computeSnapshot() *SnapshotManifest {
	specs := s.router.ListToolSpecs()
	hashes := make(map[string]string, len(specs))
	for _, t := range specs {
		raw := t.Name + "|" + t.Description + "|" + t.Scope + "|" + t.SchemaHash
		sum := sha256.Sum256([]byte(raw))
		hashes[t.Name] = hex.EncodeToString(sum[:])
	}

	// Deterministic manifest hash: sort by name
	keys := make([]string, 0, len(hashes))
	for k := range hashes {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var combined strings.Builder
	for _, k := range keys {
		combined.WriteString(k + "=" + hashes[k] + "\n")
	}
	mhSum := sha256.Sum256([]byte(combined.String()))

	return &SnapshotManifest{
		ServerName:   s.router.ServerName(),
		CapturedAt:   time.Now(),
		ToolHashes:   hashes,
		ManifestHash: hex.EncodeToString(mhSum[:]),
	}
}

// diffSnapshots returns added, removed, and schema-changed tool names.
func diffSnapshots(baseline, current *SnapshotManifest) (added, removed, changed []string) {
	for name, hash := range current.ToolHashes {
		if bHash, ok := baseline.ToolHashes[name]; !ok {
			added = append(added, name)
		} else if bHash != hash {
			changed = append(changed, name)
		}
	}
	for name := range baseline.ToolHashes {
		if _, ok := current.ToolHashes[name]; !ok {
			removed = append(removed, name)
		}
	}
	return
}
