// Package ert provides the Executive Roundtable scanning orchestration.
//
// The ScanOrchestrator coordinates multiple scanner lanes (SCA, SAST, Compliance)
// through a unified finding model, producing normalized results for EA engine
// consumption and DAG attestation.
//
// Architecture follows OWASP MCP guidance: each scan lane is isolated,
// least-privilege scoped, and independently testable. Network and integrity
// scanning are deliberately excluded — they belong to separate MCP tools
// (khepra_network_scan, khepra_integrity_watch) per their distinct permission models.
package ert

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"
)

// ──────────────────────────────────────────────────────────────────────────────
// UnifiedFinding — the internal finding model for the orchestrator.
//
// This is intentionally broader than sca.EnrichedFinding. It preserves
// source-specific semantics (secrets, compliance gaps, config vulns) that
// would be destroyed by premature flattening. Conversion to EnrichedFinding
// happens only at the EA boundary, via normalize.go.
// ──────────────────────────────────────────────────────────────────────────────

// FindingCategory classifies the type of finding.
type FindingCategory string

const (
	CategoryVulnerability FindingCategory = "vulnerability"
	CategorySecret        FindingCategory = "secret"
	CategoryCompliance    FindingCategory = "compliance"
	CategoryMisconfigure  FindingCategory = "misconfiguration"
	CategorySCA           FindingCategory = "sca"
)

// UnifiedFinding is the internal finding model for the orchestrator.
// It preserves provenance and source-specific evidence while enabling
// cross-lane aggregation. Conversion to sca.EnrichedFinding happens
// only at the EA boundary.
type UnifiedFinding struct {
	// Identity
	ID       string          `json:"id"`       // Unique finding ID (source:type:hash)
	Source   string          `json:"source"`   // Scanner that produced this finding
	Category FindingCategory `json:"category"` // vulnerability, secret, compliance, misconfiguration, sca

	// Classification
	Severity    string `json:"severity"`    // CRITICAL, HIGH, MEDIUM, LOW, INFO
	Title       string `json:"title"`       // Human-readable title
	Description string `json:"description"` // Detailed description

	// Asset
	Asset    string `json:"asset"`     // What was scanned (file path, package name, etc.)
	Location string `json:"location"`  // Where in the asset (line number, config key, etc.)

	// Vulnerability-specific (populated for CVE-bearing findings)
	CVEID    string  `json:"cve_id,omitempty"`
	CVSSv3   float64 `json:"cvss_v3,omitempty"`
	FixedIn  string  `json:"fixed_in,omitempty"`
	EPSSScore float64 `json:"epss_score,omitempty"`
	InCISAKEV bool   `json:"in_cisa_kev,omitempty"`

	// Compliance-specific
	Framework   string `json:"framework,omitempty"`   // CIS, STIG, NIST
	ControlID   string `json:"control_id,omitempty"`  // CIS-1.1.1, STIG-V-12345
	Remediation string `json:"remediation,omitempty"` // Remediation guidance

	// Secret-specific
	SecretType string  `json:"secret_type,omitempty"` // API Key, Private Key, JWT, etc.
	Entropy    float64 `json:"entropy,omitempty"`     // Shannon entropy of detected secret
	Redacted   string  `json:"redacted,omitempty"`    // Partially redacted secret value

	// Evidence — source-specific payload preserved for triage
	Evidence map[string]interface{} `json:"evidence,omitempty"`

	// Metadata
	Timestamp time.Time `json:"timestamp"`

	// Raw — the original scanner output, preserved for provenance
	Raw interface{} `json:"-"`
}

// ──────────────────────────────────────────────────────────────────────────────
// ScanLane — what the orchestrator can run
// ──────────────────────────────────────────────────────────────────────────────

// ScanLane represents a category of scanning with distinct scope and purpose.
type ScanLane string

const (
	LaneSCA        ScanLane = "sca"        // Syft → Grype → EPSS Enricher
	LaneHorusVuln  ScanLane = "horus_vuln" // Horus vulnerability pattern matching
	LaneHorusSecret ScanLane = "horus_secret" // Horus entropy-based secret detection
	LaneHorusCompliance ScanLane = "horus_compliance" // Horus CIS/STIG/NIST checks
	LaneHorusContainer ScanLane = "horus_container"  // Horus Dockerfile analysis
	LaneDNSPKI     ScanLane = "dns_pki"    // Live DNS enumeration + TLS/PKI cert discovery
)

// AllLanes returns all scan lanes the orchestrator supports.
func AllLanes() []ScanLane {
	return []ScanLane{
		LaneSCA,
		LaneHorusVuln,
		LaneHorusSecret,
		LaneHorusCompliance,
		LaneHorusContainer,
		LaneSonar,  // Network/OSINT/Crawler (requires network target)
		LaneDNSPKI, // DNS enumeration + live TLS/PKI cert discovery (requires network target)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// ScanRequest / ScanResult
// ──────────────────────────────────────────────────────────────────────────────

// ScanRequest configures what the orchestrator runs.
// This is scoped to path/image mode only — network scanning belongs
// to a separate MCP tool (khepra_network_scan).
type ScanRequest struct {
	TargetPath          string        `json:"target_path"`          // Filesystem path to scan
	ImageRef            string        `json:"image_ref,omitempty"`  // Container image reference
	Lanes               []ScanLane    `json:"lanes,omitempty"`      // nil = all lanes
	ComplianceFramework string        `json:"compliance_framework"` // cis, stig, nist (default: cis)
	Timeout             time.Duration `json:"timeout,omitempty"`    // Default: 10m
}

// ScanResult contains the unified findings from all scan lanes.
type ScanResult struct {
	RequestID string           `json:"request_id"`
	Target    string           `json:"target"`
	Lanes     []ScanLane       `json:"lanes_executed"`
	Findings  []UnifiedFinding `json:"findings"`
	Errors    []string         `json:"errors,omitempty"`
	StartTime time.Time        `json:"start_time"`
	EndTime   time.Time        `json:"end_time"`
	Duration  time.Duration    `json:"duration"`

	// Summary statistics
	Stats ScanStats `json:"stats"`
}

// ScanStats provides aggregate metrics from the scan.
type ScanStats struct {
	TotalFindings       int            `json:"total_findings"`
	BySeverity          map[string]int `json:"by_severity"`
	ByCategory          map[string]int `json:"by_category"`
	BySource            map[string]int `json:"by_source"`
	CriticalCount       int            `json:"critical_count"`
	HighCount           int            `json:"high_count"`
	SecretsDetected     int            `json:"secrets_detected"`
	ComplianceChecksPassed int         `json:"compliance_checks_passed,omitempty"`
	ComplianceChecksFailed int         `json:"compliance_checks_failed,omitempty"`
}

// ──────────────────────────────────────────────────────────────────────────────
// LaneRunner — interface for pluggable scan lanes
// ──────────────────────────────────────────────────────────────────────────────

// LaneRunner is the interface each scan lane must implement.
// This keeps lanes isolated, testable, and individually authorizable.
type LaneRunner interface {
	// Name returns the lane identifier.
	Name() ScanLane

	// Run executes the scan lane against the given target.
	// It returns UnifiedFindings and any errors encountered.
	// The lane must respect context cancellation.
	Run(ctx context.Context, req ScanRequest) ([]UnifiedFinding, error)
}

// ──────────────────────────────────────────────────────────────────────────────
// ScanOrchestrator — coordinates multiple scan lanes
// ──────────────────────────────────────────────────────────────────────────────

// ScanOrchestrator coordinates multiple scan lanes, merges findings,
// and produces a unified result. It does NOT own the EA or DAG integration —
// that lives in the caller (ert_bridge.go or MCP tool wrapper).
type ScanOrchestrator struct {
	lanes map[ScanLane]LaneRunner
	mu    sync.RWMutex
}

// NewScanOrchestrator creates a new orchestrator with no lanes registered.
// Use RegisterLane() to add scan capabilities.
func NewScanOrchestrator() *ScanOrchestrator {
	return &ScanOrchestrator{
		lanes: make(map[ScanLane]LaneRunner),
	}
}

// RegisterLane adds a scan lane to the orchestrator.
func (o *ScanOrchestrator) RegisterLane(runner LaneRunner) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.lanes[runner.Name()] = runner
}

// RegisteredLanes returns the list of currently registered lanes.
func (o *ScanOrchestrator) RegisteredLanes() []ScanLane {
	o.mu.RLock()
	defer o.mu.RUnlock()

	lanes := make([]ScanLane, 0, len(o.lanes))
	for name := range o.lanes {
		lanes = append(lanes, name)
	}
	return lanes
}

// Execute runs all requested scan lanes concurrently and merges results.
func (o *ScanOrchestrator) Execute(ctx context.Context, req ScanRequest) (*ScanResult, error) {
	if req.TargetPath == "" && req.ImageRef == "" {
		return nil, fmt.Errorf("scan request requires either target_path or image_ref")
	}

	// Apply defaults
	if req.Timeout == 0 {
		req.Timeout = 10 * time.Minute
	}
	if req.ComplianceFramework == "" {
		req.ComplianceFramework = "cis"
	}

	// Determine which lanes to run
	requestedLanes := req.Lanes
	if len(requestedLanes) == 0 {
		requestedLanes = AllLanes()
	}

	// Build the result
	result := &ScanResult{
		RequestID: fmt.Sprintf("ert-%d", time.Now().UnixNano()),
		Target:    req.TargetPath,
		StartTime: time.Now().UTC(),
		Stats: ScanStats{
			BySeverity: make(map[string]int),
			ByCategory: make(map[string]int),
			BySource:   make(map[string]int),
		},
	}
	if result.Target == "" {
		result.Target = req.ImageRef
	}

	// Context with timeout
	ctx, cancel := context.WithTimeout(ctx, req.Timeout)
	defer cancel()

	// Run lanes concurrently
	type laneResult struct {
		lane     ScanLane
		findings []UnifiedFinding
		err      error
	}

	o.mu.RLock()
	var wg sync.WaitGroup
	results := make(chan laneResult, len(requestedLanes))

	for _, lane := range requestedLanes {
		runner, exists := o.lanes[lane]
		if !exists {
			log.Printf("[ERT-ORCHESTRATOR] WARN: Lane %q not registered, skipping", lane)
			continue
		}

		result.Lanes = append(result.Lanes, lane)
		wg.Add(1)

		go func(r LaneRunner, l ScanLane) {
			defer wg.Done()

			log.Printf("[ERT-ORCHESTRATOR] Starting lane: %s", l)
			findings, err := r.Run(ctx, req)
			results <- laneResult{lane: l, findings: findings, err: err}
		}(runner, lane)
	}
	o.mu.RUnlock()

	// Collect results
	go func() {
		wg.Wait()
		close(results)
	}()

	var mu sync.Mutex
	for lr := range results {
		mu.Lock()
		if lr.err != nil {
			errMsg := fmt.Sprintf("[%s] %v", lr.lane, lr.err)
			result.Errors = append(result.Errors, errMsg)
			log.Printf("[ERT-ORCHESTRATOR] Lane %s error: %v", lr.lane, lr.err)
		}
		if len(lr.findings) > 0 {
			result.Findings = append(result.Findings, lr.findings...)
			log.Printf("[ERT-ORCHESTRATOR] Lane %s produced %d findings", lr.lane, len(lr.findings))
		}
		mu.Unlock()
	}

	// Compute stats
	result.EndTime = time.Now().UTC()
	result.Duration = result.EndTime.Sub(result.StartTime)
	result.Stats = computeStats(result.Findings)

	log.Printf("[ERT-ORCHESTRATOR] Scan complete: %d findings in %v (%d errors)",
		result.Stats.TotalFindings, result.Duration, len(result.Errors))

	return result, nil
}

// computeStats aggregates finding metrics.
func computeStats(findings []UnifiedFinding) ScanStats {
	stats := ScanStats{
		TotalFindings: len(findings),
		BySeverity:    make(map[string]int),
		ByCategory:    make(map[string]int),
		BySource:      make(map[string]int),
	}

	for _, f := range findings {
		stats.BySeverity[f.Severity]++
		stats.ByCategory[string(f.Category)]++
		stats.BySource[f.Source]++

		switch f.Severity {
		case "CRITICAL":
			stats.CriticalCount++
		case "HIGH":
			stats.HighCount++
		}

		if f.Category == CategorySecret {
			stats.SecretsDetected++
		}
	}

	return stats
}
