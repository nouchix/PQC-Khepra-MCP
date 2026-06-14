// Package sca — Enricher pipeline (Task 5)
//
// The Enricher takes raw findings from Grype and wires them with live
// threat intelligence from the IntelFeedManager (CISA KEV, EPSS, InTheWild).
//
// Design decisions:
//   AD-007: Concurrent enrichment with bounded parallelism (default 8 workers)
//   AD-008: Individual feed failures are non-blocking — partial enrichment is useful
//   AD-009: Enrich() is idempotent and safe to re-run
//   AD-010: Risk/Confidence calculations centralized in EnrichedFinding helpers

package sca

import (
	"context"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/vuln"
)

// ──────────────────────────────────────────────────────────────────────────────
// Enricher
// ──────────────────────────────────────────────────────────────────────────────

// Enricher wires raw SCA findings (from Grype) with live threat intelligence.
// It queries the IntelFeedManager for CISA KEV, EPSS, and exploit data,
// then applies confidence scoring and risk classification.
type Enricher struct {
	feedManager *vuln.IntelFeedManager
	timeout     time.Duration
	workers     int // concurrency limit for enrichment goroutines
}

// NewEnricher creates a new Enricher with production defaults.
func NewEnricher(feedManager *vuln.IntelFeedManager) *Enricher {
	return &Enricher{
		feedManager: feedManager,
		timeout:     120 * time.Second,
		workers:     8,
	}
}

// EnricherOption allows configuring Enricher behavior.
type EnricherOption func(*Enricher)

// WithEnricherTimeout sets the maximum duration for the enrichment pass.
func WithEnricherTimeout(d time.Duration) EnricherOption {
	return func(e *Enricher) { e.timeout = d }
}

// WithEnricherWorkers sets the concurrency limit.
func WithEnricherWorkers(n int) EnricherOption {
	return func(e *Enricher) {
		if n > 0 {
			e.workers = n
		}
	}
}

// NewEnricherWithOptions creates a configured Enricher.
func NewEnricherWithOptions(feedManager *vuln.IntelFeedManager, opts ...EnricherOption) *Enricher {
	e := NewEnricher(feedManager)
	for _, opt := range opts {
		opt(e)
	}
	return e
}

// ──────────────────────────────────────────────────────────────────────────────
// Enrich — main pipeline entry point
// ──────────────────────────────────────────────────────────────────────────────

// Enrich takes raw findings from Grype and returns fully enriched findings.
// It is idempotent — safe to call multiple times on the same findings.
//
// The enrichment pipeline:
//  1. Batch-fetch EPSS scores for all CVE IDs
//  2. Concurrently enrich each finding with KEV, EPSS, exploit data
//  3. Apply confidence scoring
//  4. Return enriched copy (input is not mutated)
func (e *Enricher) Enrich(ctx context.Context, findings []EnrichedFinding) ([]EnrichedFinding, error) {
	if len(findings) == 0 {
		return findings, nil
	}

	ctx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()

	// Work on a copy to avoid mutating input
	enriched := make([]EnrichedFinding, len(findings))
	copy(enriched, findings)

	// Phase 1: Batch-prefetch EPSS data for all CVE IDs
	cveIDs := collectCVEIDs(enriched)
	if len(cveIDs) > 0 && e.feedManager != nil {
		if err := e.feedManager.FetchEPSS(ctx, cveIDs); err != nil {
			// Non-fatal: log and continue with whatever data is cached
			log.Printf("[ENRICHER] EPSS prefetch warning: %v", err)
		}
	}

	// Phase 2: Concurrently enrich each finding
	sem := make(chan struct{}, e.workers)
	var wg sync.WaitGroup

	for i := range enriched {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			e.enrichSingle(ctx, &enriched[idx])
		}(i)
	}

	wg.Wait()

	return enriched, nil
}

// ──────────────────────────────────────────────────────────────────────────────
// Per-finding enrichment
// ──────────────────────────────────────────────────────────────────────────────

// enrichSingle enriches one finding from cached threat intelligence.
// Individual lookup failures are non-fatal (AD-008).
func (e *Enricher) enrichSingle(ctx context.Context, f *EnrichedFinding) {
	if f.CVEID == "" {
		return
	}

	// Feed-dependent enrichment (only when IntelFeedManager is available)
	if e.feedManager != nil {
		// 1. Lookup cached threat intel (CISA KEV, InTheWild, NVD data)
		intel := e.feedManager.LookupCVE(f.CVEID)
		if intel != nil {
			e.applyThreatIntel(f, intel)
		}

		// 2. EPSS (from prefetched cache)
		if score, percentile, found := e.feedManager.LookupEPSS(f.CVEID); found {
			f.EPSSScore = score
			f.EPSSPercentile = percentile
		}

		// 3. Update sources to reflect enrichment
		f.Sources = appendUnique(f.Sources, "enriched")
	}

	// 4. Apply confidence scoring (always, even without feeds)
	f.Confidence = calculateConfidence(f)

	// 5. Set default VEX status if not already set
	if f.VEXStatus == "" {
		f.VEXStatus = string(VEXAffected)
	}
}

// applyThreatIntel maps IntelFeedManager's ThreatIntel to our EnrichedFinding fields.
func (e *Enricher) applyThreatIntel(f *EnrichedFinding, intel *vuln.ThreatIntel) {
	// CISA KEV
	if intel.ExploitedInWild {
		f.InCISAKEV = true
		f.InTheWild = true
		if !intel.PublishedDate.IsZero() {
			f.KEVDateAdded = intel.PublishedDate.Format(time.RFC3339)
		}
	}

	// Exploit availability
	if intel.ExploitAvailable {
		f.PoCAvailable = true
	}

	// Backfill CVSS if Grype didn't provide it
	if f.CVSSv3Score == 0 && intel.CVSSv3Score > 0 {
		f.CVSSv3Score = intel.CVSSv3Score
		f.CVSSv3Vector = intel.CVSSv3Vector
		// Re-derive severity from the backfilled score
		if f.Severity == "UNKNOWN" || f.Severity == "" {
			f.Severity = string(SeverityFromCVSS(intel.CVSSv3Score))
		}
	}

	// MITRE ATT&CK (from cached intel)
	if len(intel.ATTACKTactics) > 0 {
		f.MITRETactics = intel.ATTACKTactics
	}
	if len(intel.ATTACKTechniques) > 0 {
		f.MITRETechniques = intel.ATTACKTechniques
	}

	// Track the intel source
	if intel.Source != "" {
		f.Sources = appendUnique(f.Sources, strings.ToLower(intel.Source))
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Confidence scoring
// ──────────────────────────────────────────────────────────────────────────────

// calculateConfidence returns a confidence level based on the quantity and
// quality of threat intelligence signals available for a finding.
//
// Scoring:
//   - CISA KEV confirmation: +40 (strongest signal — confirmed exploitation)
//   - EPSS data available:   +25 (probabilistic exploit prediction)
//   - InTheWild / exploit:   +20 (active exploitation observed)
//   - MITRE ATT&CK mapping:  +15 (tactical context available)
//
// Thresholds: ≥70 → high, ≥40 → medium, <40 → low
func calculateConfidence(f *EnrichedFinding) string {
	score := 0

	if f.InCISAKEV {
		score += 40
	}
	if f.EPSSScore > 0 {
		score += 25
	}
	if f.InTheWild || f.PoCAvailable {
		score += 20
	}
	if len(f.MITRETechniques) > 0 {
		score += 15
	}

	switch {
	case score >= 70:
		return string(ConfidenceHigh)
	case score >= 40:
		return string(ConfidenceMedium)
	default:
		return string(ConfidenceLow)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────────

// collectCVEIDs extracts unique CVE IDs from a slice of findings.
func collectCVEIDs(findings []EnrichedFinding) []string {
	seen := make(map[string]bool, len(findings))
	var ids []string
	for _, f := range findings {
		if strings.HasPrefix(f.CVEID, "CVE-") && !seen[f.CVEID] {
			seen[f.CVEID] = true
			ids = append(ids, f.CVEID)
		}
	}
	return ids
}

// appendUnique adds a string to a slice if it's not already present.
func appendUnique(slice []string, item string) []string {
	for _, s := range slice {
		if s == item {
			return slice
		}
	}
	return append(slice, item)
}
