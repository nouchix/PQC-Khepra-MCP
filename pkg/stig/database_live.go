// Package stig — database_live.go
// Live enrichment of the embedded compliance database via STIGViewer API.
//
// IP: SOUHIMBOU DOH KONE LLC — exclusively licensed to SecRed Knowledge Inc.
// USPTO #73565085 (KHEPRA Protocol)
//
// Design principle: NON-DESTRUCTIVE enrichment.
// The embedded 7,433-row CCI_to_NIST53.csv is loaded first and is the baseline.
// EnrichWithLiveCrosswalk overlays LIVE data from the STIGViewer BatchCrosswalk API
// on top of that baseline — adding any new/updated mappings without removing existing ones.
//
// Why both? The CSV has rich Definition strings (used for UI display).
// The API has current DISA authority (the actual live mapping — may differ from CSV).
// Together they give the most complete CCI→NIST 800-53 picture possible.
//
// Sovereign mode: if STIGVIEWER_API_KEY is absent, this is a no-op.
// The embedded CSV always remains the fallback — zero network dependency for air-gap.

package stig

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// LiveEnrichmentStats records results of a live crosswalk enrichment run.
type LiveEnrichmentStats struct {
	CCIsQueried    int           // CCIs sent to BatchCrosswalk
	NewMappings    int           // Net-new CCI→NIST53 pairs added (not in CSV)
	UpdatedCCIs    int           // CCIs that had at least one new mapping added
	Duration       time.Duration
	CacheHits      int           // CCIs resolved from disk cache (no API call)
}

// enrichMu guards the one-time live enrichment to prevent duplicate API calls
// if multiple goroutines call EnrichWithLiveCrosswalk concurrently.
var enrichMu sync.Mutex

// EnrichWithLiveCrosswalk overlays live STIGViewer crosswalk data onto CCItoNIST53.
// Collects every unique CCI already in the database, sends them in batches of 250
// to POST /crosswalk/resolve/batch, and merges any new NIST53Refs into the map.
//
// Calling convention: invoke once at apiserver startup AFTER GetDatabase().
// Returns stats about what was added (log them; they're useful for audit).
// Non-fatal: errors are logged, never crash the service (embedded data still works).
//
// Example (apiserver startup):
//
//	db, _ := stig.GetDatabase()
//	fetcher := stig.NewLiveFetcher(os.Getenv("STIGVIEWER_API_KEY"), "")
//	stats, err := db.EnrichWithLiveCrosswalk(ctx, fetcher)
//	log.Printf("CCI enrichment: +%d mappings from STIGViewer live API", stats.NewMappings)
func (d *ComplianceDatabase) EnrichWithLiveCrosswalk(ctx context.Context, fetcher *LiveFetcher) (*LiveEnrichmentStats, error) {
	if !fetcher.Available(ctx) {
		// Air-gap / no key — silent no-op, embedded data is the full dataset
		return &LiveEnrichmentStats{}, nil
	}

	enrichMu.Lock()
	defer enrichMu.Unlock()

	start := time.Now()
	stats := &LiveEnrichmentStats{}

	// ── 1. Collect all unique CCIs from the loaded database ───────────────────
	d.mu.RLock()
	ccis := make([]string, 0, len(d.CCItoNIST53))
	for cci := range d.CCItoNIST53 {
		ccis = append(ccis, cci)
	}
	d.mu.RUnlock()

	stats.CCIsQueried = len(ccis)
	if len(ccis) == 0 {
		return stats, nil
	}

	// ── 2. BatchCrosswalk — 250 CCIs per call, auto-batched ──────────────────
	// Uses POST /api/v1/crosswalk/resolve/batch (confirmed live 2026-07-11).
	// Returns map[CCI]→[]string of NIST 800-53 control IDs.
	liveMap, err := fetcher.BatchCrosswalk(ctx, ccis)
	if err != nil {
		return stats, fmt.Errorf("BatchCrosswalk failed — embedded data unchanged: %w", err)
	}

	// ── 3. Merge live data into CCItoNIST53 (non-destructive) ────────────────
	d.mu.Lock()
	defer d.mu.Unlock()

	for cci, liveRefs := range liveMap {
		// Build a set of existing NIST53Refs for this CCI (from embedded CSV)
		existing := make(map[string]bool)
		for _, m := range d.CCItoNIST53[cci] {
			// Normalise: CSV uses "AC-1 a", "AC-1.1 (i and ii)" etc.
			// API uses "AC-1", "AC-8", "CM-6", etc. (root control only).
			// Match by checking if the existing ref STARTS WITH the API ref.
			existing[normalizeNIST53Ref(m.NIST53Ref)] = true
		}

		addedForCCI := 0
		for _, liveRef := range liveRefs {
			norm := normalizeNIST53Ref(liveRef)
			if existing[norm] {
				continue // Already covered by embedded CSV
			}
			// New mapping — add it with empty Definition (live-sourced, no definition text)
			newMapping := NIST53Mapping{
				CCIID:      cci,
				NIST53Ref:  liveRef,
				Definition: "", // API doesn't return definitions — CSV has them for existing refs
			}
			d.CCItoNIST53[cci] = append(d.CCItoNIST53[cci], newMapping)

			// Update reverse map
			d.NIST53toCCI[liveRef] = appendUnique(d.NIST53toCCI[liveRef], cci)

			addedForCCI++
			stats.NewMappings++
		}
		if addedForCCI > 0 {
			stats.UpdatedCCIs++
		}
	}

	stats.Duration = time.Since(start)
	return stats, nil
}

// EnrichCCIsFromSTIGFindings adds CCIs from live STIG findings that may NOT be in
// the embedded CCI_to_NIST53.csv (e.g. new CCIs introduced in RHEL10 V1R2).
// Call after EnrichWithLiveCrosswalk to ensure all ruleIdents from the live STIG
// are resolved to NIST 800-53, not just the ones in the embedded CSV baseline.
//
// Example:
//
//	findings, _ := fetcher.FetchSTIG(ctx, "red_hat_enterprise_linux_10")
//	stats, _ := db.EnrichCCIsFromSTIGFindings(ctx, fetcher, findings)
func (d *ComplianceDatabase) EnrichCCIsFromSTIGFindings(ctx context.Context, fetcher *LiveFetcher, findings []Finding) (*LiveEnrichmentStats, error) {
	if !fetcher.Available(ctx) {
		return &LiveEnrichmentStats{}, nil
	}

	// Collect CCIs from findings that are NOT yet in the database
	seen := make(map[string]bool)
	missing := []string{}

	d.mu.RLock()
	for _, f := range findings {
		for _, ref := range f.References {
			if !strings.HasPrefix(ref, "CCI-") {
				continue
			}
			if _, known := d.CCItoNIST53[ref]; !known && !seen[ref] {
				missing = append(missing, ref)
				seen[ref] = true
			}
		}
	}
	d.mu.RUnlock()

	if len(missing) == 0 {
		return &LiveEnrichmentStats{}, nil
	}

	start := time.Now()
	stats := &LiveEnrichmentStats{CCIsQueried: len(missing)}

	liveMap, err := fetcher.BatchCrosswalk(ctx, missing)
	if err != nil {
		return stats, fmt.Errorf("BatchCrosswalk for STIG findings: %w", err)
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	for cci, liveRefs := range liveMap {
		for _, ref := range liveRefs {
			m := NIST53Mapping{CCIID: cci, NIST53Ref: ref, Definition: ""}
			d.CCItoNIST53[cci] = append(d.CCItoNIST53[cci], m)
			d.NIST53toCCI[ref] = appendUnique(d.NIST53toCCI[ref], cci)
			stats.NewMappings++
		}
		stats.UpdatedCCIs++
	}
	stats.Duration = time.Since(start)
	return stats, nil
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

// normalizeNIST53Ref strips sub-control suffixes for matching.
// "AC-1 a" → "AC-1", "CM-6" → "CM-6", "AC-1.1 (i and ii)" → "AC-1".
// The API returns root controls; the CSV may have sub-controls.
func normalizeNIST53Ref(ref string) string {
	ref = strings.TrimSpace(ref)
	// Cut at first space (handles "AC-1 a", "AC-1 b" etc.)
	if idx := strings.Index(ref, " "); idx > 0 {
		ref = ref[:idx]
	}
	// Cut at first dot (handles "AC-1.1 (i)" etc.)
	if idx := strings.Index(ref, "."); idx > 0 {
		ref = ref[:idx]
	}
	return ref
}

// appendUnique appends s to slice only if not already present.
func appendUnique(slice []string, s string) []string {
	for _, existing := range slice {
		if existing == s {
			return slice
		}
	}
	return append(slice, s)
}

// LiveCrossWalkFromEnv is a convenience constructor that reads STIGVIEWER_API_KEY
// from the environment. Returns nil if the key is not set (sovereign/air-gap mode).
// Use this in apiserver startup to avoid importing os in every caller.
func LiveCrossWalkFromEnv() *LiveFetcher {
	key := os.Getenv("STIGVIEWER_API_KEY")
	if key == "" {
		return nil
	}
	return NewLiveFetcher(key, "")
}
