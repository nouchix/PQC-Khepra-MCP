//go:build saas

// Package main — init_stig_live.go
// Startup hook: live STIG enrichment + changelog-based cache invalidation.
//
// IP: SOUHIMBOU DOH KONE LLC — exclusively licensed to SecRed Knowledge Inc.
// USPTO #73565085 (KHEPRA Protocol)
//
// Runs as a background goroutine so it never blocks server startup.
// Sovereign mode: if STIGVIEWER_API_KEY is absent, this is a complete no-op.

package main

import (
	"context"
	"log"
	"os"
	"time"

	"github.com/nouchix/PQC-Khepra-MCP/pkg/stig"
)

// initSTIGLiveData runs two operations in sequence after server startup:
//
//  1. Changelog check — invalidates disk cache for any STIG that has a new
//     DISA release since the last known sync date (KHEPRA_STIG_LAST_SYNC env var,
//     defaults to 30 days ago). Cache-busted STIGs are re-fetched on next request.
//
//  2. BatchCrosswalk enrichment — overlays live CCI→NIST 800-53 data from
//     STIGViewer onto the embedded 7,433-row CSV, adding net-new mappings for
//     CCIs that are new or updated in the current DISA catalog.
//
// Call as: go initSTIGLiveData()
// Safe to call concurrently — internally serialized with enrichMu.
func initSTIGLiveData() {
	key := os.Getenv("STIGVIEWER_API_KEY")
	if key == "" {
		// Air-gap / sovereign mode — embedded data is the full dataset. No-op.
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	fetcher := stig.NewLiveFetcher(key, "")

	// ── Step 1: Changelog — invalidate stale disk caches ─────────────────────
	// Find the last sync date: KHEPRA_STIG_LAST_SYNC env var (YYYY-MM-DD).
	// If not set, use 30 days ago as a conservative default.
	lastSync := os.Getenv("KHEPRA_STIG_LAST_SYNC")
	if lastSync == "" {
		lastSync = time.Now().AddDate(0, 0, -30).Format("2006-01-02")
	}

	changes, err := fetcher.Changelog(ctx, lastSync)
	if err != nil {
		log.Printf("[STIG-LIVE] Changelog check failed (non-fatal): %v", err)
	} else if len(changes) > 0 {
		log.Printf("[STIG-LIVE] Changelog: %d STIG(s) updated since %s", len(changes), lastSync)
		for _, ch := range changes {
			log.Printf("[STIG-LIVE]   %-55s %s → %s  (%s)",
				ch.Slug, ch.PreviousVersion, ch.NewVersion, ch.ReleaseDate)
		}
		// Invalidate disk cache for changed slugs
		f2 := stig.NewLiveFetcher(key, "") // fresh fetcher to access cache path
		invalidated, iErr := f2.InvalidateChangedCaches(ctx, lastSync)
		if iErr != nil {
			log.Printf("[STIG-LIVE] Cache invalidation error (non-fatal): %v", iErr)
		} else if len(invalidated) > 0 {
			log.Printf("[STIG-LIVE] Cache evicted for: %v", invalidated)
		}
		// Update env so the next restart knows the current sync date
		_ = os.Setenv("KHEPRA_STIG_LAST_SYNC", time.Now().Format("2006-01-02"))
	} else {
		log.Printf("[STIG-LIVE] Changelog: all STIGs current (no changes since %s)", lastSync)
	}

	// ── Step 2: BatchCrosswalk enrichment ─────────────────────────────────────
	db, err := stig.GetDatabase()
	if err != nil {
		log.Printf("[STIG-LIVE] GetDatabase failed — skipping live enrichment: %v", err)
		return
	}

	enrichCtx, enrichCancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer enrichCancel()

	stats, err := db.EnrichWithLiveCrosswalk(enrichCtx, fetcher)
	if err != nil {
		log.Printf("[STIG-LIVE] CCI enrichment failed (non-fatal, embedded data intact): %v", err)
		return
	}

	if stats.NewMappings > 0 {
		log.Printf("[STIG-LIVE] CCI→NIST53 enrichment: +%d new mappings across %d CCIs (from %d queried) in %s",
			stats.NewMappings, stats.UpdatedCCIs, stats.CCIsQueried, stats.Duration.Round(time.Millisecond))
	} else {
		log.Printf("[STIG-LIVE] CCI→NIST53 enrichment: embedded DB matches live API (%d CCIs verified in %s)",
			stats.CCIsQueried, stats.Duration.Round(time.Millisecond))
	}
}
