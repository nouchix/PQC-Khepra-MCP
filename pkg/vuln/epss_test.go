package vuln

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// ──────────────────────────────────────────────────────────────────────────────
// EPSSRank classification
// ──────────────────────────────────────────────────────────────────────────────

func TestRankFromScore(t *testing.T) {
	tests := []struct {
		score float64
		want  EPSSRank
	}{
		{0.95, EPSSRankCritical},
		{0.70, EPSSRankCritical},
		{0.50, EPSSRankHigh},
		{0.40, EPSSRankHigh},
		{0.20, EPSSRankMedium},
		{0.10, EPSSRankMedium},
		{0.09, EPSSRankLow},
		{0.01, EPSSRankLow},
		{0.00, EPSSRankLow},
	}
	for _, tt := range tests {
		if got := RankFromScore(tt.score); got != tt.want {
			t.Errorf("RankFromScore(%.2f) = %q, want %q", tt.score, got, tt.want)
		}
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// EPSSClient unit tests
// ──────────────────────────────────────────────────────────────────────────────

func TestNewEPSSClient_Defaults(t *testing.T) {
	c := NewEPSSClient()
	if c.maxBatchSize != 30 {
		t.Errorf("maxBatchSize: got %d, want 30", c.maxBatchSize)
	}
	if c.rateLimit != 1200*time.Millisecond {
		t.Errorf("rateLimit: got %v", c.rateLimit)
	}
	if c.cache == nil {
		t.Error("cache should be initialized")
	}
}

func TestEPSSClient_BatchGet_EmptyInput(t *testing.T) {
	c := NewEPSSClient()
	result, err := c.BatchGet(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("expected empty result, got %d", len(result))
	}
}

func TestEPSSClient_BatchGet_WithMockServer(t *testing.T) {
	// Mock FIRST.org EPSS API
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"status":      "OK",
			"status-code": 200,
			"version":     "1.0",
			"total":       2,
			"data": []map[string]string{
				{"cve": "CVE-2021-44228", "epss": "0.97565", "percentile": "0.99998", "date": "2024-12-19"},
				{"cve": "CVE-2022-32149", "epss": "0.00483", "percentile": "0.75332", "date": "2024-12-19"},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	c := NewEPSSClientWithOptions(
		WithEPSSBaseURL(server.URL),
		WithEPSSRateLimit(0), // No rate limit for testing
	)

	result, err := c.BatchGet(context.Background(), []string{
		"CVE-2021-44228",
		"CVE-2022-32149",
	})
	if err != nil {
		t.Fatalf("BatchGet failed: %v", err)
	}

	// Verify Log4Shell
	log4j, ok := result["CVE-2021-44228"]
	if !ok {
		t.Fatal("CVE-2021-44228 not in result")
	}
	if log4j.EPSSScore < 0.9 {
		t.Errorf("Log4Shell EPSS: got %f, expected > 0.9", log4j.EPSSScore)
	}
	if log4j.Percentile < 0.99 {
		t.Errorf("Log4Shell percentile: got %f, expected > 0.99", log4j.Percentile)
	}
	if RankFromScore(log4j.EPSSScore) != EPSSRankCritical {
		t.Errorf("Log4Shell rank: got %q, want critical", RankFromScore(log4j.EPSSScore))
	}

	// Verify x/text CVE
	xtext, ok := result["CVE-2022-32149"]
	if !ok {
		t.Fatal("CVE-2022-32149 not in result")
	}
	if xtext.EPSSScore >= 0.10 {
		t.Errorf("x/text EPSS: got %f, expected < 0.10", xtext.EPSSScore)
	}
	if RankFromScore(xtext.EPSSScore) != EPSSRankLow {
		t.Errorf("x/text rank: got %q, want low", RankFromScore(xtext.EPSSScore))
	}

	// Verify cache populated
	if c.CacheSize() != 2 {
		t.Errorf("cache size: got %d, want 2", c.CacheSize())
	}
}

func TestEPSSClient_CacheHit(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		resp := map[string]interface{}{
			"status": "OK", "status-code": 200, "total": 1,
			"data": []map[string]string{
				{"cve": "CVE-2021-44228", "epss": "0.97", "percentile": "0.99", "date": "2024-12-19"},
			},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	c := NewEPSSClientWithOptions(
		WithEPSSBaseURL(server.URL),
		WithEPSSRateLimit(0),
	)

	// First call → API hit
	c.BatchGet(context.Background(), []string{"CVE-2021-44228"})
	if callCount != 1 {
		t.Fatalf("expected 1 API call, got %d", callCount)
	}

	// Second call → cache hit, no API call
	c.BatchGet(context.Background(), []string{"CVE-2021-44228"})
	if callCount != 1 {
		t.Errorf("expected cache hit (still 1 API call), got %d", callCount)
	}
}

func TestEPSSClient_Lookup(t *testing.T) {
	c := NewEPSSClient()
	// Not in cache
	_, found := c.Lookup("CVE-2021-44228")
	if found {
		t.Error("expected not found for empty cache")
	}

	// Seed cache manually
	c.cacheMu.Lock()
	c.cache["CVE-2021-44228"] = EPSSRecord{
		CVEID: "CVE-2021-44228", EPSSScore: 0.975, Percentile: 0.999,
	}
	c.cacheMu.Unlock()

	rec, found := c.Lookup("CVE-2021-44228")
	if !found {
		t.Fatal("expected found after seeding cache")
	}
	if rec.EPSSScore != 0.975 {
		t.Errorf("EPSS score: got %f, want 0.975", rec.EPSSScore)
	}
}

func TestEPSSClient_Invalidate(t *testing.T) {
	c := NewEPSSClient()
	c.cacheMu.Lock()
	c.cache["CVE-2021-44228"] = EPSSRecord{CVEID: "CVE-2021-44228", EPSSScore: 0.97}
	c.cache["CVE-2022-32149"] = EPSSRecord{CVEID: "CVE-2022-32149", EPSSScore: 0.01}
	c.cacheMu.Unlock()

	// Invalidate specific CVE
	c.Invalidate("CVE-2021-44228")
	if c.CacheSize() != 1 {
		t.Errorf("after specific invalidate: cache size %d, want 1", c.CacheSize())
	}

	// Invalidate all
	c.Invalidate()
	if c.CacheSize() != 0 {
		t.Errorf("after full invalidate: cache size %d, want 0", c.CacheSize())
	}
}

func TestEPSSClient_FilterNonCVE(t *testing.T) {
	c := NewEPSSClient()
	// GHSA IDs should be filtered out (EPSS only works with CVEs)
	missing := c.getMissing([]string{
		"CVE-2021-44228",
		"GHSA-xg2h-wx96-xgxr",
		"CVE-2022-32149",
		"not-a-cve",
	})
	if len(missing) != 2 {
		t.Errorf("expected 2 CVE IDs after filtering, got %d: %v", len(missing), missing)
	}
}

func TestEPSSClient_Deduplication(t *testing.T) {
	c := NewEPSSClient()
	missing := c.getMissing([]string{
		"CVE-2021-44228",
		"CVE-2021-44228",
		"CVE-2021-44228",
	})
	if len(missing) != 1 {
		t.Errorf("expected 1 after dedup, got %d", len(missing))
	}
}

func TestEPSSClient_GracefulDegradation(t *testing.T) {
	// Server that returns 500
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	c := NewEPSSClientWithOptions(
		WithEPSSBaseURL(server.URL),
		WithEPSSRateLimit(0),
	)

	// Should return partial results (from cache) and an error
	result, err := c.BatchGet(context.Background(), []string{"CVE-2021-44228"})
	if err == nil {
		t.Error("expected error for 500 response")
	}
	// Result should still be non-nil (empty cache)
	if result == nil {
		t.Error("result should be non-nil even on error (graceful degradation)")
	}
}

func TestEPSSClient_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second) // Simulate slow response
	}))
	defer server.Close()

	c := NewEPSSClientWithOptions(
		WithEPSSBaseURL(server.URL),
		WithEPSSRateLimit(0),
		WithEPSSHTTPClient(&http.Client{Timeout: 500 * time.Millisecond}),
	)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	_, err := c.BatchGet(ctx, []string{"CVE-2021-44228"})
	if err == nil {
		t.Error("expected error for cancelled context")
	}
}

func TestEPSSClient_BatchSplitting(t *testing.T) {
	batchesReceived := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		batchesReceived++
		resp := map[string]interface{}{
			"status": "OK", "status-code": 200, "total": 0,
			"data": []map[string]string{},
		}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	c := NewEPSSClientWithOptions(
		WithEPSSBaseURL(server.URL),
		WithEPSSRateLimit(0),
	)
	c.maxBatchSize = 5 // Small batch size for testing

	// 12 CVEs should result in 3 batches (5+5+2)
	cves := make([]string, 12)
	for i := range cves {
		cves[i] = fmt.Sprintf("CVE-2024-%05d", i+1)
	}

	c.BatchGet(context.Background(), cves)
	if batchesReceived != 3 {
		t.Errorf("expected 3 batches, got %d", batchesReceived)
	}
}
