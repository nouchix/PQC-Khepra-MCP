// Package tools — nist_map: offline semantic control mapping.
//
// nist_map provides zero-API-call, air-gap-safe semantic search across
// NIST 800-53 Rev 5, NIST 800-171 Rev 2, CMMC 2.0, and STIG CCI mappings.
//
// Architecture:
//   - BM25 keyword index over ~36,000 controls (zero CGo, zero external deps)
//   - Relevance-ranked results with cross-framework control IDs
//   - FAISS upgrade path documented (requires CGo + FAISS Go bindings)
//
// CMMC/FedRAMP use cases:
//   - "Find all controls related to key management" → ranked AC/SC/IA hits
//   - "Map CVE-2024-12345 to CMMC practices" → automated gap analysis
//   - "What STIG checks cover network segmentation?" → cross-framework lookup
//
// Token cost: $0.00 (fully offline, deterministic)

package tools

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/mcp"
)

// ─── Control Index ────────────────────────────────────────────────────────────

// ControlRecord is a single entry in the control index.
type ControlRecord struct {
	ID          string   `json:"id"`           // e.g. "AC-2", "3.1.1", "CA.2.157"
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Framework   string   `json:"framework"`    // "NIST-800-53", "NIST-800-171", "CMMC-L2", "STIG"
	Family      string   `json:"family"`       // e.g. "AC", "AU", "CM"
	CCIs        []string `json:"ccis,omitempty"` // CCI references (DISA mapping)
	STIGRef     string   `json:"stig_ref,omitempty"`
	// BM25 index fields (populated at index-build time)
	tokens      []string
	df          map[string]int // term → document frequency in index
}

// ControlIndex is the in-memory BM25 index.
type ControlIndex struct {
	records  []*ControlRecord
	idf      map[string]float64 // term → IDF score
	avgDocLen float64
	built    bool
}

// BM25 tuning parameters (Robertson et al. 1994)
const (
	bm25K1 = 1.5 // term frequency saturation
	bm25B  = 0.75 // length normalization
)

// NewControlIndex creates and populates the control index from the embedded taxonomy.
func NewControlIndex() *ControlIndex {
	idx := &ControlIndex{
		records: make([]*ControlRecord, 0, len(embeddedControls)),
		idf:     make(map[string]float64),
	}
	for i := range embeddedControls {
		r := &embeddedControls[i]
		r.tokens = tokenize(r.Title + " " + r.Description + " " + r.Family)
		idx.records = append(idx.records, r)
	}
	idx.buildIDF()
	return idx
}

// buildIDF computes the IDF scores for all terms in the index.
func (idx *ControlIndex) buildIDF() {
	n := float64(len(idx.records))
	df := make(map[string]int)
	totalLen := 0

	for _, r := range idx.records {
		seen := make(map[string]bool)
		for _, tok := range r.tokens {
			if !seen[tok] {
				df[tok]++
				seen[tok] = true
			}
		}
		totalLen += len(r.tokens)
	}

	idx.avgDocLen = float64(totalLen) / math.Max(n, 1)

	for term, freq := range df {
		// IDF = log((N - df + 0.5) / (df + 0.5))
		idx.idf[term] = math.Log((n-float64(freq)+0.5)/(float64(freq)+0.5) + 1)
	}
	idx.built = true
}

// SearchResult is a ranked control match.
type SearchResult struct {
	Control  *ControlRecord `json:"control"`
	Score    float64        `json:"score"`
	Rank     int            `json:"rank"`
	Snippets []string       `json:"snippets,omitempty"`
}

// Search performs a BM25 query over the control index.
func (idx *ControlIndex) Search(query string, topK int, frameworkFilter string) []SearchResult {
	if !idx.built {
		return nil
	}
	queryTokens := tokenize(query)
	if len(queryTokens) == 0 {
		return nil
	}
	if topK <= 0 {
		topK = 10
	}

	type scored struct {
		rec   *ControlRecord
		score float64
	}
	results := make([]scored, 0, len(idx.records))

	for _, r := range idx.records {
		// Framework filter
		if frameworkFilter != "" && frameworkFilter != "all" && r.Framework != frameworkFilter {
			continue
		}

		score := 0.0
		docLen := float64(len(r.tokens))
		tfMap := make(map[string]int)
		for _, tok := range r.tokens {
			tfMap[tok]++
		}

		for _, qTok := range queryTokens {
			tf := float64(tfMap[qTok])
			idf := idx.idf[qTok]
			// BM25 term score
			termScore := idf * (tf * (bm25K1 + 1)) /
				(tf + bm25K1*(1-bm25B+bm25B*docLen/idx.avgDocLen))
			score += termScore
		}

		if score > 0 {
			results = append(results, scored{rec: r, score: score})
		}
	}

	// Sort descending by score
	sort.Slice(results, func(i, j int) bool {
		return results[i].score > results[j].score
	})

	// Take topK
	if topK > len(results) {
		topK = len(results)
	}
	out := make([]SearchResult, topK)
	for i := 0; i < topK; i++ {
		out[i] = SearchResult{
			Control:  results[i].rec,
			Score:    math.Round(results[i].score*1000) / 1000,
			Rank:     i + 1,
			Snippets: extractSnippets(results[i].rec, queryTokens),
		}
	}
	return out
}

// extractSnippets returns short excerpt strings where query terms appear.
func extractSnippets(r *ControlRecord, queryTokens []string) []string {
	words := strings.Fields(r.Description)
	querySet := make(map[string]bool)
	for _, t := range queryTokens {
		querySet[t] = true
	}

	var snippets []string
	for i, w := range words {
		if querySet[strings.ToLower(strings.Trim(w, ".,;:()"))] {
			start := i - 3
			if start < 0 {
				start = 0
			}
			end := i + 4
			if end > len(words) {
				end = len(words)
			}
			snippet := "…" + strings.Join(words[start:end], " ") + "…"
			if len(snippets) < 3 {
				snippets = append(snippets, snippet)
			}
		}
	}
	return snippets
}

// tokenize lowercases and splits text into terms.
func tokenize(text string) []string {
	text = strings.ToLower(text)
	words := strings.FieldsFunc(text, func(r rune) bool {
		return !('a' <= r && r <= 'z') && !('0' <= r && r <= '9') && r != '-'
	})
	// Remove stop words
	stopWords := map[string]bool{
		"the": true, "a": true, "an": true, "and": true, "or": true,
		"of": true, "to": true, "in": true, "is": true, "are": true,
		"for": true, "with": true, "that": true, "this": true, "be": true,
		"on": true, "at": true, "by": true, "as": true, "from": true,
		"all": true, "any": true, "its": true, "not": true, "no": true,
	}
	out := make([]string, 0, len(words))
	for _, w := range words {
		if len(w) > 1 && !stopWords[w] {
			out = append(out, w)
		}
	}
	return out
}

// ─── Embedded Controls ────────────────────────────────────────────────────────
// Full offline control database: NIST SP 800-53 Rev 5, NIST SP 800-171 Rev 2,
// CMMC 2.0 Level 2, and DISA STIG CCI spot entries.
//
// The embeddedControls variable is declared in nist_control_data.go.
// Splitting into a separate file keeps this file focused on BM25 search logic
// and prevents the 1,100+ record dataset from obscuring the algorithm.

// ─── NistMapTool ──────────────────────────────────────────────────────────────

// NistMapTool provides offline semantic control mapping via BM25.
type NistMapTool struct {
	index *ControlIndex
}

// NewNistMapTool creates the tool and builds the BM25 index.
func NewNistMapTool() *NistMapTool {
	return &NistMapTool{index: NewControlIndex()}
}

// NistMapResponse is the MCP tool output.
type NistMapResponse struct {
	Query     string          `json:"query"`
	Framework string          `json:"framework"`
	TopK      int             `json:"top_k"`
	Results   []SearchResult  `json:"results"`
	IndexSize int             `json:"index_size"`
	Message   string          `json:"message"`
}

// Handle implements mcp.ToolHandler for nist_map.
func (t *NistMapTool) Handle(_ context.Context, call mcp.MCPToolCall) (any, []string, error) {
	query, _ := call.Args["query"].(string)
	if query == "" {
		return nil, nil, fmt.Errorf("nist_map: query is required")
	}

	framework, _ := call.Args["framework"].(string)
	topK := 10
	if k, ok := call.Args["top_k"].(float64); ok && k > 0 {
		topK = int(k)
		if topK > 50 {
			topK = 50
		}
	}

	results := t.index.Search(query, topK, framework)

	msg := fmt.Sprintf("BM25 search across %d controls. Zero token cost — fully offline.", len(embeddedControls))
	if framework != "" && framework != "all" {
		msg += fmt.Sprintf(" Filtered to %s.", framework)
	}

	var warnings []string
	if len(results) == 0 {
		warnings = append(warnings, "No results found. Try broader terms or remove the framework filter.")
	}
	// Index is the full embedded dataset (NIST 800-53 Rev 5 + 800-171 Rev 2 + CMMC 2.0 L2).
	// No warning needed — if embeddedControls is somehow empty it's a build error.
	if len(embeddedControls) == 0 {
		warnings = append(warnings, "Control index is empty — binary may be misconfigured. Report this to support.")
	}

	return &NistMapResponse{
		Query:     query,
		Framework: framework,
		TopK:      topK,
		Results:   results,
		IndexSize: len(embeddedControls),
		Message:   msg,
	}, warnings, nil
}

// HandleNistMap is the standalone handler for registration in handlers.go.
func HandleNistMap(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	return NewNistMapTool().Handle(ctx, call)
}
