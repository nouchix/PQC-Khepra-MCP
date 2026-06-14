package sca

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	// Syft library imports — direct Go library, no binary required
	syftlib "github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

// ──────────────────────────────────────────────────────────────────────────────
// CycloneDX Types (minimal — expanded as needed by downstream consumers)
// ──────────────────────────────────────────────────────────────────────────────

// CycloneDXBOM represents the subset of a CycloneDX JSON SBOM we need.
// This is our canonical internal representation — not tied to Syft's encoding.
type CycloneDXBOM struct {
	BOMFormat   string         `json:"bomFormat"`
	SpecVersion string         `json:"specVersion"`
	Version     int            `json:"version"`
	Metadata    CDXMetadata    `json:"metadata,omitempty"`
	Components  []CDXComponent `json:"components"`
}

// CDXMetadata holds SBOM metadata including the generating tool.
type CDXMetadata struct {
	Timestamp string   `json:"timestamp,omitempty"`
	Tools     CDXTools `json:"tools,omitempty"`
}

// CDXTools wraps the tools block in CycloneDX 1.5+ format.
type CDXTools struct {
	Components []CDXToolComponent `json:"components,omitempty"`
}

// CDXToolComponent identifies a tool (e.g. Syft) and its version.
type CDXToolComponent struct {
	Type    string `json:"type,omitempty"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

// CDXComponent represents a software component in the CycloneDX SBOM.
type CDXComponent struct {
	Type       string       `json:"type"`
	Name       string       `json:"name"`
	Version    string       `json:"version"`
	PURL       string       `json:"purl,omitempty"`
	CPE        string       `json:"cpe,omitempty"`
	BOMRef     string       `json:"bom-ref,omitempty"`
	Licenses   []CDXLicense `json:"licenses,omitempty"`
	Properties []CDXProp    `json:"properties,omitempty"`
}

// CDXLicense represents a license entry.
type CDXLicense struct {
	License struct {
		ID   string `json:"id,omitempty"`
		Name string `json:"name,omitempty"`
	} `json:"license,omitempty"`
}

// CDXProp represents a key-value property.
type CDXProp struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Marshal serializes the CycloneDX BOM to JSON bytes.
func (b *CycloneDXBOM) Marshal() ([]byte, error) {
	return jsonMarshal(b)
}

// ──────────────────────────────────────────────────────────────────────────────
// SyftAdapter — Sovereign In-Process SBOM Generation
// ──────────────────────────────────────────────────────────────────────────────

// SyftAdapter generates SBOMs using the Syft Go library directly.
// Zero external binary dependency — full sovereignty per AD-002.
type SyftAdapter struct {
	// Timeout for SBOM generation. Default: 120s.
	Timeout time.Duration

	// cache stores checksums of lockfiles to avoid redundant SBOM generation.
	cache   map[string]cachedBOM
	cacheMu sync.RWMutex

	// internalSBOM stores the raw Syft SBOM for downstream consumers (e.g. Grype).
	lastSBOM   *sbom.SBOM
	lastSBOMMu sync.RWMutex
}

type cachedBOM struct {
	checksum    string
	bom         *CycloneDXBOM
	meta        *ScannerMetadata
	internalBOM *sbom.SBOM // retained for Grype consumption
}

// Known lockfile names per ecosystem — used for cache invalidation.
var lockfileNames = []string{
	"go.sum",            // Go
	"package-lock.json", // Node.js (npm)
	"yarn.lock",         // Node.js (yarn)
	"pnpm-lock.yaml",    // Node.js (pnpm)
	"Pipfile.lock",      // Python (pipenv)
	"poetry.lock",       // Python (poetry)
	"requirements.txt",  // Python (pip)
	"Cargo.lock",        // Rust
	"Gemfile.lock",      // Ruby
	"composer.lock",     // PHP
	"pom.xml",           // Java (Maven)
	"build.gradle.kts",  // Java (Gradle)
	"gradle.lockfile",   // Java (Gradle)
}

// NewSyftAdapter creates a SyftAdapter with production defaults.
func NewSyftAdapter() *SyftAdapter {
	return &SyftAdapter{
		Timeout: 120 * time.Second,
		cache:   make(map[string]cachedBOM),
	}
}

// GenerateSBOM uses the Syft library directly (in-process) to generate a CycloneDX BOM.
// No external binary required — sovereign execution.
//
// Returns a CycloneDX BOM, scanner metadata, and any error.
func (a *SyftAdapter) GenerateSBOM(ctx context.Context, projectPath string) (*CycloneDXBOM, *ScannerMetadata, error) {
	if projectPath == "" {
		return nil, nil, fmt.Errorf("sca/syft: projectPath is required")
	}

	absPath, err := filepath.Abs(projectPath)
	if err != nil {
		return nil, nil, fmt.Errorf("sca/syft: cannot resolve path: %w", err)
	}

	// Verify path exists
	_, err = os.Stat(absPath)
	if err != nil {
		return nil, nil, fmt.Errorf("sca/syft: path does not exist: %w", err)
	}

	// ── Cache check ────────────────────────────────────────────────────
	checksum := a.computeLockfileChecksum(absPath)
	if checksum != "" {
		a.cacheMu.RLock()
		if cached, ok := a.cache[absPath]; ok && cached.checksum == checksum {
			a.cacheMu.RUnlock()
			// Also update the lastSBOM for Grype
			a.lastSBOMMu.Lock()
			a.lastSBOM = cached.internalBOM
			a.lastSBOMMu.Unlock()
			return cached.bom, cached.meta, nil
		}
		a.cacheMu.RUnlock()
	}

	// ── Resolve target for Syft library ───────────────────────────────
	// Note: when using the Go library directly, pass the absolute path as-is.
	// Do NOT add "dir:" prefix — that's for CLI/user-input parsing and breaks
	// on paths with spaces (e.g., "khepra protocol").
	target := absPath

	// ── Execute Syft in-process ───────────────────────────────────────
	cmdCtx, cancel := context.WithTimeout(ctx, a.Timeout)
	defer cancel()

	log.Printf("[SCA/SYFT] Resolving source: %s", target)

	// Step 1: Resolve source
	srcCfg := syftlib.DefaultGetSourceConfig()
	src, err := syftlib.GetSource(cmdCtx, target, srcCfg)
	if err != nil {
		if cmdCtx.Err() == context.DeadlineExceeded {
			return nil, nil, fmt.Errorf("sca/syft: source resolution timed out after %s", a.Timeout)
		}
		return nil, nil, fmt.Errorf("sca/syft: failed to resolve source: %w", err)
	}
	defer func() {
		if closer, ok := src.(source.Source); ok {
			_ = closer.Close()
		}
	}()

	// Step 2: Create SBOM
	sbomCfg := syftlib.DefaultCreateSBOMConfig()
	rawSBOM, err := syftlib.CreateSBOM(cmdCtx, src, sbomCfg)
	if err != nil {
		if cmdCtx.Err() == context.DeadlineExceeded {
			return nil, nil, fmt.Errorf("sca/syft: SBOM generation timed out after %s", a.Timeout)
		}
		return nil, nil, fmt.Errorf("sca/syft: SBOM generation failed: %w", err)
	}

	// Step 3: Convert Syft's internal SBOM to our CycloneDX representation
	bom := convertSyftSBOMToCDX(rawSBOM)
	meta := extractSyftMetadataFromSBOM(rawSBOM)

	// Store raw SBOM for Grype consumption (zero-copy handoff)
	a.lastSBOMMu.Lock()
	a.lastSBOM = rawSBOM
	a.lastSBOMMu.Unlock()

	// ── Update cache ───────────────────────────────────────────────────
	if checksum != "" {
		a.cacheMu.Lock()
		a.cache[absPath] = cachedBOM{
			checksum:    checksum,
			bom:         bom,
			meta:        meta,
			internalBOM: rawSBOM,
		}
		a.cacheMu.Unlock()
	}

	log.Printf("[SCA/SYFT] SBOM generated: %d components (in-process)", len(bom.Components))
	return bom, meta, nil
}

// GetLastSBOM returns the raw Syft SBOM for direct Grype consumption.
// This avoids re-serializing/deserializing the SBOM between adapters.
func (a *SyftAdapter) GetLastSBOM() *sbom.SBOM {
	a.lastSBOMMu.RLock()
	defer a.lastSBOMMu.RUnlock()
	return a.lastSBOM
}

// InvalidateCache clears the cached SBOM for a given project path.
func (a *SyftAdapter) InvalidateCache(projectPath string) {
	absPath, err := filepath.Abs(projectPath)
	if err != nil {
		return
	}
	a.cacheMu.Lock()
	delete(a.cache, absPath)
	a.cacheMu.Unlock()
}

// ──────────────────────────────────────────────────────────────────────────────
// Conversion: Syft internal SBOM → CycloneDX (our canonical format)
// ──────────────────────────────────────────────────────────────────────────────

// convertSyftSBOMToCDX converts a raw Syft SBOM to our CycloneDX representation.
func convertSyftSBOMToCDX(s *sbom.SBOM) *CycloneDXBOM {
	if s == nil {
		return &CycloneDXBOM{
			BOMFormat:   "CycloneDX",
			SpecVersion: "1.5",
			Version:     1,
			Components:  make([]CDXComponent, 0),
		}
	}

	bom := &CycloneDXBOM{
		BOMFormat:   "CycloneDX",
		SpecVersion: "1.5",
		Version:     1,
		Metadata: CDXMetadata{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Tools: CDXTools{
				Components: []CDXToolComponent{
					{Type: "application", Name: "syft", Version: "embedded"},
				},
			},
		},
		Components: make([]CDXComponent, 0),
	}

	// Iterate over all packages in the SBOM
	for p := range s.Artifacts.Packages.Enumerate() {
		comp := CDXComponent{
			Type:    "library",
			Name:    p.Name,
			Version: p.Version,
		}

		// Extract PURL
		if p.PURL != "" {
			comp.PURL = p.PURL
		}

		// Extract CPEs
		if len(p.CPEs) > 0 {
			comp.CPE = p.CPEs[0].Attributes.BindToFmtString()
		}

		bom.Components = append(bom.Components, comp)
	}

	return bom
}

// extractSyftMetadataFromSBOM pulls Syft version info from the raw SBOM.
func extractSyftMetadataFromSBOM(s *sbom.SBOM) *ScannerMetadata {
	meta := &ScannerMetadata{
		ScannedAt:   time.Now(),
		SyftVersion: "embedded", // Using library, no binary version
	}
	return meta
}

// ──────────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────────

// computeLockfileChecksum computes a combined SHA-256 of all lockfiles found
// in the project directory. Returns empty string if none found (no caching).
func (a *SyftAdapter) computeLockfileChecksum(projectDir string) string {
	h := sha256.New()
	found := false

	for _, name := range lockfileNames {
		path := filepath.Join(projectDir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		h.Write([]byte(name))
		h.Write(data)
		found = true
	}

	if !found {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

// jsonMarshal is a helper alias to avoid import cycles.
var jsonMarshal = func(v interface{}) ([]byte, error) {
	return jsonMarshalImpl(v)
}

// The actual implementation will be set during init to break the cycle.
// This uses encoding/json directly.
func init() {
	// Override with actual json.Marshal
	jsonMarshal = func(v interface{}) ([]byte, error) {
		return jsonMarshalImpl(v)
	}
}

// StringContains checks if a string is present in a slice.
func stringContains(slice []string, s string) bool {
	for _, v := range slice {
		if strings.EqualFold(v, s) {
			return true
		}
	}
	return false
}
