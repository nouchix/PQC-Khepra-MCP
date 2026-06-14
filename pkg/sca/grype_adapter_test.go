package sca

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ──────────────────────────────────────────────────────────────────────────────
// Realistic Grype JSON sample (matches actual `grype -o json` output)
// ──────────────────────────────────────────────────────────────────────────────

const sampleGrypeJSON = `{
  "matches": [
    {
      "vulnerability": {
        "id": "CVE-2024-45337",
        "dataSource": "https://nvd.nist.gov/vuln/detail/CVE-2024-45337",
        "severity": "Critical",
        "description": "SSH handshake vulnerability in golang.org/x/crypto",
        "cvss": [
          {
            "source": "nvd@nist.gov",
            "type": "Primary",
            "version": "3.1",
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            "metrics": {"baseScore": 9.1}
          }
        ],
        "fix": {
          "versions": ["0.31.0"],
          "state": "fixed"
        },
        "urls": ["https://github.com/golang/go/issues/70666"]
      },
      "artifact": {
        "name": "golang.org/x/crypto",
        "version": "v0.17.0",
        "type": "go-module",
        "purl": "pkg:golang/golang.org/x/crypto@v0.17.0",
        "cpes": ["cpe:2.3:a:golang:x_crypto:0.17.0:*:*:*:*:go:*:*"],
        "locations": [{"path": "/go.sum"}]
      }
    },
    {
      "vulnerability": {
        "id": "CVE-2023-44487",
        "dataSource": "https://nvd.nist.gov/vuln/detail/CVE-2023-44487",
        "severity": "High",
        "description": "HTTP/2 Rapid Reset attack",
        "cvss": [
          {
            "source": "nvd@nist.gov",
            "type": "Primary",
            "version": "3.1",
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
            "metrics": {"baseScore": 7.5}
          },
          {
            "source": "redhat",
            "version": "3.1",
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
            "metrics": {"baseScore": 7.5}
          }
        ],
        "fix": {
          "versions": ["0.17.0"],
          "state": "fixed"
        },
        "urls": []
      },
      "artifact": {
        "name": "golang.org/x/net",
        "version": "v0.15.0",
        "type": "go-module",
        "purl": "pkg:golang/golang.org/x/net@v0.15.0",
        "cpes": [],
        "locations": [{"path": "/go.sum"}]
      }
    },
    {
      "vulnerability": {
        "id": "GHSA-xg2h-wx96-xgxr",
        "dataSource": "https://github.com/advisories/GHSA-xg2h-wx96-xgxr",
        "severity": "Medium",
        "description": "Prototype pollution in lodash",
        "cvss": [],
        "fix": {
          "versions": ["4.17.21"],
          "state": "fixed"
        },
        "urls": []
      },
      "artifact": {
        "name": "lodash",
        "version": "4.17.20",
        "type": "npm",
        "purl": "pkg:npm/lodash@4.17.20",
        "cpes": ["cpe:2.3:a:lodash:lodash:4.17.20:*:*:*:*:node.js:*:*"],
        "locations": [{"path": "/node_modules/lodash/package.json"}]
      }
    }
  ],
  "descriptor": {
    "name": "grype",
    "version": "0.79.0",
    "db": {
      "built": "2024-12-19T01:32:02Z",
      "schemaVersion": 5,
      "location": "/home/user/.cache/grype/db/5",
      "checksum": "sha256:abc123def456"
    }
  }
}`

const sampleGrypeEmptyJSON = `{
  "matches": [],
  "descriptor": {
    "name": "grype",
    "version": "0.79.0",
    "db": {
      "built": "2024-12-19T01:32:02Z",
      "schemaVersion": 5
    }
  }
}`

// ──────────────────────────────────────────────────────────────────────────────
// Adapter construction
// ──────────────────────────────────────────────────────────────────────────────

func TestNewGrypeAdapter_Defaults(t *testing.T) {
	a := NewGrypeAdapter()
	if a.Timeout != 180*time.Second {
		t.Errorf("default timeout: got %v, want 180s", a.Timeout)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Error paths (no grype binary required)
// ──────────────────────────────────────────────────────────────────────────────

func TestGrypeAdapter_MatchVulnerabilities_EmptyTarget(t *testing.T) {
	a := NewGrypeAdapter()
	_, _, err := a.MatchVulnerabilities(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for empty target")
	}
}

func TestGrypeAdapter_MatchVulnerabilities_NonExistentTarget(t *testing.T) {
	a := NewGrypeAdapter()
	_, _, err := a.MatchVulnerabilities(context.Background(), "/nonexistent/path/xyz")
	if err == nil {
		t.Fatal("expected error for non-existent target")
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// JSON parsing & conversion
// ──────────────────────────────────────────────────────────────────────────────

func TestGrypeOutput_Parse(t *testing.T) {
	var output GrypeOutput
	if err := json.Unmarshal([]byte(sampleGrypeJSON), &output); err != nil {
		t.Fatalf("failed to parse sample Grype JSON: %v", err)
	}

	if len(output.Matches) != 3 {
		t.Fatalf("matches count: got %d, want 3", len(output.Matches))
	}

	// Verify first match
	m := output.Matches[0]
	if m.Vulnerability.ID != "CVE-2024-45337" {
		t.Errorf("match[0] vuln ID: got %q", m.Vulnerability.ID)
	}
	if m.Vulnerability.Severity != "Critical" {
		t.Errorf("match[0] severity: got %q", m.Vulnerability.Severity)
	}
	if m.Artifact.Name != "golang.org/x/crypto" {
		t.Errorf("match[0] artifact name: got %q", m.Artifact.Name)
	}
	if m.Artifact.PURL != "pkg:golang/golang.org/x/crypto@v0.17.0" {
		t.Errorf("match[0] PURL: got %q", m.Artifact.PURL)
	}

	// Verify CVSS
	if len(m.Vulnerability.CVSS) != 1 {
		t.Fatalf("match[0] CVSS count: got %d, want 1", len(m.Vulnerability.CVSS))
	}
	if m.Vulnerability.CVSS[0].Metrics.BaseScore != 9.1 {
		t.Errorf("match[0] CVSS score: got %f", m.Vulnerability.CVSS[0].Metrics.BaseScore)
	}

	// Verify descriptor
	if output.Descriptor.Version != "0.79.0" {
		t.Errorf("descriptor version: got %q", output.Descriptor.Version)
	}
	if output.Descriptor.DB.SchemaVersion != 5 {
		t.Errorf("DB schema version: got %d", output.Descriptor.DB.SchemaVersion)
	}
}

func TestGrypeOutput_ParseEmpty(t *testing.T) {
	var output GrypeOutput
	if err := json.Unmarshal([]byte(sampleGrypeEmptyJSON), &output); err != nil {
		t.Fatalf("failed to parse empty Grype JSON: %v", err)
	}
	if len(output.Matches) != 0 {
		t.Errorf("expected 0 matches, got %d", len(output.Matches))
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Grype → EnrichedFinding conversion
// ──────────────────────────────────────────────────────────────────────────────

func TestConvertGrypeToEnriched(t *testing.T) {
	var output GrypeOutput
	json.Unmarshal([]byte(sampleGrypeJSON), &output)

	findings := convertGrypeToEnriched(output.Matches)

	if len(findings) != 3 {
		t.Fatalf("findings count: got %d, want 3", len(findings))
	}

	// ── Finding 0: CVE-2024-45337 (Critical, x/crypto) ──
	f0 := findings[0]
	if f0.CVEID != "CVE-2024-45337" {
		t.Errorf("f[0] CVEID: got %q", f0.CVEID)
	}
	if f0.Severity != "CRITICAL" {
		t.Errorf("f[0] Severity: got %q, want CRITICAL", f0.Severity)
	}
	if f0.CVSSv3Score != 9.1 {
		t.Errorf("f[0] CVSSv3Score: got %f, want 9.1", f0.CVSSv3Score)
	}
	if f0.CVSSv3Vector != "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N" {
		t.Errorf("f[0] CVSSv3Vector: got %q", f0.CVSSv3Vector)
	}
	if f0.Ecosystem != "go" {
		t.Errorf("f[0] Ecosystem: got %q, want go", f0.Ecosystem)
	}
	if f0.PackageURL != "pkg:golang/golang.org/x/crypto@v0.17.0" {
		t.Errorf("f[0] PackageURL: got %q", f0.PackageURL)
	}
	if f0.CPE != "cpe:2.3:a:golang:x_crypto:0.17.0:*:*:*:*:go:*:*" {
		t.Errorf("f[0] CPE: got %q", f0.CPE)
	}
	if len(f0.Sources) != 1 || f0.Sources[0] != "grype" {
		t.Errorf("f[0] Sources: got %v", f0.Sources)
	}

	// Should be high risk (CRITICAL severity)
	if !f0.IsHighRisk() {
		t.Error("f[0] should be high risk (CRITICAL)")
	}

	// ── Finding 1: CVE-2023-44487 (High, x/net, multiple CVSS sources) ──
	f1 := findings[1]
	if f1.CVEID != "CVE-2023-44487" {
		t.Errorf("f[1] CVEID: got %q", f1.CVEID)
	}
	if f1.Severity != "HIGH" {
		t.Errorf("f[1] Severity: got %q, want HIGH", f1.Severity)
	}
	if f1.CVSSv3Score != 7.5 {
		t.Errorf("f[1] CVSSv3Score: got %f, want 7.5", f1.CVSSv3Score)
	}
	// NVD source should be preferred over redhat
	if f1.CVSSv3Vector == "" {
		t.Error("f[1] CVSSv3Vector should be populated from NVD source")
	}

	// ── Finding 2: GHSA (Medium, lodash, no CVSS) ──
	f2 := findings[2]
	if f2.CVEID != "GHSA-xg2h-wx96-xgxr" {
		t.Errorf("f[2] CVEID: got %q", f2.CVEID)
	}
	if f2.Severity != "MEDIUM" {
		t.Errorf("f[2] Severity: got %q, want MEDIUM", f2.Severity)
	}
	if f2.Ecosystem != "npm" {
		t.Errorf("f[2] Ecosystem: got %q, want npm", f2.Ecosystem)
	}
	if f2.CVSSv3Score != 0 {
		t.Errorf("f[2] CVSSv3Score: should be 0 (no CVSS data), got %f", f2.CVSSv3Score)
	}
}

func TestConvertGrypeToEnriched_EmptyMatches(t *testing.T) {
	findings := convertGrypeToEnriched(nil)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for nil matches, got %d", len(findings))
	}

	findings = convertGrypeToEnriched([]GrypeMatch{})
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for empty matches, got %d", len(findings))
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// CVSS v3 selection logic
// ──────────────────────────────────────────────────────────────────────────────

func TestBestCVSSv3(t *testing.T) {
	// NVD should be preferred
	scores := []GrypeCVSS{
		{Source: "redhat", Version: "3.1", Vector: "CVSS:3.1/AV:N/...", Metrics: GrypeCVSSMetrics{BaseScore: 7.0}},
		{Source: "nvd@nist.gov", Version: "3.1", Vector: "CVSS:3.1/AV:N/AC:L/...", Metrics: GrypeCVSSMetrics{BaseScore: 9.1}},
	}
	best := bestCVSSv3(scores)
	if best == nil {
		t.Fatal("expected non-nil result")
	}
	if best.Metrics.BaseScore != 9.1 {
		t.Errorf("should prefer NVD: got score %f", best.Metrics.BaseScore)
	}

	// No NVD → fall back to first v3
	scores = []GrypeCVSS{
		{Source: "redhat", Version: "3.1", Vector: "CVSS:3.1/...", Metrics: GrypeCVSSMetrics{BaseScore: 7.0}},
	}
	best = bestCVSSv3(scores)
	if best == nil || best.Metrics.BaseScore != 7.0 {
		t.Error("should fall back to first v3 entry")
	}

	// Only v2 → nil
	scores = []GrypeCVSS{
		{Source: "nvd", Version: "2.0", Vector: "AV:N/AC:L/...", Metrics: GrypeCVSSMetrics{BaseScore: 5.0}},
	}
	best = bestCVSSv3(scores)
	if best != nil {
		t.Error("should return nil when only v2 available")
	}

	// Empty → nil
	best = bestCVSSv3(nil)
	if best != nil {
		t.Error("should return nil for empty scores")
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Metadata extraction
// ──────────────────────────────────────────────────────────────────────────────

func TestExtractGrypeMetadata(t *testing.T) {
	desc := &GrypeDescriptor{
		Name:    "grype",
		Version: "0.79.0",
		DB: GrypeDB{
			Built:         "2024-12-19T01:32:02Z",
			SchemaVersion: 5,
		},
	}

	meta := extractGrypeMetadata(desc)
	if meta.GrypeVersion != "0.79.0" {
		t.Errorf("GrypeVersion: got %q, want 0.79.0", meta.GrypeVersion)
	}
	if meta.GrypeDBVersion != "2024-12-19T01:32:02Z" {
		t.Errorf("GrypeDBVersion: got %q", meta.GrypeDBVersion)
	}
	if meta.ScannedAt.IsZero() {
		t.Error("ScannedAt should be set")
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// Utility function tests
// ──────────────────────────────────────────────────────────────────────────────

func TestNormalizeEcosystem(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"go-module", "go"}, {"gomod", "go"}, {"go", "go"},
		{"npm", "npm"}, {"javascript", "npm"},
		{"python", "pypi"}, {"pip", "pypi"},
		{"java-archive", "maven"}, {"jar", "maven"},
		{"rust", "cargo"}, {"cargo", "cargo"},
		{"gem", "gem"}, {"nuget", "nuget"},
		{"deb", "deb"}, {"rpm", "rpm"},
		{"unknown-type", "unknown-type"},
	}
	for _, tt := range tests {
		if got := normalizeEcosystem(tt.input); got != tt.want {
			t.Errorf("normalizeEcosystem(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestNormalizeSeverity(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"Critical", "CRITICAL"}, {"critical", "CRITICAL"},
		{"High", "HIGH"}, {"high", "HIGH"},
		{"Medium", "MEDIUM"},
		{"Low", "LOW"},
		{"Negligible", "LOW"},
		{"", "UNKNOWN"}, {"nonsense", "UNKNOWN"},
	}
	for _, tt := range tests {
		if got := normalizeSeverity(tt.input); got != tt.want {
			t.Errorf("normalizeSeverity(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestFirstOrEmpty(t *testing.T) {
	if got := firstOrEmpty(nil); got != "" {
		t.Errorf("nil: got %q", got)
	}
	if got := firstOrEmpty([]string{}); got != "" {
		t.Errorf("empty: got %q", got)
	}
	if got := firstOrEmpty([]string{"a", "b"}); got != "a" {
		t.Errorf("got %q, want a", got)
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// SBOM file detection
// ──────────────────────────────────────────────────────────────────────────────

func TestIsSBOMFile(t *testing.T) {
	// CycloneDX JSON file
	dir := t.TempDir()
	cdxPath := filepath.Join(dir, "sbom.json")
	os.WriteFile(cdxPath, []byte(`{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}`), 0644)
	if !isSBOMFile(cdxPath) {
		t.Error("should detect CycloneDX JSON as SBOM")
	}

	// Regular JSON file (not SBOM)
	regPath := filepath.Join(dir, "config.json")
	os.WriteFile(regPath, []byte(`{"name":"test","version":"1.0"}`), 0644)
	if isSBOMFile(regPath) {
		t.Error("should NOT detect regular JSON as SBOM")
	}

	// Non-JSON file
	txtPath := filepath.Join(dir, "readme.txt")
	os.WriteFile(txtPath, []byte(`hello world`), 0644)
	if isSBOMFile(txtPath) {
		t.Error("should NOT detect .txt as SBOM")
	}

	// Directory (not a file)
	if isSBOMFile(dir) {
		t.Error("should NOT detect directory as SBOM")
	}
}
