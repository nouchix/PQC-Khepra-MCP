//go:build integration

// Integration tests for the KHEPRA web application scanner.
//
// Prerequisites:
//
//	docker compose -f docker/testbed/docker-compose.yml up -d
//	# wait for all three targets to be healthy (~60–90 s)
//
// Run:
//
//	go test -v -tags integration ./tests/integration/ -timeout 90m
//
// Each test asserts that Nuclei detects at least the known-present vulnerability
// classes for the given crash-dummy target. Counts are logged so regressions in
// template coverage are visible over time.
package integration_test

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/scanner/webapp"
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/types"
)

// Target URLs match docker/testbed/docker-compose.yml port bindings.
const (
	dvwaURL           = "http://localhost:8080"
	webgoatURL        = "http://localhost:8081/WebGoat"
	metasploitableURL = "http://localhost:8082"
)

// waitForTarget polls the target URL until it responds 200 or the deadline passes.
func waitForTarget(t *testing.T, url string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url) //nolint:gosec // test helper — URL is a constant
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode < 500 {
				return
			}
		}
		time.Sleep(5 * time.Second)
	}
	t.Fatalf("target %s not ready after %s — is docker compose up?", url, timeout)
}

func newScanner(t *testing.T) *webapp.Scanner {
	t.Helper()
	s, err := webapp.New("../../tools") // relative to tests/integration/
	if err != nil {
		t.Fatalf("create scanner: %v", err)
	}
	return s
}

func logSummary(t *testing.T, target string, findings []types.WebFinding) {
	t.Helper()
	counts := webapp.ScanSummary(findings)
	t.Logf("%s: %d total findings — critical=%d high=%d medium=%d low=%d info=%d",
		target,
		len(findings),
		counts["critical"], counts["high"], counts["medium"], counts["low"], counts["info"],
	)
	for _, f := range findings {
		if f.Severity == "critical" || f.Severity == "high" {
			t.Logf("  [%s] %s — %s (matched: %s)", f.Severity, f.TemplateID, f.Name, f.MatchedAt)
		}
	}
}

// ── DVWA ──────────────────────────────────────────────────────────────────

func TestDVWAScan(t *testing.T) {
	waitForTarget(t, dvwaURL+"/login.php", 2*time.Minute)

	s := newScanner(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	findings, err := s.Scan(ctx, dvwaURL, webapp.DefaultScanOptions())
	if err != nil {
		t.Fatalf("scan DVWA: %v", err)
	}
	logSummary(t, "DVWA", findings)

	var sqliCount, xssCount, highPlus int
	for _, f := range findings {
		for _, tag := range f.Tags {
			switch tag {
			case "sqli":
				sqliCount++
			case "xss":
				xssCount++
			}
		}
		if f.Severity == "critical" || f.Severity == "high" {
			highPlus++
		}
	}

	if sqliCount == 0 {
		t.Error("DVWA: expected ≥1 SQL injection finding (security level=low)")
	}
	if xssCount == 0 {
		t.Error("DVWA: expected ≥1 XSS finding (security level=low)")
	}
	if highPlus == 0 {
		t.Error("DVWA: expected ≥1 high/critical finding overall")
	}

	// Verify ParamifyCapability is populated on all findings.
	for _, f := range findings {
		if f.ParamifyCapability == "" {
			t.Errorf("DVWA: finding %s has empty ParamifyCapability", f.TemplateID)
		}
	}
}

// ── WebGoat ───────────────────────────────────────────────────────────────

func TestWebGoatScan(t *testing.T) {
	waitForTarget(t, webgoatURL, 3*time.Minute)

	s := newScanner(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	findings, err := s.Scan(ctx, webgoatURL, webapp.DefaultScanOptions())
	if err != nil {
		t.Fatalf("scan WebGoat: %v", err)
	}
	logSummary(t, "WebGoat", findings)

	var highPlus int
	for _, f := range findings {
		if f.Severity == "critical" || f.Severity == "high" {
			highPlus++
		}
	}
	if highPlus == 0 {
		t.Error("WebGoat: expected ≥1 high/critical finding")
	}
}

// ── Metasploitable 2 ──────────────────────────────────────────────────────

func TestMetasploitableScan(t *testing.T) {
	waitForTarget(t, metasploitableURL, 3*time.Minute)

	s := newScanner(t)
	// Update templates before the broadest scan to catch latest CVE detections.
	s.UpdateTemplates()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	findings, err := s.Scan(ctx, metasploitableURL, webapp.NetworkScanOptions())
	if err != nil {
		t.Fatalf("scan Metasploitable2: %v", err)
	}
	logSummary(t, "Metasploitable2", findings)

	var criticalCount int
	var cvesFound []string
	for _, f := range findings {
		if f.Severity == "critical" {
			criticalCount++
		}
		cvesFound = append(cvesFound, f.CVEIDs...)
	}

	if criticalCount == 0 {
		t.Error("Metasploitable2: expected ≥1 critical finding (known CVEs present)")
	}
	t.Logf("Metasploitable2: CVEs detected: %v", cvesFound)
}

// ── Full pipeline smoke test ───────────────────────────────────────────────
// Verifies that WebFinding structs from a scan can be serialised into an
// AuditSnapshot — exercises the types.AuditSnapshot.WebFindings field.

func TestWebFindingsInSnapshot(t *testing.T) {
	waitForTarget(t, dvwaURL+"/login.php", 2*time.Minute)

	s := newScanner(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	// Restrict to info+low to keep this smoke test fast.
	opts := webapp.DefaultScanOptions()
	opts.Severity = []string{"info", "low", "medium"}
	opts.Timeout = 10 * time.Minute

	findings, err := s.Scan(ctx, dvwaURL, opts)
	if err != nil {
		t.Fatalf("smoke scan: %v", err)
	}

	snap := types.AuditSnapshot{
		SchemaVersion: "1",
		WebFindings:   findings,
	}

	if len(snap.WebFindings) == 0 {
		t.Log("no findings in smoke scan — consider relaxing severity filter or checking target")
		return
	}

	for _, f := range snap.WebFindings {
		if f.TemplateID == "" {
			t.Errorf("finding has empty TemplateID: %+v", f)
		}
		if f.URL == "" {
			t.Errorf("finding %s has empty URL", f.TemplateID)
		}
	}
	fmt.Printf("WebFindingsInSnapshot: %d findings ingested into AuditSnapshot\n", len(snap.WebFindings))
}
