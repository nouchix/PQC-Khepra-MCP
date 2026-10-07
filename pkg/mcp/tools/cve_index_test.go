package tools

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCVEIndex(t *testing.T) {
	dir := t.TempDir()
	write := func(rel, body string) {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("kev/known_exploited_vulnerabilities.json", `{"vulnerabilities":[{"cveID":"CVE-2021-44228","vendorProject":"Apache","product":"Log4j2","dateAdded":"2021-12-10","shortDescription":"Log4j2 JNDI","requiredAction":"Apply updates"}]}`)
	write("cve-data/mitre/cves/2021/44xxx/CVE-2021-44228.json", `{"cveMetadata":{"cveId":"CVE-2021-44228","state":"PUBLISHED"},"containers":{"cna":{"descriptions":[{"lang":"en","value":"Apache Log4j2 JNDI features do not protect against attacker controlled LDAP"}],"affected":[{"vendor":"Apache Software Foundation","product":"Apache Log4j2"}],"metrics":[{"cvssV3_1":{"baseScore":10.0,"baseSeverity":"CRITICAL"}}]}}}`)
	write("cve-data/mitre/cves/2003/0xxx/CVE-2003-0001.json", `{"cveMetadata":{"cveId":"CVE-2003-0001","state":"PUBLISHED"},"containers":{"cna":{"descriptions":[{"lang":"en","value":"NIC drivers do not pad frames"}]}}}`)
	write("cve-data/mitre/cves/2003/0xxx/CVE-2003-0002.json", `{"cveMetadata":{"cveId":"CVE-2003-0002","state":"REJECTED"},"containers":{"cna":{}}}`)
	write("cve-data/mitre/.github/workflows/package.json", `{"name":"not-a-cve"}`)

	idx := buildCVEIndex([]string{filepath.Join(dir, "missing"), dir})
	if len(idx.records) != 2 {
		t.Fatalf("want 2 records (rejected and non-CVE files skipped), got %d", len(idx.records))
	}
	hits := idx.search("cve-2021-44228", 50)
	if len(hits) != 1 || !hits[0].IsKEV || hits[0].CVSSScore != 10.0 || hits[0].Severity != "CRITICAL" || hits[0].Remediation == "" {
		t.Fatalf("KEV and CVE 5.x data not merged: %+v", hits)
	}
	if got := idx.search("log4j", 50); len(got) != 1 {
		t.Fatalf("substring search: %+v", got)
	}
	if got := idx.search("CVE-2003-0002", 50); len(got) != 0 {
		t.Fatal("rejected CVE returned")
	}
	d := idx.describe()
	if !strings.Contains(d, "2 records") || !strings.Contains(d, "2003–2021") || !strings.Contains(d, "1 CISA KEV") {
		t.Fatalf("describe: %s", d)
	}
	if empty := buildCVEIndex([]string{filepath.Join(dir, "missing")}); empty.describe() != "no offline CVE database installed" {
		t.Fatalf("empty describe: %s", empty.describe())
	}
}
