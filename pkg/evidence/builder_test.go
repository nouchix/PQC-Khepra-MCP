package evidence

import (
	"archive/zip"
	"encoding/hex"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/nouchix/PQC-Khepra-MCP/pkg/adinkra"
	"golang.org/x/crypto/sha3"
)

func readZip(t *testing.T, path string) map[string]string {
	t.Helper()
	zr, err := zip.OpenReader(path)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	out := map[string]string{}
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(rc)
		rc.Close()
		out[f.Name[strings.LastIndex(f.Name, "/")+1:]] = string(b)
	}
	return out
}

func testConfig(t *testing.T) BuildConfig {
	return BuildConfig{
		Findings: []Finding{{ID: "SC-13", Title: "FIPS crypto", Severity: "CAT I", SPRSPoints: 5,
			CMMCPractice: "CMMC.SC.L2-3.13.11", NIST: "3.13.11", CCI: "CCI-002450"}},
		DAGNodes:  []DAGNode{{Index: 0, Label: "genesis", Type: "genesis", Hash: "abc"}},
		Target:    "test-host",
		OutputDir: t.TempDir(),
	}
}

func TestBuildSignedPackage(t *testing.T) {
	pub, priv, err := adinkra.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	cfg := testConfig(t)
	cfg.PrivKey, cfg.PubKey = priv, pub
	pkg, err := Build(cfg)
	if err != nil {
		t.Fatal(err)
	}
	files := readZip(t, pkg.ZipPath)

	var m struct {
		Algorithm string `json:"algorithm"`
		Files     []struct {
			SHA256 string `json:"sha256"`
		} `json:"files"`
		Sig string `json:"manifest_signature"`
	}
	if err := json.Unmarshal([]byte(files["manifest.json"]), &m); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(m.Sig, "ML-DSA-87:") || !strings.Contains(m.Algorithm, "ML-DSA-87") {
		t.Fatalf("manifest not ML-DSA-87 signed: %q / %q", m.Algorithm, m.Sig)
	}
	sig, err := hex.DecodeString(strings.TrimPrefix(m.Sig, "ML-DSA-87:"))
	if err != nil {
		t.Fatal(err)
	}
	h := sha3.New256()
	for _, f := range m.Files {
		h.Write([]byte(f.SHA256))
	}
	if ok, err := adinkra.Verify(pub, h.Sum(nil), sig); err != nil || !ok {
		t.Fatalf("manifest signature does not verify: %v %v", ok, err)
	}

	for name, body := range files {
		if strings.Contains(body, "ML-DSA-65") {
			t.Errorf("%s still claims ML-DSA-65", name)
		}
	}
	if strings.Contains(files["10-personnel-training.md"], "CMMC Level 2 Awareness") {
		t.Error("training records were fabricated")
	}
	if strings.Contains(files["11-incident-response.md"], "Detection time") {
		t.Error("tabletop exercise was fabricated")
	}
	if strings.Contains(files["06-spd-flight-log.ndjson"], "OutcomeSuccess") {
		t.Error("synthesized flight frames claim success")
	}
}

func TestBuildUnsignedPackage(t *testing.T) {
	pkg, err := Build(testConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	files := readZip(t, pkg.ZipPath)
	if !strings.Contains(files["manifest.json"], "UNSIGNED") {
		t.Error("unsigned manifest does not say UNSIGNED")
	}
	if strings.Contains(files["00-README.md"], "ML-DSA-87:") {
		t.Error("unsigned package shows a signature")
	}
}
