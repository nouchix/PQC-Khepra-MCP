package ironbank

import (
	"testing"
)

// ─── NewClient ──────────────────────────────────────────────────────────────

func TestNewClient_MissingEnvVars(t *testing.T) {
	// Clear env vars (test isolation)
	t.Setenv("IRONBANK_USERNAME", "")
	t.Setenv("IRONBANK_CLI_SECRET", "")

	_, err := NewClient()
	if err == nil {
		t.Fatal("expected error when env vars are not set")
	}
}

func TestNewClientWithCredentials_EmptyFields(t *testing.T) {
	_, err := NewClientWithCredentials("", "secret")
	if err == nil {
		t.Error("expected error for empty username")
	}
	_, err = NewClientWithCredentials("user", "")
	if err == nil {
		t.Error("expected error for empty secret")
	}
	_, err = NewClientWithCredentials("", "")
	if err == nil {
		t.Error("expected error for both empty")
	}
}

// ─── parseTargetURI ─────────────────────────────────────────────────────────

func TestParseTargetURI_TagForm(t *testing.T) {
	project, repo, ref, err := parseTargetURI("ironbank/redhat/ubi/ubi8:8.7")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if project != "ironbank" {
		t.Errorf("expected project=ironbank, got %s", project)
	}
	if repo != "redhat/ubi/ubi8" {
		t.Errorf("expected repo=redhat/ubi/ubi8, got %s", repo)
	}
	if ref != "8.7" {
		t.Errorf("expected ref=8.7, got %s", ref)
	}
}

func TestParseTargetURI_DigestForm(t *testing.T) {
	digest := "sha256:abc123def456"
	uri := "myproject/myrepo@" + digest
	project, repo, ref, err := parseTargetURI(uri)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if project != "myproject" {
		t.Errorf("expected project=myproject, got %s", project)
	}
	if repo != "myrepo" {
		t.Errorf("expected repo=myrepo, got %s", repo)
	}
	if ref != digest {
		t.Errorf("expected ref=%s, got %s", digest, ref)
	}
}

func TestParseTargetURI_NoTag_DefaultsToLatest(t *testing.T) {
	_, _, ref, err := parseTargetURI("myproject/myrepo")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ref != "latest" {
		t.Errorf("expected ref=latest, got %s", ref)
	}
}

func TestParseTargetURI_RegistryPrefix(t *testing.T) {
	// Strip registry prefix
	project, repo, ref, err := parseTargetURI("registry1.dso.mil/ironbank/redhat/ubi/ubi8:8.7")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if project != "ironbank" {
		t.Errorf("expected project=ironbank, got %s", project)
	}
	if repo != "redhat/ubi/ubi8" {
		t.Errorf("expected repo=redhat/ubi/ubi8, got %s", repo)
	}
	if ref != "8.7" {
		t.Errorf("expected ref=8.7, got %s", ref)
	}
}

func TestParseTargetURI_Empty(t *testing.T) {
	_, _, _, err := parseTargetURI("")
	if err == nil {
		t.Error("expected error for empty URI")
	}
}

func TestParseTargetURI_NoSlash(t *testing.T) {
	_, _, _, err := parseTargetURI("singletoken")
	if err == nil {
		t.Error("expected error for URI with no project/repo separator")
	}
}

// ─── ScanOverview ───────────────────────────────────────────────────────────

func TestScanOverviewZeroValue(t *testing.T) {
	var s ScanOverview
	if s.ScanStatus != "" || s.Total != 0 || s.Critical != 0 {
		t.Error("zero-value ScanOverview should have empty fields")
	}
}

// ─── HarborAPIBase ──────────────────────────────────────────────────────────

func TestHarborAPIBase(t *testing.T) {
	if HarborAPIBase == "" {
		t.Error("HarborAPIBase must not be empty")
	}
	// Should point at registry1.dso.mil
	if len(HarborAPIBase) < 10 {
		t.Errorf("HarborAPIBase looks too short: %s", HarborAPIBase)
	}
}
