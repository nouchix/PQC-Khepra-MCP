package mcp_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/nouchix/PQC-Khepra-MCP/pkg/adinkra"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/attestenvelope"
	khepramcp "github.com/nouchix/PQC-Khepra-MCP/pkg/mcp"
)

func testSpecs(names ...string) []khepramcp.ToolSpec {
	var specs []khepramcp.ToolSpec
	for _, n := range names {
		h := sha256.Sum256([]byte(n))
		specs = append(specs, khepramcp.ToolSpec{
			Name: n, Description: n, RiskClass: khepramcp.RiskReadOnly, Scope: "test:read",
			SchemaVersion: "1.0.0", SchemaHash: hex.EncodeToString(h[:]),
			AllowedBackend: "in-process", TimeoutMs: 1000, MaxPrivilege: "read-only",
			ArgsSchema: map[string]any{"type": "object", "properties": map[string]any{}},
		})
	}
	return specs
}

func writeManifest(t *testing.T, m *khepramcp.SignedToolManifest) string {
	t.Helper()
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadTrustedRegistry(t *testing.T) {
	ctx := context.Background()
	signer := attestenvelope.AdinkraSigner{}

	releasePub, releasePriv, err := adinkra.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}
	procPub, procPriv, err := adinkra.GenerateSigningKey()
	if err != nil {
		t.Fatal(err)
	}

	release, err := khepramcp.GenerateSignedManifest(testSpecs("file_a", "file_b", "file_c"), releasePriv, "release", signer)
	if err != nil {
		t.Fatal(err)
	}
	path := writeManifest(t, release)
	builtIn := testSpecs("builtin_a")

	prev := khepramcp.ReleaseManifestPublicKey
	t.Cleanup(func() { khepramcp.ReleaseManifestPublicKey = prev })

	// No pinned key: the file is ignored and the built-in specs load.
	khepramcp.ReleaseManifestPublicKey = ""
	reg, err := khepramcp.LoadTrustedRegistry(ctx, path, builtIn, procPriv, procPub, "proc", signer, t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	if reg.ToolCount() != 1 {
		t.Fatalf("unpinned build loaded %d tools, want the 1 built-in", reg.ToolCount())
	}

	// Pinned key: the signed release manifest loads.
	khepramcp.ReleaseManifestPublicKey = hex.EncodeToString(releasePub)
	reg, err = khepramcp.LoadTrustedRegistry(ctx, path, builtIn, procPriv, procPub, "proc", signer, t.Logf)
	if err != nil {
		t.Fatalf("signed release manifest rejected: %v", err)
	}
	if reg.ToolCount() != 3 {
		t.Fatalf("loaded %d tools, want 3", reg.ToolCount())
	}

	// A manifest with an extra tool added after signing is rejected.
	tampered := *release
	tampered.Tools = append(append([]khepramcp.ToolSpec{}, release.Tools...), testSpecs("injected")...)
	if _, err := khepramcp.LoadTrustedRegistry(ctx, writeManifest(t, &tampered), builtIn, procPriv, procPub, "proc", signer, t.Logf); err == nil {
		t.Fatal("tampered manifest accepted")
	}

	// A manifest signed by any other key is rejected.
	forged, err := khepramcp.GenerateSignedManifest(testSpecs("file_a"), procPriv, "proc", signer)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := khepramcp.LoadTrustedRegistry(ctx, writeManifest(t, forged), builtIn, procPriv, procPub, "proc", signer, t.Logf); err == nil {
		t.Fatal("manifest signed by a non-release key accepted")
	}

	// The built-in path verifies too: a wrong process public key fails.
	khepramcp.ReleaseManifestPublicKey = ""
	if _, err := khepramcp.LoadTrustedRegistry(ctx, "", builtIn, procPriv, releasePub, "proc", signer, t.Logf); err == nil {
		t.Fatal("built-in manifest verified against the wrong public key")
	}
}
