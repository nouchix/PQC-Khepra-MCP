package main

import (
	"bytes"
	"os"
	"testing"
)

// The embedded release manifest must match the repository's manifest.json.
// After regenerating manifest.json, copy it to cmd/khepra-mcp/release_manifest.json.
func TestReleaseManifestInSync(t *testing.T) {
	root, err := os.ReadFile("../../manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	norm := func(b []byte) []byte { return bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n")) }
	if !bytes.Equal(norm(root), norm(releaseManifestJSON)) {
		t.Fatal("cmd/khepra-mcp/release_manifest.json differs from manifest.json; copy it over")
	}
	if n := len(builtInToolSpecs()); n < 7 {
		t.Fatalf("embedded manifest yields %d tools", n)
	}
}
