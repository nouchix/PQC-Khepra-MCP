package main

import (
	_ "embed"
	"encoding/json"

	khepramcp "github.com/nouchix/PQC-Khepra-MCP/pkg/mcp"
)

// releaseManifestJSON is the release tool manifest compiled into the binary,
// so the full tool set ships with the same integrity as the binary itself. It
// is a copy of the repository's manifest.json; TestReleaseManifestInSync
// keeps the two identical.
//
//go:embed release_manifest.json
var releaseManifestJSON []byte

// builtInToolSpecs returns the tool specs compiled into the binary, falling
// back to the minimal defaults if the embedded manifest cannot be parsed.
func builtInToolSpecs() []khepramcp.ToolSpec {
	var m khepramcp.SignedToolManifest
	if err := json.Unmarshal(releaseManifestJSON, &m); err != nil || len(m.Tools) == 0 {
		return defaultToolSpecs(nil)
	}
	return m.Tools
}
