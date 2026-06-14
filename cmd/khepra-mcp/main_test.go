package main

import "testing"

// Smoke test — verifies the package compiles and the binary entrypoint
// is reachable without invoking main() (which would start a server).
func TestPackageCompiles(t *testing.T) {
	// The khepra-mcp command provides the PQC-secured MCP server.
	// Compilation coverage is sufficient; integration tests use the binary directly.
	t.Log("cmd/khepra-mcp: package compiles OK")
}
