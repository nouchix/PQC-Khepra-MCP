// Package mcp — backward compatibility shim.
//
// This file re-exports legacy types and functions that existing consumers
// (pkg/apiserver, cmd/khepra-mcp, cmd/apiserver) still import from "pkg/mcp".
//
// These exist ONLY for backward compatibility and are NOT part of the new
// hardened MCP wrapper (types.go, manifest.go, router.go, server.go, executor.go).
//
// Consumer migration path:
//   1. Import "pkg/mcp/legacy" instead of "pkg/mcp"
//   2. Or update to use the new MCP types directly
//
// These shims will be removed once all consumers are migrated.
package legacy

import (
	"github.com/nouchix/PQC-Khepra-MCP/pkg/adinkra"
)

// ─── Re-exported Legacy Types (used by pkg/apiserver, cmd/khepra-mcp) ──────────

// NLProcessor is the legacy natural language processor.

// NLQuery is the legacy natural language query envelope.

// NLResponse is the legacy NL response envelope.

// ToolExecutor is the legacy tool executor interface (used by apiserver).

// ToolResult is the legacy tool result.

// ContentItem is the legacy content item for tool results.

// ToolHandler is the legacy tool handler function type.
// NOTE: The new handler interface is ToolHandlerIface (executor.go).

// Tool is the legacy tool definition format.

// ToolInvocation is the legacy tool invocation record.

// LLMProvider is the legacy LLM provider interface.

// Config is the legacy server configuration (used by cmd/khepra-mcp).

// AuditLogger is the legacy audit logger interface.

// Store is the legacy store interface.

// Request is the legacy JSON-RPC request type.

// Response is the legacy JSON-RPC response type.

// ─── Re-exported Legacy Functions ──────────────────────────────────────────────

// NewServer creates a legacy MCP server instance (used by cmd/khepra-mcp).
// Deprecated: Use NewHardenedServer() from server.go for the new implementation.

// KhepraTools returns the legacy tool definitions (used by cmd/khepra-mcp).
// Deprecated: Tools are now defined in signed manifests.

// NewNLProcessor creates a legacy NL processor (used by apiserver).


type AdinkraSigner struct{}

func (s AdinkraSigner) Sign(data []byte, privateKey []byte) ([]byte, error) {
	return adinkra.Sign(privateKey, data)
}

func (s AdinkraSigner) Verify(publicKey []byte, data []byte, signature []byte) (bool, error) {
	return adinkra.Verify(publicKey, data, signature)
}
