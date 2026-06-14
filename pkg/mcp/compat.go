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
package mcp

import (
	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/mcp/legacy"
)

// ─── Re-exported Legacy Types (used by pkg/apiserver, cmd/khepra-mcp) ──────────

// NLProcessor is the legacy natural language processor.
type NLProcessor = legacy.NLProcessor

// NLQuery is the legacy natural language query envelope.
type NLQuery = legacy.NLQuery

// NLResponse is the legacy NL response envelope.
type NLResponse = legacy.NLResponse

// ToolExecutor is the legacy tool executor interface (used by apiserver).
type ToolExecutor = legacy.ToolExecutor

// ToolResult is the legacy tool result.
type ToolResult = legacy.ToolResult

// ContentItem is the legacy content item for tool results.
type ContentItem = legacy.ContentItem

// ToolHandler is the legacy tool handler function type.
// NOTE: The new handler interface is ToolHandlerIface (executor.go).
type ToolHandler = legacy.ToolHandler

// Tool is the legacy tool definition format.
type Tool = legacy.Tool

// ToolInvocation is the legacy tool invocation record.
type ToolInvocation = legacy.ToolInvocation

// LLMProvider is the legacy LLM provider interface.
type LLMProvider = legacy.LLMProvider

// Config is the legacy server configuration (used by cmd/khepra-mcp).
type Config = legacy.Config

// AuditLogger is the legacy audit logger interface.
type AuditLogger = legacy.AuditLogger

// Store is the legacy store interface.
type Store = legacy.Store

// Request is the legacy JSON-RPC request type.
type Request = legacy.Request

// Response is the legacy JSON-RPC response type.
type Response = legacy.Response

// ─── Re-exported Legacy Functions ──────────────────────────────────────────────

// NewServer creates a legacy MCP server instance (used by cmd/khepra-mcp).
// Deprecated: Use NewHardenedServer() from server.go for the new implementation.
var NewServer = legacy.NewServer

// KhepraTools returns the legacy tool definitions (used by cmd/khepra-mcp).
// Deprecated: Tools are now defined in signed manifests.
var KhepraTools = legacy.KhepraTools

// NewNLProcessor creates a legacy NL processor (used by apiserver).
var NewNLProcessor = legacy.NewNLProcessor
