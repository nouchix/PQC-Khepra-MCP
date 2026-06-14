package mcp

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

	"golang.org/x/crypto/sha3"

	licpkg "github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/license"
)

// ─── Security Boundary Interfaces ──────────────────────────────────────────────
//
// These interfaces are implemented by the existing Mitochondrial/Polymorphic/DEMARC
// stack. The MCP wrapper does NOT create new auth logic — it wires into these.

// DemarcGateway authenticates callers using PQC credentials and enforces
// network-level access control (CIDR allowlisting).
// Production impl: pkg/acp.AgentControlPlane (credential validation)
type DemarcGateway interface {
	// Authenticate resolves a credential (ZeroTrustToken, API key, etc.) into an Identity.
	Authenticate(ctx context.Context, cred any) (Identity, error)
	// CheckCIDR validates that the caller's remote address is within the allowed range.
	// For stdio transport, remoteAddr is "local" and always passes.
	CheckCIDR(ctx context.Context, id Identity, remoteAddr string) error
}

// PolymorphicEngine wraps and verifies requests/responses with provenance envelopes.
// Production impl: pkg/gateway or pkg/polymorphic (SecureEnvelope lifecycle)
type PolymorphicEngine interface {
	// WrapRequest seals the raw request payload with agent provenance metadata.
	WrapRequest(payload []byte, agentID string) ([]byte, error)
	// VerifyRequest validates a wrapped request's integrity and provenance.
	VerifyRequest(wrapped []byte) error
	// WrapResponse seals a tool result in a SecureEnvelope with PQC signature.
	WrapResponse(result any, requestID string) (SecureEnvelope, error)
	// VerifyResponse validates a SecureEnvelope's integrity.
	VerifyResponse(envelope SecureEnvelope) error
}

// MCPGateway enforces RBAC scope checks and scans for prompt injection in tool arguments.
type MCPGateway interface {
	// CheckPermission validates that the identity has the required scope for the tool.
	CheckPermission(id Identity, scope string) error
	// ScanForInjection checks raw input text for prompt injection patterns.
	ScanForInjection(text string) error
}

// Attestor records tool executions in the DAG audit chain with PQC signatures.
// Production impl: wrapper over pkg/dag.Store + pkg/adinkra.Sign
type Attestor interface {
	// Append records a tool execution in the DAG and returns the attestation node ID.
	Append(ctx context.Context, toolName string, input []byte, output []byte) (string, error)
	// SignEnvelope adds a PQC signature to the SecureEnvelope using the attestation key.
	SignEnvelope(ctx context.Context, env SecureEnvelope) (SecureEnvelope, error)
}

// ToolDispatcher dispatches tool calls according to their risk classification.
type ToolDispatcher interface {
	Execute(ctx context.Context, spec ToolSpec, call MCPToolCall) (any, []string, error)
}

// ─── Router (AD-010: The Orchestrator) ─────────────────────────────────────────
//
// The Router is the single admission control chain. The protocol NEVER reaches
// execution before identity and policy are fully resolved.
//
// Chain order (MUST NOT be reordered):
//   1. DEMARC boundary (authenticate + CIDR check)
//   2. Manifest lookup + schema pin validation
//   3. Polymorphic wrap + verify (provenance)
//   4. MCPGateway policy (RBAC + injection scan)
//   5. Risk-classified execution
//   6. Attestation + PQC seal

// Router orchestrates the full security chain for every tool call.
type Router struct {
	demarc   DemarcGateway
	poly     PolymorphicEngine
	gateway  MCPGateway
	registry *ManifestRegistry
	exec     ToolDispatcher
	attest   Attestor
	logger   *log.Logger

	// Production hardening
	events      *EventEmitter       // Structured observability
	mistakes    *MistakeTracker     // Mistake / loop detection
	limiter     *RateLimiter        // Per-agent rate limiting
	concurrency *ConcurrencyLimiter // Per-agent concurrent call cap (NSA prompt-storm defense)
	// invocationRootKey is derived from the ML-DSA-65 license key and used
	// to issue + verify per-invocation HMAC tokens (ASD/CISA ephemeral credentials).
	// If nil, invocation token issuance is skipped (stdio dev mode).
	invocationRootKey []byte
	// license is the parsed KhepraLicense for this server instance.
	// Controls tool gating at Step 1.6b. nil = Community tier.
	license *licpkg.KhepraLicense
	// callLog is the in-memory ring buffer capturing every tool call.
	// Enables T02/T08 scanner checks and SOW pilot metrics.
	callLog *CallLog
}

// RouterConfig holds all dependencies for constructing a Router.
type RouterConfig struct {
	Demarc   DemarcGateway
	Poly     PolymorphicEngine
	Gateway  MCPGateway
	Registry *ManifestRegistry
	Executor ToolDispatcher
	Attestor Attestor
	Logger   *log.Logger

	// Production hardening (optional — sensible defaults applied)
	Events        *EventEmitter
	MistakeConfig MistakeTrackerConfig
	RateWindow    int64 // Rate limit window in ms (default: 60000)
	RateMax       int   // Max requests per window (default: 100)
	MaxConcurrent int   // Max concurrent tool calls per agent (default: 5)

	// Tamper-evident audit log (DFARS 252.204-7012 compliance).
	// When set, every MCPEvent is signed and appended to the NDJSON log chain.
	SignedAuditLog *SignedAuditLog

	// InvocationRootKey is the HMAC root key for per-invocation token issuance.
	// Derive from ML-DSA-65 license key using DeriveRootKey().
	// If nil, invocation token issuance is skipped (stdio dev mode).
	InvocationRootKey []byte

	// License is the parsed and verified license claim for this server instance.
	// Obtained via license.ParseMCPLicense() from KHEPRA_LICENSE_KEY env var.
	// If nil, Community tier is enforced (ert_scan basic + nist_map 25 controls).
	License *licpkg.KhepraLicense

	// CallLogCapacity is the ring buffer size for tool call records.
	// Default: 512. Increase for high-throughput deployments.
	// Set to -1 to disable call logging (not recommended for DFARS environments).
	CallLogCapacity int
}

// NewRouter creates a Router with all security chain components.
// All components are required — missing dependencies cause a fail-closed error.
func NewRouter(cfg RouterConfig) (*Router, error) {
	if cfg.Demarc == nil {
		return nil, errors.New("mcp/router: DemarcGateway is required")
	}
	if cfg.Poly == nil {
		return nil, errors.New("mcp/router: PolymorphicEngine is required")
	}
	if cfg.Gateway == nil {
		return nil, errors.New("mcp/router: MCPGateway is required")
	}
	if cfg.Registry == nil {
		return nil, errors.New("mcp/router: ManifestRegistry is required")
	}
	if cfg.Executor == nil {
		return nil, errors.New("mcp/router: ToolDispatcher is required")
	}
	if cfg.Attestor == nil {
		return nil, errors.New("mcp/router: Attestor is required")
	}
	logger := cfg.Logger
	if logger == nil {
		logger = log.Default()
	}

	// Initialize observability emitter
	events := cfg.Events
	if events == nil {
		events = NewEventEmitter(EventEmitterConfig{
			Logger:    logger,
			SignedLog: cfg.SignedAuditLog,
		})
	} else if cfg.SignedAuditLog != nil && events.SignedLog == nil {
		// Caller supplied an emitter but also wants signed logging
		events.SignedLog = cfg.SignedAuditLog
	}

	// Initialize mistake tracker
	mistakes := NewMistakeTracker(cfg.MistakeConfig)

	// Initialize rate limiter
	rateWindow := cfg.RateWindow
	if rateWindow <= 0 {
		rateWindow = 60000 // 1 minute default
	}
	rateMax := cfg.RateMax
	if rateMax <= 0 {
		rateMax = 100 // 100 requests per minute default
	}
	limiter := NewRateLimiter(rateWindow, rateMax)

	events.Emit(MCPEvent{Type: EventStartup, Success: true, Metadata: map[string]any{
		"tools":     cfg.Registry.ToolCount(),
		"version":   cfg.Registry.Version(),
		"rate_limit": fmt.Sprintf("%d/%dms", rateMax, rateWindow),
	}})

	return &Router{
		demarc:            cfg.Demarc,
		poly:              cfg.Poly,
		gateway:           cfg.Gateway,
		registry:          cfg.Registry,
		exec:              cfg.Executor,
		attest:            cfg.Attestor,
		logger:            logger,
		events:            events,
		mistakes:          mistakes,
		limiter:           limiter,
		concurrency:       NewConcurrencyLimiter(cfg.MaxConcurrent),
		invocationRootKey: cfg.InvocationRootKey,
		license:           cfg.License,
		callLog:           NewCallLog(cfg.CallLogCapacity),
	}, nil
}

// CallLog returns the router's in-memory call log for metric queries and T02/T08 scanning.
func (r *Router) CallLog() *CallLog { return r.callLog }

// HandleToolCall processes a single tool invocation through the full security chain.
//
// Chain:
//   DEMARC → Validate → Manifest → Polymorphic → MCPGateway → Executor → Attestation → Response
//
// Returns a fully sealed MCPToolResponse or a typed error.
func (r *Router) HandleToolCall(ctx context.Context, call MCPToolCall, cred any, remoteAddr string) (*MCPToolResponse, error) {
	start := time.Now()

	// ── Step 1: DEMARC Boundary ─────────────────────────────────────────────
	id, err := r.demarc.Authenticate(ctx, cred)
	if err != nil {
		r.events.EmitError(EventAuth, call.ToolName, "", "AUTH_FAILED", err.Error())
		r.logger.Printf("[MCP:DEMARC] auth failed for tool=%s: %v", call.ToolName, err)
		return nil, fmt.Errorf("authentication failed: %w", err)
	}
	if err := r.demarc.CheckCIDR(ctx, id, remoteAddr); err != nil {
		r.events.EmitError(EventAuth, call.ToolName, id.AgentID, "CIDR_DENIED", err.Error())
		r.logger.Printf("[MCP:DEMARC] CIDR denied for agent=%s addr=%s: %v", id.AgentID, remoteAddr, err)
		return nil, fmt.Errorf("CIDR check failed: %w", err)
	}

	// Attach identity to the call for downstream use.
	call.Identity = id

	// ── Step 1.5: Rate Limiting ─────────────────────────────────────────────
	if rlErr := r.limiter.Allow(id.AgentID); rlErr != nil {
		r.events.EmitError(EventRateLimit, call.ToolName, id.AgentID, rlErr.Code, rlErr.Message)
		r.logger.Printf("[MCP:RATE] rate limit for agent=%s: %s", id.AgentID, rlErr.Message)
		return &MCPToolResponse{
			IsError:      true,
			ErrorMessage: rlErr.Message,
		}, nil
	}

	// ── Step 1.6: Input Validation ──────────────────────────────────────────
	if valErr := ValidateToolArgs(call.Args); valErr != nil {
		r.events.EmitError(EventPolicy, call.ToolName, id.AgentID, valErr.Code, valErr.Message)
		r.logger.Printf("[MCP:VALIDATE] blocked: tool=%s agent=%s: %s", call.ToolName, id.AgentID, valErr.Error())
		return &MCPToolResponse{
			IsError:      true,
			ErrorMessage: valErr.Error(),
		}, nil
	}

	// ── Step 1.6a: Scope Taxonomy Allow-List (NSA parameter injection defense) ─
	if scopeErr := ValidateScopedToolArgs(call.Args, call.ToolName); scopeErr != nil {
		r.events.EmitError(EventPolicy, call.ToolName, id.AgentID, scopeErr.Code, scopeErr.Message)
		r.logger.Printf("[MCP:SCOPE] blocked: tool=%s agent=%s: %s", call.ToolName, id.AgentID, scopeErr.Error())
		return &MCPToolResponse{
			IsError:      true,
			ErrorMessage: scopeErr.Error(),
		}, nil
	}

	// ── Step 1.6b: License Tier Gate ───────────────────────────────────────
	// Check that the caller's license tier permits the requested tool.
	// Community tier: ert_scan (basic) + nist_map (limited) only.
	// Enterprise+:    all 13 tools.
	// Non-fatal for Community callers hitting Community tools.
	if tierErr := licpkg.CheckToolAccess(r.license, call.ToolName); tierErr != nil {
		r.events.EmitError(EventPolicy, call.ToolName, id.AgentID, "LICENSE_TIER", tierErr.Error())
		r.logger.Printf("[MCP:LICENSE] tier gate: tool=%s agent=%s: %s", call.ToolName, id.AgentID, tierErr.Error())
		return &MCPToolResponse{
			IsError:      true,
			ErrorMessage: tierErr.Error(),
		}, nil
	}

	// ── Step 1.7: Loop / Mistake Detection ──────────────────────────────────
	argsFingerprint := fmt.Sprintf("%v", call.Args) // crude but effective
	if loopErr := r.mistakes.CheckLoop(id.AgentID, call.ToolName, argsFingerprint); loopErr != nil {
		r.events.EmitError(EventLoopDetected, call.ToolName, id.AgentID, loopErr.Code, loopErr.Message)
		r.logger.Printf("[MCP:LOOP] detected: tool=%s agent=%s: %s", call.ToolName, id.AgentID, loopErr.Message)
		return &MCPToolResponse{
			IsError:      true,
			ErrorMessage: loopErr.Message,
		}, nil
	}

	// ── Step 1.8: Per-Invocation Ephemeral Credential (ASD/CISA requirement) ─
	if len(r.invocationRootKey) > 0 {
		// Extract scan profile and target from args for token binding
		profile, _ := call.Args["profile"].(string)
		if profile == "" {
			profile, _ = call.Args["framework"].(string)
		}
		target, _ := call.Args["target"].(string)
		tok, tokErr := IssueInvocationToken(r.invocationRootKey, id.AgentID, call.ToolName, profile, target)
		if tokErr != nil {
			r.events.EmitError(EventAuth, call.ToolName, id.AgentID, "INVOCATION_TOKEN_FAILED", tokErr.Error())
			return nil, fmt.Errorf("invocation token issuance failed: %w", tokErr)
		}
		call.InvocationToken = tok
		r.logger.Printf("[MCP:TOKEN] issued invocation token=%s tool=%s agent=%s ttl=5m",
			tok.TokenID, call.ToolName, id.AgentID)
	}

	// ── Step 2: Manifest Lookup + Schema Pin Validation ────────────────────
	spec, ok := r.registry.GetTool(call.ToolName)
	if !ok {
		r.events.EmitError(EventManifest, call.ToolName, id.AgentID, "UNKNOWN_TOOL", "not in manifest")
		r.logger.Printf("[MCP:MANIFEST] unknown tool: %s (agent=%s)", call.ToolName, id.AgentID)
		return nil, fmt.Errorf("unknown tool: %s", call.ToolName)
	}
	if err := r.registry.ValidatePinnedSchema(spec.Name, spec.SchemaVersion, spec.SchemaHash); err != nil {
		r.events.EmitError(EventManifest, call.ToolName, id.AgentID, "SCHEMA_PIN", err.Error())
		r.logger.Printf("[MCP:MANIFEST] schema pin violation: %v", err)
		return nil, fmt.Errorf("schema pin violation: %w", err)
	}

	// ── Step 3: Polymorphic Wrap + Verify (Provenance) ─────────────────────
	rawPayload := call.RawPayload
	if rawPayload == nil {
		rawPayload, _ = json.Marshal(call.Args)
	}
	wrapped, err := r.poly.WrapRequest(rawPayload, id.AgentID)
	if err != nil {
		r.events.EmitError(EventPoly, call.ToolName, id.AgentID, "WRAP_FAILED", err.Error())
		r.logger.Printf("[MCP:POLY] wrap request failed: %v", err)
		return nil, fmt.Errorf("polymorphic wrap failed: %w", err)
	}
	if err := r.poly.VerifyRequest(wrapped); err != nil {
		r.events.EmitError(EventPoly, call.ToolName, id.AgentID, "VERIFY_FAILED", err.Error())
		r.logger.Printf("[MCP:POLY] verify request failed: %v", err)
		return nil, fmt.Errorf("polymorphic verify failed: %w", err)
	}

	// ── Step 4: MCPGateway Policy (RBAC + Injection Scan) ──────────────────
	if err := r.gateway.CheckPermission(id, spec.Scope); err != nil {
		r.events.EmitError(EventPolicy, call.ToolName, id.AgentID, "PERMISSION_DENIED", err.Error())
		r.logger.Printf("[MCP:POLICY] permission denied: agent=%s scope=%s: %v", id.AgentID, spec.Scope, err)
		return nil, fmt.Errorf("permission denied: %w", err)
	}
	if err := r.gateway.ScanForInjection(string(rawPayload)); err != nil {
		r.events.EmitError(EventPolicy, call.ToolName, id.AgentID, "INJECTION", err.Error())
		r.logger.Printf("[MCP:POLICY] injection detected: agent=%s tool=%s: %v", id.AgentID, call.ToolName, err)
		return nil, fmt.Errorf("injection detected: %w", err)
	}

	// ── Step 5: Risk-Classified Execution (with Concurrency Gate) ──────────
	// Acquire concurrency slot (NSA prompt-storm defense)
	if concErr := r.concurrency.Acquire(id.AgentID); concErr != nil {
		r.events.EmitError(EventRateLimit, call.ToolName, id.AgentID, concErr.Code, concErr.Message)
		r.logger.Printf("[MCP:CONCURRENCY] %s", concErr.Message)
		return &MCPToolResponse{
			IsError:      true,
			ErrorMessage: concErr.Message,
		}, nil
	}
	defer r.concurrency.Release(id.AgentID)

	r.events.EmitToolStart(call.ToolName, id.AgentID, call.RequestID, string(spec.RiskClass))

	result, warnings, execErr := r.exec.Execute(ctx, spec, call)
	durationMs := time.Since(start).Milliseconds()

	if execErr != nil {
		// Record mistake for loop/mistake detection
		if mistakeErr := r.mistakes.RecordError(id.AgentID); mistakeErr != nil {
			r.events.EmitError(EventError, call.ToolName, id.AgentID, mistakeErr.Code, mistakeErr.Message)
			r.logger.Printf("[MCP:MISTAKE] %s", mistakeErr.Message)
			return &MCPToolResponse{
				IsError:      true,
				ErrorMessage: mistakeErr.Message,
			}, nil
		}

		r.events.EmitToolEnd(call.ToolName, id.AgentID, call.RequestID, durationMs, false, "EXEC_ERROR", execErr.Error())
		r.logger.Printf("[MCP:EXEC] tool=%s failed: %v (duration=%v)", call.ToolName, execErr, time.Since(start))
		return &MCPToolResponse{
			IsError:      true,
			ErrorMessage: execErr.Error(),
			Warnings:     warnings,
		}, nil
	}

	// Reset mistake counter on success
	r.mistakes.RecordSuccess(id.AgentID)

	// ── Step 5.5: Output Pipeline Filtering (NSA CSI MCP mandate) ───────────
	// NSA MCP Security Design Considerations p.12-13:
	// "Outputs from tools and models should never be treated as implicitly trusted,
	// even if they originate from previously vetted components. Each output must be
	// treated as untrusted input to the next phase of the pipeline."
	//
	// We serialize the result and run it through the same injection scanner used
	// for inbound args. Non-fatal (warning-only): compliant security reports
	// legitimately contain CVE IDs, exploit code snippets, and other patterns
	// that superficially resemble injection — we warn but do not block.
	if outputBytes, marshalOK := json.Marshal(result); marshalOK == nil {
		if outErr := r.gateway.ScanForInjection(string(outputBytes)); outErr != nil {
			// Non-fatal: log and warn — security report outputs may contain
			// CVE IDs or exploit patterns that match injection heuristics.
			r.logger.Printf("[MCP:OUTPUT-FILTER] tool=%s potential injection pattern in output: %v (non-fatal)",
				call.ToolName, outErr)
			warnings = append(warnings, "output-filter: potential injection pattern in tool output — review before piping to next agent")
			r.events.Emit(MCPEvent{
				Type:    EventPolicy,
				Success: false,
				Metadata: map[string]any{
					"step":    "output_filter",
					"tool":    call.ToolName,
					"agent":   id.AgentID,
					"finding": outErr.Error(),
				},
			})
		}
	}



	// ── Step 6: Attestation + PQC Seal ─────────────────────────────────────
	// Wrap result in SecureEnvelope.
	env, err := r.poly.WrapResponse(result, call.RequestID)
	if err != nil {
		r.events.EmitError(EventAttest, call.ToolName, id.AgentID, "WRAP_RESP_FAILED", err.Error())
		r.logger.Printf("[MCP:POLY] wrap response failed: %v", err)
		return nil, fmt.Errorf("response wrapping failed: %w", err)
	}

	// Record in DAG.
	outputBytes, _ := json.Marshal(result)
	attestationID, err := r.attest.Append(ctx, spec.Name, rawPayload, outputBytes)
	if err != nil {
		r.events.EmitError(EventAttest, call.ToolName, id.AgentID, "DAG_APPEND_FAILED", err.Error())
		r.logger.Printf("[MCP:ATTEST] DAG append failed: %v", err)
		return nil, fmt.Errorf("attestation failed: %w", err)
	}
	env.AttestationID = attestationID

	// PQC-sign the envelope.
	signedEnv, err := r.attest.SignEnvelope(ctx, env)
	if err != nil {
		r.events.EmitError(EventAttest, call.ToolName, id.AgentID, "SIGN_FAILED", err.Error())
		r.logger.Printf("[MCP:ATTEST] envelope signing failed: %v", err)
		return nil, fmt.Errorf("envelope signing failed: %w", err)
	}

	r.events.EmitToolEnd(call.ToolName, id.AgentID, call.RequestID, durationMs, true, "", "")
	r.logger.Printf("[MCP:OK] tool=%s agent=%s attestation=%s duration=%v",
		call.ToolName, id.AgentID, attestationID, time.Since(start))

	// ── CallLog: record for T02/T08 scanning + SOW pilot metrics ────────────
	r.callLog.Push(MCPCallRecord{
		ToolName:   spec.Name,
		CallerID:   id.AgentID,
		SessionID:  id.SessionID,
		Scope:      spec.Scope,
		RiskClass:  spec.RiskClass,
		Timestamp:  start,
		DurationMs: durationMs,
		IsSigned:   signedEnv.Signature != "",
		IsError:    false,
		ParamsLen:  len(rawPayload),
		DAGNodeID:  attestationID,
	})

	resp := &MCPToolResponse{
		Envelope: signedEnv,
		Warnings: warnings,
	}

	// ── Step 6.5: Wire-Level _khepra_sig (NSA message integrity) ────────────
	// Compute SHA3-256 of the response JSON (excluding _khepra_sig itself)
	// and sign with the attestation key. Any client can verify this field
	// without parsing the nested SecureEnvelope structure.
	if len(r.invocationRootKey) > 0 {
		respBody, marshalErr := json.Marshal(resp)
		if marshalErr == nil {
			digest := sha3digestRouter(respBody)
			// Re-use the HMAC root key for the wire-level signature (lightweight)
			import_hmac := hmacSHA256(r.invocationRootKey, digest)
			resp.KhepraSign = hex.EncodeToString(import_hmac)
		}
	}

	return resp, nil
}

// ListTools returns MCP-formatted tool definitions from the registry.
//
// IMPORTANT: The MCP spec mandates that every tool entry includes an
// "inputSchema" field (JSON Schema object). Omitting it causes clients
// (Claude, Cursor, Windsurf) to silently hide the tool from the UI.
// We always emit at least a minimal no-argument schema.
func (r *Router) ListTools() []map[string]any {
	// Minimal JSON Schema for tools that accept no arguments.
	noArgSchema := map[string]any{
		"type":       "object",
		"properties": map[string]any{},
	}

	specs := r.registry.ListTools()
	tools := make([]map[string]any, 0, len(specs))
	for _, s := range specs {
		schema := s.ArgsSchema
		if schema == nil {
			schema = noArgSchema
		}
		tool := map[string]any{
			"name":        s.Name,
			"description": s.Description,
			"inputSchema": schema,
		}
		tools = append(tools, tool)
	}
	return tools
}

// Events returns the event emitter for external access (e.g. telemetry hooks).
func (r *Router) Events() *EventEmitter {
	return r.events
}

// ─── Router-local crypto helpers ──────────────────────────────────────────────

// sha3digestRouter returns the SHA3-256 hash of data.
// Private to router to avoid import cycle with signed_audit_log.go's sha3digest.
func sha3digestRouter(data []byte) []byte {
	h := sha3.New256()
	h.Write(data)
	return h.Sum(nil)
}

// hmacSHA256 computes HMAC-SHA256(key, data).
func hmacSHA256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

// hexEncode is hex.EncodeToString aliased for clarity.
// Avoids unused import warnings in files that import encoding/hex only via this path.
var _ = hex.EncodeToString // suppress unused import
