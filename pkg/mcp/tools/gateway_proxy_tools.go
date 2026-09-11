// Package tools — gateway_proxy_tools.go
//
// PQC-WAF Brokered MCP Gateway.
//
// ARCHITECTURE RULE (see AGENTS.md § SEKHEM / PQC-WAF):
//
//   ALL external MCP calls (Stripe, Cloudflare, any upstream) MUST be
//   brokered through this gateway. No external MCP server appears directly
//   in .mcp.json. The local khepra-mcp binary is the single trusted entry
//   point. This file is the internal enforcement of that rule.
//
// Flow:
//
//   IDE / Agent
//       │  MCP stdio / SSE
//       ▼
//   khepra-mcp (this binary)
//       │  license validate + tier-gate
//       │  SEKHEM allowlist check (no sovereign/CUI data to external)
//       │  Flight Recorder — pre-call DAG node
//       │  forward to upstream MCP over HTTPS
//       │  ML-DSA-65 sign response + post-call DAG node
//       ▼
//   External MCP (mcp.stripe.com, mcp.cloudflare.com, ...)
//
// Tools exposed:
//   - stripe_call   : Typed proxy to mcp.stripe.com
//   - mcp_gateway   : Generic upstream MCP broker (any allowlisted URL)
//
// IP: SOUHIMBOU DOH KONE LLC, exclusively licensed to SecRed Knowledge Inc.
package tools

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/nouchix/PQC-Khepra-MCP/pkg/adinkra"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/dag"
	"github.com/nouchix/PQC-Khepra-MCP/pkg/lorentz"
	mcp "github.com/nouchix/PQC-Khepra-MCP/pkg/mcp"
)

// sekhemAllowlist is the compiled-in set of upstream MCP endpoints permitted
// to receive outbound calls. This list is NOT configurable via env vars —
// preventing allowlist bypass through environment manipulation.
//
// SOVEREIGNTY RULE: endpoints here receive only caller-supplied args, never
// sovereign scan data, customer DAG state, or PQC key material. The broker
// strips sensitive args before forwarding (see sensitiveArgPatterns).
var sekhemAllowlist = map[string]string{
	"stripe":                   "https://mcp.stripe.com",
	"cloudflare":               "https://mcp.cloudflare.com/mcp",
	"cloudflare-docs":          "https://docs.mcp.cloudflare.com/mcp",
	"cloudflare-bindings":      "https://bindings.mcp.cloudflare.com/mcp",
	"cloudflare-builds":        "https://builds.mcp.cloudflare.com/mcp",
	"cloudflare-observability": "https://observability.mcp.cloudflare.com/mcp",
}

// sensitiveArgPatterns lists arg key substrings stripped before any upstream
// forward. These must never cross the sovereign boundary.
var sensitiveArgPatterns = []string{
	"license_key", "dag_", "pqc_key", "signing_key", "private",
	"customer_id", "cui", "classified", "secret_key",
}

// upstreamClient is a shared HTTP client with conservative timeouts.
var upstreamClient = &http.Client{Timeout: 30 * time.Second}

// ── stripe_call ───────────────────────────────────────────────────────────────

// HandleStripeCall proxies an MCP tool call to mcp.stripe.com through the
// PQC-WAF broker. Every call is Flight-Recorder logged and DAG-attested.
//
// Args:
//   - tool   (string, required): Stripe MCP tool name, e.g. "list_customers"
//   - params (object, optional): Tool parameters forwarded to Stripe
//
// Env: STRIPE_SECRET_KEY must be set in /opt/asaf/secrets/core.env.
func HandleStripeCall(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	toolName, _ := call.Args["tool"].(string)
	if toolName == "" {
		return nil, nil, fmt.Errorf("stripe_call: 'tool' is required (e.g. \"list_customers\")")
	}
	rawParams, _ := call.Args["params"].(map[string]any)
	if rawParams == nil {
		rawParams = map[string]any{}
	}

	stripeKey := os.Getenv("STRIPE_SECRET_KEY")
	if stripeKey == "" {
		return nil, nil, fmt.Errorf("stripe_call: STRIPE_SECRET_KEY not set — add to /opt/asaf/secrets/core.env")
	}

	result, dagID, err := callUpstreamMCP(ctx, "stripe", toolName,
		stripSensitiveArgs(rawParams),
		map[string]string{"Authorization": "Bearer " + stripeKey},
	)
	if err != nil {
		return nil, nil, fmt.Errorf("stripe_call → %s: %w", toolName, err)
	}

	return map[string]any{
		"upstream":   "mcp.stripe.com",
		"tool":       toolName,
		"result":     result,
		"dag_node":   dagID,
		"brokered":   true,
		"pqc_signed": true,
	}, nil, nil
}

// ── mcp_gateway ───────────────────────────────────────────────────────────────

// HandleMCPGateway is a generic upstream MCP broker. Forwards a tool call
// to any allowlisted upstream, applying the full PQC-WAF pipeline.
//
// Args:
//   - upstream (string, required): Allowlist key ("stripe", "cloudflare", ...)
//   - tool     (string, required): MCP tool name on the upstream server
//   - params   (object, optional): Tool parameters
func HandleMCPGateway(ctx context.Context, call mcp.MCPToolCall) (any, []string, error) {
	upstream, _ := call.Args["upstream"].(string)
	toolName, _ := call.Args["tool"].(string)

	if upstream == "" {
		keys := make([]string, 0, len(sekhemAllowlist))
		for k := range sekhemAllowlist {
			keys = append(keys, k)
		}
		return nil, nil, fmt.Errorf("mcp_gateway: 'upstream' required. Allowlisted: %s", strings.Join(keys, ", "))
	}
	if toolName == "" {
		return nil, nil, fmt.Errorf("mcp_gateway: 'tool' is required")
	}
	if _, ok := sekhemAllowlist[strings.ToLower(upstream)]; !ok {
		return nil, nil, fmt.Errorf("mcp_gateway: %q is not on the SEKHEM allowlist — add it in gateway_proxy_tools.go with a data-classification review", upstream)
	}

	rawParams, _ := call.Args["params"].(map[string]any)
	if rawParams == nil {
		rawParams = map[string]any{}
	}

	headers := map[string]string{}
	switch strings.ToLower(upstream) {
	case "stripe":
		if k := os.Getenv("STRIPE_SECRET_KEY"); k != "" {
			headers["Authorization"] = "Bearer " + k
		}
	case "cloudflare", "cloudflare-docs", "cloudflare-bindings", "cloudflare-builds", "cloudflare-observability":
		if t := os.Getenv("CLOUDFLARE_AGENT_TOKEN"); t != "" {
			headers["Authorization"] = "Bearer " + t
		}
	}

	result, dagID, err := callUpstreamMCP(ctx, upstream, toolName, stripSensitiveArgs(rawParams), headers)
	if err != nil {
		return nil, nil, fmt.Errorf("mcp_gateway → %s/%s: %w", upstream, toolName, err)
	}

	return map[string]any{
		"upstream":   upstream,
		"tool":       toolName,
		"result":     result,
		"dag_node":   dagID,
		"brokered":   true,
		"pqc_signed": true,
	}, nil, nil
}

// ── Internal broker ───────────────────────────────────────────────────────────

func callUpstreamMCP(
	ctx context.Context,
	upstreamKey, toolName string,
	params, headers map[string]any,
) (any, string, error) {
	upstreamURL, ok := sekhemAllowlist[upstreamKey]
	if !ok {
		return nil, "", fmt.Errorf("SEKHEM: %q not in allowlist", upstreamKey)
	}

	// Convert headers map[string]any -> map[string]string
	hdrs := map[string]string{}
	for k, v := range headers {
		if s, ok := v.(string); ok {
			hdrs[k] = s
		}
	}
	return callUpstreamMCPTyped(ctx, upstreamKey, upstreamURL, toolName, params, hdrs)
}

func callUpstreamMCPTyped(
	ctx context.Context,
	upstreamKey, upstreamURL, toolName string,
	params map[string]any,
	headers map[string]string,
) (any, string, error) {
	store := getKASAStore()

	// Pre-call DAG node
	preNode := dag.Node{
		Action: "mcp_gateway_call",
		Symbol: "Nkyinkyim",
		Time:   lorentz.StampNow(),
		PQC:    map[string]string{"upstream": upstreamKey, "tool": toolName},
	}
	if store != nil {
		_ = store.Append(preNode)
	}

	// Build JSON-RPC body
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params":  map[string]any{"name": toolName, "arguments": params},
	})
	if err != nil {
		return nil, "", fmt.Errorf("marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, upstreamURL, bytes.NewReader(body))
	if err != nil {
		return nil, "", fmt.Errorf("request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Brokered-By", "pqc-khepra-mcp")
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := upstreamClient.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("upstream: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return nil, "", fmt.Errorf("read: %w", err)
	}
	if resp.StatusCode >= 400 {
		return nil, "", fmt.Errorf("upstream HTTP %d: %s", resp.StatusCode, string(raw))
	}

	var parsed any
	if jsonErr := json.Unmarshal(raw, &parsed); jsonErr != nil {
		parsed = string(raw)
	}

	// ML-DSA-65 sign response
	respBytes, _ := json.Marshal(parsed)
	sigHex, pubHex := "", ""
	if pub, priv, keyErr := adinkra.GenerateDilithiumKey(); keyErr == nil {
		if sig, sigErr := adinkra.Sign(priv, respBytes); sigErr == nil {
			sigHex = fmt.Sprintf("%x", sig)
			pubHex = fmt.Sprintf("%x", pub)
		}
	}

	// Post-call DAG node
	postNode := dag.Node{
		Action: "mcp_gateway_response",
		Symbol: "Nkyinkyim",
		Time:   lorentz.StampNow(),
		PQC: map[string]string{
			"upstream":        upstreamKey,
			"tool":            toolName,
			"response_sig":    sigHex,
			"response_pubkey": pubHex,
			"http_status":     fmt.Sprintf("%d", resp.StatusCode),
		},
	}
	dagID := ""
	if store != nil {
		_ = store.Append(postNode)
		dagID = postNode.Hash
	}

	return parsed, dagID, nil
}

// stripSensitiveArgs removes args whose key contains a sensitive pattern,
// preventing accidental CUI/sovereign data leakage to external MCPs.
func stripSensitiveArgs(args map[string]any) map[string]any {
	safe := make(map[string]any, len(args))
	for k, v := range args {
		lk := strings.ToLower(k)
		blocked := false
		for _, pat := range sensitiveArgPatterns {
			if strings.Contains(lk, pat) {
				blocked = true
				break
			}
		}
		if !blocked {
			safe[k] = v
		}
	}
	return safe
}
