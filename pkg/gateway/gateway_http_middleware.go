// Package gateway — net/http bilateral adapter for the Khepra Secure Gateway.
//
// GatewayMiddleware wraps the 4-layer Gateway (Firewall → Auth → Anomaly → RateLimit)
// as a standard net/http middleware, making it composable with the MCP HTTP transport.
//
// Bilateral security model:
//
//	INGRESS (request side — 4 layers in order):
//	  Layer 1: FirewallLayer  — IP blocklist, geo-block, WAF (SQLi/XSS/LFI/RCE)
//	  Layer 2: AuthLayer      — ML-DSA-65 ASAF attestation, mTLS, Bearer JWT
//	  Layer 3: AnomalyLayer   — KASA behavioral scoring, block threshold
//	  Layer 4: ControlLayer   — per-identity rate limiting
//
//	EGRESS (response side):
//	  • Identity + anomaly score injected into response headers (X-Khepra-Identity,
//	    X-Khepra-Anomaly-Score) for downstream observability and DAG attestation.
//	  • Minimal error responses on block (no internal detail leakage).
//	  • All requests logged to gateway control layer for DAG audit trail.
//
// Usage (in transport_http.go):
//
//	var handler http.Handler = mux
//	handler = sekhem.HTTPMiddleware(waf)(handler)        // WAF bilateral
//	handler = gateway.Middleware(gw)(handler)            // 4-layer gateway
//	handler = corsMiddleware(handler)
//	handler = secureHeadersMiddleware(handler)
package gateway

import (
	"net/http"
)

// Middleware wraps a Gateway as a net/http middleware function.
//
// The returned middleware applies all four security layers to every request
// before passing it to the next handler. Blocked requests are terminated with
// minimal error bodies; allowed requests carry identity context headers.
//
// Middleware ordering (outer → inner, i.e. first-called → last-called):
//
//	secureHeaders → cors → gateway.Middleware → sekhem.HTTPMiddleware → mux
//
// The gateway layer sits outside the SEKHEM WAF so that:
//   - IP blocklists and auth failures are rejected before WAF rule scanning (cheaper).
//   - The gateway can add identity context that the WAF and mux handlers can read.
func Middleware(gw *Gateway) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		// Gateway.Handler() already returns an http.Handler that chains all
		// four security layers and delegates to the upstream handler on pass.
		return gw.Handler(next)
	}
}
