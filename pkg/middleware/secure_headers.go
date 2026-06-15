// Package middleware provides reusable HTTP middleware for the Khepra gateway.
// This file implements OWASP Secure Headers Project recommendations.
//
// Reference: https://owasp.org/www-project-secure-headers/
// OWASP SDLC Phase: Implementation (OWASP Proactive Control C9: Security Logging;
//                                   OWASP Secure Headers Project)
//
// Headers enforced:
//   - Strict-Transport-Security (HSTS) — forces HTTPS, prevents SSL stripping
//   - Content-Security-Policy (CSP) — prevents XSS, data injection
//   - X-Content-Type-Options: nosniff — prevents MIME-type sniffing
//   - X-Frame-Options: DENY — prevents clickjacking
//   - Referrer-Policy — limits referrer leakage
//   - Permissions-Policy — restricts browser feature access
//   - Cache-Control — prevents caching of sensitive API responses
//   - X-Request-ID — traceability for audit logs
package middleware

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strings"
)

// SecureHeadersConfig controls which headers are applied.
type SecureHeadersConfig struct {
	// HSTSMaxAge is the max-age for Strict-Transport-Security in seconds.
	// Default: 31536000 (1 year). Set to 0 to disable HSTS (non-HTTPS environments).
	HSTSMaxAge int

	// HSTSIncludeSubdomains adds includeSubDomains to the HSTS directive.
	HSTSIncludeSubdomains bool

	// HSTSPreload adds the preload directive (requires HSTS submission).
	HSTSPreload bool

	// CSPDirective is the Content-Security-Policy value.
	// If empty, a strict default is applied.
	CSPDirective string

	// IsDevelopment relaxes some headers for local development.
	// Never set true in production.
	IsDevelopment bool

	// APIMode sets headers appropriate for JSON API responses (not HTML).
	// CSP is omitted for pure API endpoints.
	APIMode bool

	// RequestIDHeader is the header name for request tracing.
	// Default: "X-Request-ID"
	RequestIDHeader string
}

// DefaultSecureHeadersConfig returns OWASP-recommended secure header settings
// appropriate for the Khepra API server (API mode).
func DefaultSecureHeadersConfig() *SecureHeadersConfig {
	return &SecureHeadersConfig{
		HSTSMaxAge:            31536000, // 1 year
		HSTSIncludeSubdomains: true,
		HSTSPreload:           false, // Enable after HSTS preload list submission
		APIMode:               true,
		RequestIDHeader:       "X-Request-ID",
	}
}

// DefaultWebSecureHeadersConfig returns OWASP-recommended headers for HTML UIs.
func DefaultWebSecureHeadersConfig() *SecureHeadersConfig {
	return &SecureHeadersConfig{
		HSTSMaxAge:            31536000,
		HSTSIncludeSubdomains: true,
		HSTSPreload:           false,
		APIMode:               false,
		CSPDirective: strings.Join([]string{
			"default-src 'self'",
			"script-src 'self'",
			"style-src 'self' 'unsafe-inline'",   // Allow inline styles for UI frameworks
			"img-src 'self' data: https:",
			"font-src 'self'",
			"connect-src 'self' https://api.souhimbou.ai",
			"frame-ancestors 'none'",
			"object-src 'none'",
			"base-uri 'self'",
			"form-action 'self'",
			"upgrade-insecure-requests",
		}, "; "),
		RequestIDHeader: "X-Request-ID",
	}
}

// SecureHeaders returns an HTTP middleware that applies OWASP security headers
// to all responses. It must be the outermost middleware in the chain.
//
// Usage:
//
//	mux := http.NewServeMux()
//	handler := middleware.SecureHeaders(mux, middleware.DefaultSecureHeadersConfig())
//	http.ListenAndServe(":8080", handler)
func SecureHeaders(next http.Handler, cfg *SecureHeadersConfig) http.Handler {
	if cfg == nil {
		cfg = DefaultSecureHeadersConfig()
	}

	// Build HSTS header value once (immutable after construction)
	hstsValue := buildHSTS(cfg)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()

		// ── HSTS (Strict-Transport-Security) ─────────────────────────────────
		// Only set over HTTPS or when explicitly configured for production.
		if hstsValue != "" && (r.TLS != nil || !cfg.IsDevelopment) {
			h.Set("Strict-Transport-Security", hstsValue)
		}

		// ── Anti-clickjacking ─────────────────────────────────────────────────
		h.Set("X-Frame-Options", "DENY")

		// ── MIME-type sniffing prevention ─────────────────────────────────────
		h.Set("X-Content-Type-Options", "nosniff")

		// ── Referrer policy ───────────────────────────────────────────────────
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")

		// ── Permissions policy (restrict browser features) ────────────────────
		h.Set("Permissions-Policy",
			"camera=(), microphone=(), geolocation=(), payment=(), usb=(), "+
				"interest-cohort=(), accelerometer=(), gyroscope=()")

		// ── Content Security Policy ───────────────────────────────────────────
		if !cfg.APIMode {
			csp := cfg.CSPDirective
			if csp == "" {
				csp = "default-src 'self'; frame-ancestors 'none'; object-src 'none'"
			}
			h.Set("Content-Security-Policy", csp)
		}

		// ── Cross-Origin policies ─────────────────────────────────────────────
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")

		// ── Cache control for API responses ───────────────────────────────────
		// Prevents caching of potentially sensitive API responses.
		if cfg.APIMode {
			h.Set("Cache-Control", "no-store, max-age=0")
			h.Set("Pragma", "no-cache")
		}

		// ── Remove server identification headers ──────────────────────────────
		h.Del("Server")
		h.Del("X-Powered-By")

		// ── Request tracing ───────────────────────────────────────────────────
		headerName := cfg.RequestIDHeader
		if headerName == "" {
			headerName = "X-Request-ID"
		}
		if h.Get(headerName) == "" {
			requestID := generateRequestID()
			h.Set(headerName, requestID)
			// Make the request ID accessible to downstream handlers via the request header
			r.Header.Set(headerName, requestID)
		}

		next.ServeHTTP(w, r)
	})
}

// buildHSTS constructs the Strict-Transport-Security header value.
func buildHSTS(cfg *SecureHeadersConfig) string {
	if cfg.HSTSMaxAge <= 0 {
		return ""
	}
	var sb strings.Builder
	sb.WriteString("max-age=")
	// Use strconv to avoid fmt import dependency
	maxAge := cfg.HSTSMaxAge
	if maxAge < 0 {
		maxAge = 0
	}
	sb.WriteString(itoa(maxAge))
	if cfg.HSTSIncludeSubdomains {
		sb.WriteString("; includeSubDomains")
	}
	if cfg.HSTSPreload {
		sb.WriteString("; preload")
	}
	return sb.String()
}

// generateRequestID returns a random 16-byte hex request ID.
func generateRequestID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "00000000000000000000000000000000"
	}
	return hex.EncodeToString(b)
}

// itoa converts a non-negative integer to its decimal string representation
// without importing strconv.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	buf := make([]byte, 0, 10)
	for n > 0 {
		buf = append([]byte{byte('0' + n%10)}, buf...)
		n /= 10
	}
	return string(buf)
}
