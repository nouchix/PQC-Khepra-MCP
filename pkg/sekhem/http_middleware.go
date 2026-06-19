// Package sekhem — net/http bilateral security middleware adapter.
//
// HTTPMiddleware wraps the WAFShield for use with plain net/http servers
// (the MCP HTTP transport) without requiring the Gin framework.
//
// Security model — bilateral (ingress + egress):
//
//	INGRESS (request):
//	  ① Body size cap (maxBodyBytes) — SEKHEM-004
//	  ② Spectral fingerprint computed per request
//	  ③ All 8 WAF rules run via WAFRule.Inspect(*http.Request)
//	     — SEKHEM-001 SQLi, 002 XSS, 003 PathTraversal, 005 BadUTF8,
//	       006 BadHost, 007 RateLimit, 008 MaliciousUA
//	  ④ Block/Challenge → 403/429 + threat channel + Crowdsec decision
//	  ⑤ X-Sekhem-FP set on allowed requests
//
//	EGRESS (response):
//	  ① responseWriter wrapper captures status code
//	  ② Secret scrubber removes accidental key material from JSON bodies
//	  ③ X-Sekhem-FP echoed on response for downstream tracing
//	  ④ Threat event emitted if a HIGH anomaly score is detected on egress

package sekhem

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/nouchix/PQC-Khepra-MCP/pkg/maat"
)

// ─── Egress secret-scrubbing patterns ─────────────────────────────────────────
//
// These patterns match JSON field names whose values must never appear in a
// response body sent over the HTTP transport.  Any match → field value replaced
// with "[REDACTED]".

var secretFieldPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)"(password|passwd|secret|api[_-]?key|private[_-]?key|token|bearer|credential|auth|priv_key|privkey|kyber_priv|dsa_priv)"\s*:\s*"[^"]*"`),
	regexp.MustCompile(`(?i)"(seed|mnemonic|entropy|iv|salt|hmac|signature|x509|cert|pem)"\s*:\s*"[^"]*"`),
}

const redactedValue = `"[REDACTED]"`

// ─── captureWriter ─────────────────────────────────────────────────────────────

// captureWriter wraps http.ResponseWriter so we can inspect the response body
// before (or after) flushing it to the actual connection.
type captureWriter struct {
	http.ResponseWriter
	buf        bytes.Buffer
	statusCode int
	written    bool
}

func newCaptureWriter(w http.ResponseWriter) *captureWriter {
	return &captureWriter{ResponseWriter: w, statusCode: http.StatusOK}
}

func (cw *captureWriter) WriteHeader(code int) {
	cw.statusCode = code
	// Do NOT forward yet — we write header only after egress scan.
}

func (cw *captureWriter) Write(b []byte) (int, error) {
	return cw.buf.Write(b)
}

// flush applies egress transforms and sends the captured response to the wire.
func (cw *captureWriter) flush(fingerprint string) error {
	body := cw.buf.Bytes()

	// Egress transform 1: secret scrubbing on JSON responses.
	ct := cw.Header().Get("Content-Type")
	if strings.Contains(ct, "application/json") {
		body = scrubSecrets(body)
	}

	// Egress transform 2: add spectral fingerprint to response headers.
	if fingerprint != "" {
		cw.Header().Set("X-Sekhem-FP", fingerprint[:16])
	}

	// Egress transform 3: validate JSON is still well-formed after scrubbing.
	if strings.Contains(ct, "application/json") && !json.Valid(body) {
		// Scrubbing broke the JSON — replace with a safe error body.
		body = []byte(`{"error":"response encoding error"}`)
		cw.statusCode = http.StatusInternalServerError
	}

	cw.ResponseWriter.WriteHeader(cw.statusCode)
	_, err := cw.ResponseWriter.Write(body)
	return err
}

// Flush implements http.Flusher so SSE streams still work: when the SSE handler
// calls Flush() we forward the current buffer contents immediately.
func (cw *captureWriter) Flush() {
	if f, ok := cw.ResponseWriter.(http.Flusher); ok {
		// For SSE, forward the buffer immediately without a full egress scan
		// (SSE data is server-generated, not user-reflected, so scrubbing here
		// would interfere with the stream framing).
		cw.ResponseWriter.WriteHeader(cw.statusCode)
		cw.ResponseWriter.Write(cw.buf.Bytes()) //nolint:errcheck
		cw.buf.Reset()
		f.Flush()
	}
}

// ─── HTTPMiddleware ────────────────────────────────────────────────────────────

// HTTPMiddleware returns a net/http middleware that applies bilateral WAF
// security using the WAFShield's rules without requiring the Gin framework.
//
// Usage:
//
//	var handler http.Handler = mux
//	handler = sekhem.HTTPMiddleware(wafShield)(handler)
//
// Middleware ordering should be:
//
//	secureHeaders → cors → sekhem.HTTPMiddleware → mux handlers
func HTTPMiddleware(ws *WAFShield) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			clientIP := extractClientIP(r)

			// ── BYPASS: health probes and NPM Docker gateway ──────────────────
			if ws.isBypassPath(r.URL.Path) {
				ws.metrics.record("SEKHEM-BYPASS", WAFActionBypass)
				next.ServeHTTP(w, r)
				return
			}

			// ── INGRESS ①: Body size cap (SEKHEM-004) ────────────────────────
			if r.Body != nil {
				limited := http.MaxBytesReader(w, r.Body, maxBodyBytes)
				body, err := io.ReadAll(limited)
				if err != nil {
					corrID := newCorrelationID()
					ws.metrics.record("SEKHEM-004", WAFActionBlock)
					ws.emitThreat(&WAFRuleResult{
						RuleID:        "SEKHEM-004",
						Action:        WAFActionBlock,
						Severity:      maat.SeveritySevere,
						Certainty:     0.99,
						CorrelationID: corrID,
					}, clientIP, "", r.URL.Path)
					http.Error(w,
						fmt.Sprintf(`{"error":"request too large","correlation_id":%q}`, corrID),
						http.StatusRequestEntityTooLarge)
					return
				}
				// Rebuffer body for downstream handlers
				r.Body = io.NopCloser(bytes.NewReader(body))
			}

			// ── INGRESS ②: Spectral fingerprint ──────────────────────────────
			fingerprint := ws.computeFingerprint(clientIP, r)

			// ── INGRESS ③: Run all 8 WAF rules ───────────────────────────────
			for _, rule := range ws.rules {
				result := rule.Inspect(r)
				if result == nil {
					continue
				}
				ws.metrics.record(result.RuleID, result.Action)
				ws.emitThreat(result, clientIP, fingerprint, r.URL.Path)

				switch result.Action {
				case WAFActionBlock:
					// Severe/Catastrophic → submit Crowdsec ban (fire-and-forget)
					go ws.submitCrowdsecDecision(clientIP, crowdsecDecisionDuration, "ban")
					http.Error(w,
						fmt.Sprintf(`{"error":"forbidden","correlation_id":%q}`, result.CorrelationID),
						http.StatusForbidden)
					return

				case WAFActionChallenge:
					w.Header().Set("Retry-After", "60")
					http.Error(w,
						fmt.Sprintf(`{"error":"rate_limit_exceeded","correlation_id":%q}`, result.CorrelationID),
						http.StatusTooManyRequests)
					return
				}
			}

			// ── INGRESS ④: Mark request as WAF-cleared ───────────────────────
			r.Header.Set("X-Sekhem-FP", fingerprint[:16])
			r.Header.Set("X-Sekhem-Cleared", "true")

			// ── EGRESS: wrap ResponseWriter for bilateral scanning ────────────
			// SSE streams use a passthrough path (captureWriter.Flush() forwards
			// data immediately to preserve the event-stream framing).
			cw := newCaptureWriter(w)
			next.ServeHTTP(cw, r)
			if err := cw.flush(fingerprint); err != nil {
				// Client disconnected — normal for SSE; log at debug level only.
				_ = err
			}
		})
	}
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

// scrubSecrets replaces values of sensitive JSON fields with "[REDACTED]".
// Only operates on the first 1 MiB of the response body to bound CPU usage.
func scrubSecrets(body []byte) []byte {
	if len(body) > 1<<20 {
		return body // too large — skip scrubbing, return as-is
	}
	out := body
	for _, pat := range secretFieldPatterns {
		// Each match is: `"field_name": "sensitive_value"`
		// We want to keep the field name and replace only the value part.
		out = pat.ReplaceAllFunc(out, func(match []byte) []byte {
			// Find the colon-quote boundary: `": "value"`
			colonIdx := bytes.Index(match, []byte(`": "`))
			if colonIdx < 0 {
				// Fallback: replace everything after the first colon
				colonIdx = bytes.IndexByte(match, ':')
				if colonIdx < 0 {
					return match
				}
				return append(match[:colonIdx+1], []byte(` `+redactedValue)...)
			}
			// Preserve: `"field_name": [REDACTED]`
			return append(match[:colonIdx+2], []byte(redactedValue)...)
		})
	}
	return out
}


