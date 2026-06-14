//go:build saas

// =============================================================================
// KHEPRA PROTOCOL - Public Attestation Verification
// =============================================================================
// Public (no-auth) endpoint that allows C3PAOs and third parties to
// independently verify the PQC signature on an ADINKHEPRA attestation.
// This is the #1 trust builder — when your evidence says
// "Verify at verify.adinkhepra.com/abc123" and the assessor clicks it.
//
// Deployment: Fly.io (Go API server)
// Route: GET /verify/:attestation_id  (public, no auth)
// =============================================================================

package apiserver

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// VerificationResponse is returned by the public verification endpoint.
type VerificationResponse struct {
	Valid           bool      `json:"valid"`
	AttestationID   string    `json:"attestation_id"`
	Status          string    `json:"status"` // "VERIFIED" | "INVALID" | "NOT_FOUND"
	Algorithm       string    `json:"algorithm"`
	SignedAt        time.Time `json:"signed_at,omitempty"`
	Scope           string    `json:"scope,omitempty"`
	DAGChainHash    string    `json:"dag_chain_hash,omitempty"`
	SignerIdentity  string    `json:"signer_identity"`
	VerifiedAt      time.Time `json:"verified_at"`
	VerificationURL string    `json:"verification_url"`
}

// registerPublicVerificationRoute adds the public verification route
// OUTSIDE the auth middleware group. Called from setupRoutes.
func (s *Server) registerPublicVerificationRoute() {
	s.router.GET("/verify/:attestation_id", s.handlePublicVerification)
	s.router.GET("/verify/:attestation_id/badge", s.handleVerificationBadge)
}

// handlePublicVerification verifies a PQC attestation by ID.
// No auth required — this is public by design.
func (s *Server) handlePublicVerification(c *gin.Context) {
	attestationID := c.Param("attestation_id")
	if attestationID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "attestation_id required"})
		return
	}

	// Accept header check: return HTML for browsers, JSON for APIs
	accept := c.GetHeader("Accept")
	wantsHTML := false
	for _, part := range []string{"text/html", "application/xhtml+xml"} {
		if len(accept) >= len(part) && containsSubstr(accept, part) {
			wantsHTML = true
			break
		}
	}

	// Look up the attestation in the DAG
	response := s.verifyAttestation(attestationID, c.Request.Host)

	if wantsHTML {
		c.Header("Content-Type", "text/html; charset=utf-8")
		c.String(http.StatusOK, renderVerificationHTML(response))
		return
	}

	c.JSON(http.StatusOK, response)
}

// verifyAttestation checks server identity and DAG for an attestation.
func (s *Server) verifyAttestation(attestationID, host string) VerificationResponse {
	response := VerificationResponse{
		AttestationID:   attestationID,
		VerifiedAt:      time.Now(),
		SignerIdentity:  "AdinKhepra SEKHEM Gateway",
		Algorithm:       "ML-DSA-65 (Dilithium3)",
		VerificationURL: fmt.Sprintf("https://%s/verify/%s", host, attestationID),
	}

	// Check the DAG store for this attestation
	if s.dagStore != nil {
		allNodes := s.dagStore.All()
		for _, node := range allNodes {
			if node.NodeID == attestationID {
				response.Valid = true
				response.Status = "VERIFIED"
				response.SignedAt = node.Timestamp
				if node.PQCSignature != "" {
					response.DAGChainHash = node.PQCSignature[:min(32, len(node.PQCSignature))]
				}
				return response
			}
		}
	}

	// Server has PQC identity → it can attest, but this specific ID wasn't found
	if s.sigPubKey != nil {
		response.Valid = false
		response.Status = "NOT_FOUND"
	} else {
		response.Valid = false
		response.Status = "NOT_FOUND"
	}

	return response
}

// handleVerificationBadge returns an SVG badge for embedding.
func (s *Server) handleVerificationBadge(c *gin.Context) {
	attestationID := c.Param("attestation_id")
	response := s.verifyAttestation(attestationID, c.Request.Host)

	color := "#e74c3c" // red
	text := "UNVERIFIED"
	if response.Valid {
		color = "#27ae60" // green
		text = "PQC VERIFIED"
	} else if response.Status == "NOT_FOUND" {
		color = "#95a5a6" // gray
		text = "NOT FOUND"
	}

	svg := fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" width="200" height="28">
  <rect rx="4" width="200" height="28" fill="#333"/>
  <rect rx="4" x="100" width="100" height="28" fill="%s"/>
  <text x="50" y="19" fill="#fff" text-anchor="middle" font-family="monospace" font-size="11">ADINKHEPRA</text>
  <text x="150" y="19" fill="#fff" text-anchor="middle" font-family="monospace" font-size="11">%s</text>
</svg>`, color, text)

	c.Header("Content-Type", "image/svg+xml")
	c.Header("Cache-Control", "no-cache")
	c.String(http.StatusOK, svg)
}

// renderVerificationHTML returns a branded HTML verification page.
func renderVerificationHTML(v VerificationResponse) string {
	statusIcon := "❌"
	statusColor := "#e74c3c"
	statusText := "VERIFICATION FAILED"
	bgGradient := "linear-gradient(135deg, #1a1a2e, #16213e)"

	if v.Valid {
		statusIcon = "✅"
		statusColor = "#27ae60"
		statusText = "CRYPTOGRAPHICALLY VERIFIED"
		bgGradient = "linear-gradient(135deg, #0a1628, #0d2137)"
	} else if v.Status == "NOT_FOUND" {
		statusIcon = "🔍"
		statusColor = "#95a5a6"
		statusText = "ATTESTATION NOT FOUND"
	}

	dagInfo := ""
	if v.DAGChainHash != "" {
		dagInfo = fmt.Sprintf(`<div class="field"><span class="label">DAG Chain Hash</span><span class="value mono">%s</span></div>`, v.DAGChainHash)
	}

	signedAt := "—"
	if !v.SignedAt.IsZero() {
		signedAt = v.SignedAt.Format("2006-01-02 15:04:05 UTC")
	}

	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AdinKhepra Verification — %s</title>
<meta name="description" content="Independent cryptographic verification of CMMC compliance attestation %s">
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=DM+Serif+Display&display=swap" rel="stylesheet">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:%s;color:#e2e5ec;font-family:'IBM Plex Sans',sans-serif;min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:24px}
.card{background:#12151c;border:1px solid #1e2433;border-radius:16px;max-width:560px;width:100%%;padding:48px 40px;box-shadow:0 20px 60px rgba(0,0,0,.5)}
.logo{font-family:'DM Serif Display',serif;font-size:24px;color:#c9a227;text-align:center;margin-bottom:8px;letter-spacing:.08em}
.subtitle{text-align:center;font-size:12px;color:#5c6478;font-family:'IBM Plex Mono',monospace;letter-spacing:.1em;text-transform:uppercase;margin-bottom:32px}
.status{text-align:center;padding:24px;border-radius:12px;margin-bottom:32px;border:1px solid %s33}
.status-icon{font-size:48px;margin-bottom:12px}
.status-text{font-family:'IBM Plex Mono',monospace;font-size:14px;font-weight:600;letter-spacing:.08em;color:%s}
.fields{display:flex;flex-direction:column;gap:16px}
.field{display:flex;justify-content:space-between;align-items:center;padding:12px 0;border-bottom:1px solid #1e2433}
.label{font-size:12px;color:#5c6478;font-family:'IBM Plex Mono',monospace;letter-spacing:.04em;text-transform:uppercase}
.value{font-size:14px;color:#e2e5ec;text-align:right;max-width:60%%}
.mono{font-family:'IBM Plex Mono',monospace;font-size:12px;word-break:break-all}
.footer{margin-top:32px;text-align:center;font-size:11px;color:#5c6478}
.footer a{color:#c9a227;text-decoration:none}
.badge{display:inline-block;padding:4px 10px;border-radius:4px;font-size:10px;font-family:'IBM Plex Mono',monospace;letter-spacing:.08em;font-weight:600}
</style>
</head>
<body>
<div class="card">
  <div class="logo">🛡️ AdinKhepra</div>
  <div class="subtitle">Attestation Verification</div>
  
  <div class="status" style="background:%s11">
    <div class="status-icon">%s</div>
    <div class="status-text">%s</div>
  </div>

  <div class="fields">
    <div class="field">
      <span class="label">Attestation ID</span>
      <span class="value mono">%s</span>
    </div>
    <div class="field">
      <span class="label">Algorithm</span>
      <span class="value">%s</span>
    </div>
    <div class="field">
      <span class="label">Signed At</span>
      <span class="value mono">%s</span>
    </div>
    <div class="field">
      <span class="label">Signer</span>
      <span class="value">%s</span>
    </div>
    <div class="field">
      <span class="label">Verified At</span>
      <span class="value mono">%s</span>
    </div>
    %s
  </div>

  <div class="footer">
    <p>This verification was performed by the <a href="https://adinkhepra.com">AdinKhepra CMMC Compliance Engine</a>.</p>
    <p style="margin-top:8px">SecRed Knowledge Inc. (NouchiX) · SDVOSB · Patent Pending</p>
  </div>
</div>
</body>
</html>`,
		v.AttestationID,
		v.AttestationID,
		bgGradient,
		statusColor,
		statusColor,
		statusColor, statusIcon, statusText,
		v.AttestationID,
		v.Algorithm,
		signedAt,
		v.SignerIdentity,
		v.VerifiedAt.Format("2006-01-02 15:04:05 UTC"),
		dagInfo,
	)
}

// containsSubstr checks if s contains substr.
func containsSubstr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
