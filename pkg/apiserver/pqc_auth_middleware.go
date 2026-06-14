//go:build saas

// Package apiserver — PQC Auth Middleware (Gin adapter)
//
// Bridges pkg/auth.PQCAuthGateway into the Gin HTTP framework.
// Supports three credential types with a single middleware:
//
//	Priority 1 — X-Khepra-PQC-Token: <mldsa65-jwt>
//	  Native PQC token issued by this gateway (ML-DSA-65 / NIST FIPS 204).
//	  Highest trust. Issued after successful OAuth2 PKCE or SAML flow.
//
//	Priority 2 — Authorization: Bearer <supabase-jwt>
//	  HS256 JWT from Supabase Auth (email, Google, GitHub OAuth).
//	  Validated with SUPABASE_JWT_SECRET, then auto-wrapped in a PQC token.
//	  This is how users log in with their existing Claude/Google accounts
//	  via Supabase → get a PQC-secured session token.
//
//	Priority 3 — Authorization: Bearer <api-key>
//	  Legacy machine-bound API keys validated via the license manager.
//	  Backward compatible. No PQC wrapping (service accounts only).
//
// Claude Enterprise SSO (SAML 2.0 / WorkOS):
//
//	Enterprise users authenticated via Anthropic's WorkOS IdP flow have their
//	SAML assertion routed through POST /api/v1/auth/saml/callback, which calls
//	PQCAuthGateway.IssueFromSAML() → ML-DSA-65 signed PQCToken.
//	The resulting PQCToken is then used for all subsequent API calls.
package apiserver

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/auth"
)

// ─── Gin Context Keys ─────────────────────────────────────────────────────────

const (
	// GinKeyPQCClaims holds *auth.PQCTokenClaims when a PQC token was validated.
	GinKeyPQCClaims = "pqc_claims"
	// GinKeySubject holds the authenticated user/agent subject string.
	GinKeySubject = "subject"
	// GinKeyRoles holds []string of roles from the token.
	GinKeyRoles = "roles"
	// GinKeyTrustScore holds the float64 ASAF trust score.
	GinKeyTrustScore = "trust_score"
	// GinKeyAuthMethod identifies which credential type was used.
	GinKeyAuthMethod = "auth_method"
)

// ─── Server Injection ─────────────────────────────────────────────────────────

// WithPQCAuthGateway injects the PQC auth gateway into the server.
// When set, all API calls are validated with ML-DSA-65 PQC signatures.
// When nil, the server falls back to legacy API key validation.
func (s *Server) WithPQCAuthGateway(gw *auth.PQCAuthGateway) {
	s.pqcGateway = gw
}

// ─── Unified PQC Auth Middleware ──────────────────────────────────────────────

// PQCGinMiddleware replaces the basic AuthMiddleware with full PQC + multi-IdP support.
// It is injected automatically when WithPQCAuthGateway() is called.
//
// Auth priority:
//  1. X-Khepra-PQC-Token (native ML-DSA-65 JWT)
//  2. Bearer <supabase-jwt> (HS256 → auto-wrapped in PQC token)
//  3. Bearer <pqc-jwt> (ML-DSA-65 JWT via Authorization header)
//  4. Bearer <api-key> (legacy, backward compat)
func (s *Server) PQCGinMiddleware() gin.HandlerFunc {
	supabaseSecret := []byte(os.Getenv("SUPABASE_JWT_SECRET"))

	return func(c *gin.Context) {
		// ── Priority 1: Native X-Khepra-PQC-Token header ─────────────────────
		if pqcTok := c.GetHeader("X-Khepra-PQC-Token"); pqcTok != "" && s.pqcGateway != nil {
			claims, err := s.pqcGateway.VerifyPQCToken(pqcTok)
			if err != nil {
				c.JSON(http.StatusUnauthorized, gin.H{
					"error":  "invalid_pqc_token",
					"detail": err.Error(),
				})
				c.Abort()
				return
			}
			s.setPQCContext(c, claims, "pqc-native")
			c.Next()
			return
		}

		authHdr := c.GetHeader("Authorization")
		if authHdr == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "unauthorized",
				"hint":  "Provide X-Khepra-PQC-Token or Authorization: Bearer <token>",
				"auth_docs": gin.H{
					"supabase_jwt": "Login via Supabase Auth (email/Google/GitHub) → use the access_token",
					"pqc_token":    "POST /api/v1/auth/token to exchange any valid token for a PQC token",
					"saml_sso":     "POST /api/v1/auth/saml/callback for enterprise SAML 2.0 / WorkOS",
					"api_key":      "Machine-bound API key from your Khepra license",
				},
			})
			c.Abort()
			return
		}

		parts := strings.SplitN(authHdr, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_authorization_format"})
			c.Abort()
			return
		}
		bearerToken := parts[1]

		// ── Priority 2: Supabase JWT (HS256) ──────────────────────────────────
		if len(supabaseSecret) > 0 {
			if sbClaims, ok := validateSupabaseJWT(bearerToken, supabaseSecret); ok {
				subject, _ := sbClaims["sub"].(string)
				if subject == "" {
					subject = "supabase-unknown"
				}

				// Auto-wrap into PQC token if gateway available
				if s.pqcGateway != nil {
					roles := extractSupabaseRoles(sbClaims)
					pqcTok, err := s.pqcGateway.WrapOAuth2Token(bearerToken, subject, roles, "supabase-auth")
					if err == nil {
						s.setPQCContext(c, pqcTok.Claims, "supabase-pqc-wrapped")
						if email, ok := sbClaims["email"].(string); ok {
							c.Set("email", email)
						}
						c.Next()
						return
					}
				}

				// Gateway unavailable — set context from raw Supabase claims
				c.Set(GinKeySubject, subject)
				c.Set(GinKeyRoles, extractSupabaseRoles(sbClaims))
				c.Set(GinKeyTrustScore, 0.80)
				c.Set(GinKeyAuthMethod, "supabase-jwt")
				if email, ok := sbClaims["email"].(string); ok {
					c.Set("email", email)
				}
				c.Next()
				return
			}
		}

		// ── Priority 3: PQC Bearer token (ML-DSA-65 JWT via Auth header) ─────
		if s.pqcGateway != nil {
			if claims, err := s.pqcGateway.VerifyPQCToken(bearerToken); err == nil {
				s.setPQCContext(c, claims, "pqc-bearer")
				c.Next()
				return
			}
		}

		// ── Priority 4: Legacy API key (backward compat) ─────────────────────
		if s.licMgr != nil {
			valid, err := s.licMgr.ValidateAPIKey(bearerToken)
			if err == nil && valid {
				keyPrefix := bearerToken
				if len(keyPrefix) > 8 {
					keyPrefix = keyPrefix[:8] + "…"
				}
				c.Set(GinKeySubject, "api-key:"+keyPrefix)
				c.Set(GinKeyRoles, []string{"operator"})
				c.Set(GinKeyTrustScore, 0.70)
				c.Set(GinKeyAuthMethod, "legacy-api-key")
				c.Next()
				return
			}
		} else {
			// No license manager — dev pass-through (never in production)
			c.Set(GinKeySubject, "dev-passthrough")
			c.Set(GinKeyAuthMethod, "dev")
			c.Next()
			return
		}

		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "unauthorized",
			"hint":  "All credential types failed. Visit POST /api/v1/auth/token",
		})
		c.Abort()
	}
}

// setPQCContext sets Gin context keys from verified PQCTokenClaims.
func (s *Server) setPQCContext(c *gin.Context, claims *auth.PQCTokenClaims, method string) {
	c.Set(GinKeyPQCClaims, claims)
	c.Set(GinKeySubject, claims.Subject)
	c.Set(GinKeyRoles, claims.Roles)
	c.Set(GinKeyTrustScore, claims.TrustScore)
	c.Set(GinKeyAuthMethod, method)
	c.Header("X-Khepra-Subject", claims.Subject)
	c.Header("X-Khepra-Symbol", claims.Symbol)
}

// ─── Auth Endpoints ───────────────────────────────────────────────────────────

// setupAuthRoutes registers public auth endpoints on the v1 group.
// These endpoints operate WITHOUT the auth middleware so they can bootstrap tokens.
func (s *Server) setupAuthRoutes(r *gin.RouterGroup) {
	authGroup := r.Group("/auth")
	{
		// Exchange any valid credential for a native PQC token
		authGroup.POST("/token", s.handleAuthToken)

		// SAML 2.0 / WorkOS callback — Claude Enterprise SSO
		authGroup.POST("/saml/callback", s.handleAuthSAMLCallback)

		// RFC 7662 token introspection
		authGroup.GET("/introspect", s.handleAuthIntrospect)

		// ML-DSA-65 public key — for verifiers (clients, other services)
		authGroup.GET("/keys/public", s.handleAuthPublicKey)
	}
}

// handleAuthToken accepts a Supabase JWT or API key and issues a native PQC token.
//
//	POST /api/v1/auth/token
//	Authorization: Bearer <supabase-jwt>
//	→ { "pqc_token": "...", "expires_at": "...", "subject": "..." }
func (s *Server) handleAuthToken(c *gin.Context) {
	if s.pqcGateway == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": "pqc_gateway_not_configured",
			"hint":  "Set KHEPRA_PQC_ENABLED=true and restart",
		})
		return
	}

	supabaseSecret := []byte(os.Getenv("SUPABASE_JWT_SECRET"))
	authHdr := c.GetHeader("Authorization")
	if authHdr == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing Authorization header"})
		return
	}
	parts := strings.SplitN(authHdr, " ", 2)
	if len(parts) != 2 || parts[0] != "Bearer" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "expected Bearer token"})
		return
	}
	bearerToken := parts[1]

	// Try Supabase JWT first
	if len(supabaseSecret) > 0 {
		if sbClaims, ok := validateSupabaseJWT(bearerToken, supabaseSecret); ok {
			subject, _ := sbClaims["sub"].(string)
			roles := extractSupabaseRoles(sbClaims)
			pqcTok, err := s.pqcGateway.WrapOAuth2Token(bearerToken, subject, roles, "supabase-auth")
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to issue PQC token"})
				return
			}
			c.JSON(http.StatusOK, gin.H{
				"pqc_token":   pqcTok.Signed,
				"expires_at":  pqcTok.ExpiresAt.UTC().Format(time.RFC3339),
				"subject":     pqcTok.Claims.Subject,
				"symbol":      pqcTok.Claims.Symbol,
				"trust_score": pqcTok.Claims.TrustScore,
				"protocol":    "AdinKhepra-v1",
				"algorithm":   "ML-DSA-65",
				"usage":       "Set as X-Khepra-PQC-Token header for all API calls",
			})
			return
		}
	}

	c.JSON(http.StatusUnauthorized, gin.H{
		"error": "token_validation_failed",
		"hint":  "Provide a valid Supabase JWT (email/Google/GitHub via Supabase Auth)",
	})
}

// handleAuthSAMLCallback accepts a SAML 2.0 assertion and issues a PQC token.
// This is the endpoint that Anthropic WorkOS SSO (Claude Enterprise) calls.
//
//	POST /api/v1/auth/saml/callback
//	Content-Type: application/xml  (raw SAML assertion XML)
//	→ { "pqc_token": "...", "subject": "...", "expires_at": "..." }
func (s *Server) handleAuthSAMLCallback(c *gin.Context) {
	if s.pqcGateway == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "pqc_gateway_not_configured"})
		return
	}

	assertionXML, err := c.GetRawData()
	if err != nil || len(assertionXML) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing SAML assertion XML in request body"})
		return
	}

	// NOTE: XML-DSig signature validation of the SAML assertion MUST be performed
	// by your IdP SDK (e.g., github.com/crewjam/saml) before reaching here.
	// This endpoint performs identity extraction + PQC wrapping only.
	pqcTok, err := s.pqcGateway.IssueFromSAML(assertionXML)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":  "saml_assertion_invalid",
			"detail": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"pqc_token":   pqcTok.Signed,
		"expires_at":  pqcTok.ExpiresAt.UTC().Format(time.RFC3339),
		"subject":     pqcTok.Claims.Subject,
		"symbol":      pqcTok.Claims.Symbol,
		"trust_score": pqcTok.Claims.TrustScore,
		"protocol":    "AdinKhepra-v1 / SAML2",
		"algorithm":   "ML-DSA-65",
	})
}

// handleAuthIntrospect returns RFC 7662-compatible token metadata.
//
//	GET /api/v1/auth/introspect
//	Authorization: Bearer <pqc-token>
func (s *Server) handleAuthIntrospect(c *gin.Context) {
	if s.pqcGateway == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "pqc_gateway_not_configured"})
		return
	}
	parts := strings.SplitN(c.GetHeader("Authorization"), " ", 2)
	if len(parts) != 2 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing token"})
		return
	}
	intro := s.pqcGateway.Introspect(parts[1])
	c.JSON(http.StatusOK, intro)
}

// handleAuthPublicKey returns the ML-DSA-65 public key for external verifiers.
//
//	GET /api/v1/auth/keys/public
//	→ { "algorithm": "ML-DSA-65", "public_key_hex": "...", "symbol": "Eban" }
func (s *Server) handleAuthPublicKey(c *gin.Context) {
	if s.pqcGateway == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "pqc_gateway_not_configured"})
		return
	}
	pubBytes := s.pqcGateway.PublicKeyBytes()
	c.JSON(http.StatusOK, gin.H{
		"algorithm":      "ML-DSA-65",
		"nist_standard":  "FIPS 204",
		"public_key_hex": hex2str(pubBytes),
		"key_size_bytes": len(pubBytes),
		"issuer":         "khepra-pqc-gateway",
		"protocol":       "AdinKhepra-v1",
	})
}

// ─── Supabase JWT Validation ──────────────────────────────────────────────────

// validateSupabaseJWT validates a Supabase HS256 JWT using the JWT secret.
// Pure stdlib — no external JWT library dependency in this layer.
// Returns the decoded claims and true if the token is valid and unexpired.
func validateSupabaseJWT(tokenStr string, secret []byte) (map[string]interface{}, bool) {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return nil, false
	}

	// Verify HMAC-SHA256 signature — constant-time comparison
	signingInput := parts[0] + "." + parts[1]
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(signingInput))
	expectedSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(expectedSig), []byte(parts[2])) {
		return nil, false
	}

	// Decode payload
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, false
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, false
	}

	// Check expiry
	if exp, ok := claims["exp"].(float64); ok {
		if time.Now().Unix() > int64(exp) {
			return nil, false // expired
		}
	}

	return claims, true
}

// extractSupabaseRoles extracts the role(s) from Supabase JWT claims.
// Supabase uses a single "role" claim ("authenticated", "anon", "service_role", etc.)
// mapped to your Khepra permission model.
func extractSupabaseRoles(claims map[string]interface{}) []string {
	role, _ := claims["role"].(string)
	switch role {
	case "service_role":
		return []string{"admin", "security-engineer"}
	case "authenticated":
		return []string{"security-engineer"}
	default:
		return []string{"viewer"}
	}
}

// ─── Utilities ────────────────────────────────────────────────────────────────

// hex2str converts bytes to a lowercase hex string without importing encoding/hex.
func hex2str(b []byte) string {
	const hextable = "0123456789abcdef"
	buf := make([]byte, len(b)*2)
	for i, v := range b {
		buf[i*2] = hextable[v>>4]
		buf[i*2+1] = hextable[v&0x0f]
	}
	return string(buf)
}
