// Package auth — PQC-enhanced OAuth2 / SAML authentication gateway.
//
// Layers AdinKhepra ML-DSA-65 attestation on top of standard OAuth2 PKCE
// and SAML 2.0 flows.  Standard protocol tokens are accepted from any IdP
// (Keycloak, Okta, Azure AD, ADFS, etc.) and immediately re-signed with
// ML-DSA-65 before being issued to API consumers.
//
// Flow overview:
//
//	OAuth2 PKCE ──► IdP access_token ──► PQCAuthGateway.WrapOAuth2Token()
//	                                      └─► ML-DSA-65 signed PQCToken
//
//	SAML 2.0 ──────► SAML assertion ───► PQCAuthGateway.IssueFromSAML()
//	                                      └─► ML-DSA-65 signed PQCToken
//
// The resulting PQCToken is a compact JWT whose signature is produced by
// ML-DSA-65 (NIST FIPS 204) instead of the traditional HMAC-SHA256.
// AdinKhepra ASAF attestation metadata is embedded in every token.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/golang-jwt/jwt/v5"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/adinkra"
)

// =============================================================================
// ML-DSA-65 JWT Signing Method  (NIST FIPS 204)
// =============================================================================

const algMLDSA65 = "ML-DSA-65"

// SigningMethodMLDSA65 implements jwt.SigningMethod using NIST FIPS 204 ML-DSA-65.
// Register once at startup via RegisterMLDSA65JWTMethod().
type SigningMethodMLDSA65 struct{}

var (
	mldsaMethod     = &SigningMethodMLDSA65{}
	mldsaMethodOnce sync.Once
)

// RegisterMLDSA65JWTMethod registers ML-DSA-65 as a named JWT signing method.
// Call this once before issuing or verifying PQC tokens.
func RegisterMLDSA65JWTMethod() {
	mldsaMethodOnce.Do(func() {
		jwt.RegisterSigningMethod(algMLDSA65, func() jwt.SigningMethod {
			return mldsaMethod
		})
	})
}

// Alg returns the algorithm identifier embedded in the JWT header.
func (m *SigningMethodMLDSA65) Alg() string { return algMLDSA65 }

// Sign produces an ML-DSA-65 signature over the JWT signing string.
// key must be *mldsa65.PrivateKey.
func (m *SigningMethodMLDSA65) Sign(signingString string, key interface{}) ([]byte, error) {
	priv, ok := key.(*mldsa65.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("ML-DSA-65 JWT: expected *mldsa65.PrivateKey, got %T", key)
	}
	sig, err := priv.Sign(rand.Reader, []byte(signingString), nil)
	if err != nil {
		return nil, fmt.Errorf("ML-DSA-65 JWT: sign error: %w", err)
	}
	return sig, nil
}

// Verify checks an ML-DSA-65 signature against the JWT signing string.
// key must be *mldsa65.PublicKey.
func (m *SigningMethodMLDSA65) Verify(signingString string, sig []byte, key interface{}) error {
	pub, ok := key.(*mldsa65.PublicKey)
	if !ok {
		return fmt.Errorf("ML-DSA-65 JWT: expected *mldsa65.PublicKey, got %T", key)
	}
	if !mldsa65.Verify(pub, []byte(signingString), nil, sig) {
		return errors.New("ML-DSA-65 JWT: signature verification failed")
	}
	return nil
}

// =============================================================================
// PQC Token Claims
// =============================================================================

// PQCTokenClaims are the standard JWT claims enriched with AdinKhepra ASAF metadata.
type PQCTokenClaims struct {
	jwt.RegisteredClaims

	// Standard identity
	Roles       []string `json:"roles,omitempty"`
	Permissions []string `json:"perms,omitempty"`

	// AdinKhepra / ASAF enrichment
	Symbol              string  `json:"asaf_symbol,omitempty"`
	SpectralFingerprint string  `json:"asaf_sfp,omitempty"`
	TrustScore          float64 `json:"asaf_trust,omitempty"`

	// Upstream IdP traceability
	UpstreamProvider string `json:"upstream_idp,omitempty"`
	UpstreamDigest   string `json:"upstream_dig,omitempty"` // SHA-256 of upstream token

	// Protocol that produced this token
	ProtocolType string `json:"proto,omitempty"` // "oauth2", "saml", "local"
}

// PQCToken bundles the signed JWT compact string with its parsed claims.
type PQCToken struct {
	Signed    string          // Compact JWT (Header.Payload.Signature)
	Claims    *PQCTokenClaims
	ExpiresAt time.Time
}

// =============================================================================
// OAuth2 PKCE Session
// =============================================================================

// PKCESession tracks one in-flight OAuth2 PKCE authorization code exchange.
type PKCESession struct {
	State        string // CSRF state token (random, URL-safe base64)
	CodeVerifier string // S256 code verifier (secret, 64 random bytes base64url)
	RedirectURI  string
	CreatedAt    time.Time
	ExpiresAt    time.Time // 10-minute window
}

// CodeChallenge returns the S256 code challenge: base64url(SHA256(codeVerifier)).
func (s *PKCESession) CodeChallenge() string {
	h := sha256.Sum256([]byte(s.CodeVerifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// IsExpired returns true if the PKCE session has timed out.
func (s *PKCESession) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}

// =============================================================================
// PQC Auth Gateway
// =============================================================================

// pqcClaimsKey is the context key for attaching PQCTokenClaims to requests.
type pqcClaimsKey struct{}

// PQCAuthGateway is the top-level gateway.  It accepts standard OAuth2/SAML
// credentials from any IdP and issues PQC-signed tokens for downstream services.
type PQCAuthGateway struct {
	priv   *mldsa65.PrivateKey
	pub    *mldsa65.PublicKey
	symbol string
	issuer string

	tokenTTL time.Duration

	// PKCE session store (production should use Redis/Postgres for HA)
	pkceMu       sync.Mutex
	pkceSessions map[string]*PKCESession
}

// PQCAuthGatewayConfig configures a PQCAuthGateway.
type PQCAuthGatewayConfig struct {
	Symbol   string        // Adinkra symbol for this gateway (default: "Eban")
	Issuer   string        // JWT iss claim (default: "khepra-pqc-auth-gateway")
	TokenTTL time.Duration // Default: 1 hour
}

// NewPQCAuthGateway creates a new PQCAuthGateway.  Pass nil keys to auto-generate
// a fresh ML-DSA-65 key pair.
func NewPQCAuthGateway(priv *mldsa65.PrivateKey, pub *mldsa65.PublicKey, cfg PQCAuthGatewayConfig) (*PQCAuthGateway, error) {
	RegisterMLDSA65JWTMethod()

	if priv == nil || pub == nil {
		// GenerateKey returns (PublicKey, PrivateKey, error) in CIRCL
		p, v, err := mldsa65.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("pqc-auth: generate key pair: %w", err)
		}
		pub, priv = p, v
	}

	symbol := cfg.Symbol
	if symbol == "" {
		symbol = "Eban"
	}
	issuer := cfg.Issuer
	if issuer == "" {
		issuer = "khepra-pqc-auth-gateway"
	}
	ttl := cfg.TokenTTL
	if ttl == 0 {
		ttl = time.Hour
	}

	adinkra.AuditSensitiveOperation(fmt.Sprintf("PQCAuthGateway:Init:%s", symbol), true)
	return &PQCAuthGateway{
		priv:         priv,
		pub:          pub,
		symbol:       symbol,
		issuer:       issuer,
		tokenTTL:     ttl,
		pkceSessions: make(map[string]*PKCESession),
	}, nil
}

// PublicKey returns the gateway's ML-DSA-65 public key for external verifiers.
func (g *PQCAuthGateway) PublicKey() *mldsa65.PublicKey { return g.pub }

// PublicKeyBytes returns the gateway's serialized public key.
func (g *PQCAuthGateway) PublicKeyBytes() []byte {
	b, _ := g.pub.MarshalBinary()
	return b
}

// =============================================================================
// OAuth2 PKCE Flow
// =============================================================================

// StartPKCEFlow creates a new PKCE session with a cryptographically random
// state token and code verifier.  Use PKCESession.State and
// PKCESession.CodeChallenge() when building the IdP authorization URL.
func (g *PQCAuthGateway) StartPKCEFlow(redirectURI string) (*PKCESession, error) {
	stateBytes := make([]byte, 32)
	verifierBytes := make([]byte, 64)
	if _, err := rand.Read(stateBytes); err != nil {
		return nil, fmt.Errorf("pqc-auth: state gen: %w", err)
	}
	if _, err := rand.Read(verifierBytes); err != nil {
		return nil, fmt.Errorf("pqc-auth: verifier gen: %w", err)
	}

	session := &PKCESession{
		State:        base64.RawURLEncoding.EncodeToString(stateBytes),
		CodeVerifier: base64.RawURLEncoding.EncodeToString(verifierBytes),
		RedirectURI:  redirectURI,
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(10 * time.Minute),
	}

	g.pkceMu.Lock()
	g.pkceSessions[session.State] = session
	g.pkceMu.Unlock()

	adinkra.AuditSensitiveOperation("OAuth2:PKCESessionStarted", true)
	return session, nil
}

// ExchangeFn is the caller-supplied IdP-specific token exchange function.
// It receives (authorizationCode, codeVerifier, redirectURI) and must return
// the upstream access token, subject (user ID), roles, and any error.
type ExchangeFn func(code, verifier, redirect string) (accessToken, subject string, roles []string, err error)

// CompletePKCEFlow validates the PKCE callback, calls exchangeFn to obtain
// an upstream access token, then wraps the result in a PQC-signed PQCToken.
func (g *PQCAuthGateway) CompletePKCEFlow(code, state string, exchangeFn ExchangeFn) (*PQCToken, error) {
	g.pkceMu.Lock()
	session, ok := g.pkceSessions[state]
	if ok {
		delete(g.pkceSessions, state) // One-time use — prevent replay
	}
	g.pkceMu.Unlock()

	if !ok {
		adinkra.AuditSensitiveOperation("OAuth2:PKCEInvalidState", false)
		return nil, errors.New("pqc-auth: unknown or replayed PKCE state")
	}
	if session.IsExpired() {
		adinkra.AuditSensitiveOperation("OAuth2:PKCEExpiredState", false)
		return nil, errors.New("pqc-auth: PKCE session expired")
	}

	accessToken, subject, roles, err := exchangeFn(code, session.CodeVerifier, session.RedirectURI)
	if err != nil {
		adinkra.AuditSensitiveOperation("OAuth2:PKCEExchangeFailed", false)
		return nil, fmt.Errorf("pqc-auth: token exchange: %w", err)
	}

	adinkra.AuditSensitiveOperation(fmt.Sprintf("OAuth2:PKCEComplete:%s", subject), true)
	return g.WrapOAuth2Token(accessToken, subject, roles, "oauth2-pkce")
}

// WrapOAuth2Token wraps an upstream access token in a PQC-signed JWT.
// The upstream token is hashed (SHA-256) and embedded as upstreamDigest for audit trails.
func (g *PQCAuthGateway) WrapOAuth2Token(accessToken, subject string, roles []string, provider string) (*PQCToken, error) {
	sfp := pqcSFPHex(g.symbol)
	digest := sha256.Sum256([]byte(accessToken))
	now := time.Now()
	exp := now.Add(g.tokenTTL)

	claims := &PQCTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    g.issuer,
			Subject:   subject,
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(exp),
			ID:        pqcRandHex(16),
		},
		Roles:               roles,
		Symbol:              g.symbol,
		SpectralFingerprint: sfp,
		TrustScore:          0.85, // OAuth2 PKCE base trust
		UpstreamProvider:    provider,
		UpstreamDigest:      hex.EncodeToString(digest[:]),
		ProtocolType:        "oauth2",
	}

	signed, err := g.signClaims(claims)
	if err != nil {
		return nil, err
	}

	adinkra.AuditSensitiveOperation(fmt.Sprintf("PQC:Issued:oauth2:%s", subject), true)
	return &PQCToken{Signed: signed, Claims: claims, ExpiresAt: exp}, nil
}

// =============================================================================
// SAML 2.0 Flow
// =============================================================================

// samlAssertion is a minimal XML struct for extracting identity from SAML 2.0 assertions.
type samlAssertion struct {
	XMLName    xml.Name   `xml:"Assertion"`
	NameID     string     `xml:"Subject>NameID"`
	Attributes []samlAttr `xml:"AttributeStatement>Attribute"`
}

type samlAttr struct {
	Name   string   `xml:",attr"`
	Values []string `xml:"AttributeValue"`
}

// samlResponse wraps a SAML Response that contains an Assertion.
type samlResponse struct {
	XMLName   xml.Name      `xml:"Response"`
	Assertion samlAssertion `xml:"Assertion"`
}

// IssueFromSAML parses a SAML 2.0 assertion (XML bytes), extracts the subject
// and roles, then issues a ML-DSA-65 signed PQCToken.
//
// IMPORTANT: This function performs identity extraction only.  XML-DSIG
// verification of the SAML assertion MUST be performed by the caller before
// passing assertionXML here.  Use your IdP's SAML library for XML-DSIG validation.
func (g *PQCAuthGateway) IssueFromSAML(assertionXML []byte) (*PQCToken, error) {
	var assertion samlAssertion
	if err := xml.Unmarshal(assertionXML, &assertion); err != nil {
		// Try wrapped <Response><Assertion> structure
		var resp samlResponse
		if err2 := xml.Unmarshal(assertionXML, &resp); err2 != nil {
			adinkra.AuditSensitiveOperation("SAML:ParseFailed", false)
			return nil, fmt.Errorf("pqc-auth: parse SAML assertion: %w", err)
		}
		assertion = resp.Assertion
	}

	subject := strings.TrimSpace(assertion.NameID)
	if subject == "" {
		adinkra.AuditSensitiveOperation("SAML:MissingNameID", false)
		return nil, errors.New("pqc-auth: SAML assertion missing NameID")
	}

	// Extract roles/groups from standard SAML attribute names
	var roles []string
	for _, attr := range assertion.Attributes {
		lower := strings.ToLower(attr.Name)
		if strings.Contains(lower, "role") || strings.Contains(lower, "group") ||
			strings.Contains(lower, "memberof") {
			roles = append(roles, attr.Values...)
		}
	}

	sfp := pqcSFPHex(g.symbol)
	digest := sha256.Sum256(assertionXML)
	now := time.Now()
	exp := now.Add(g.tokenTTL)

	claims := &PQCTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    g.issuer,
			Subject:   subject,
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(exp),
			ID:        pqcRandHex(16),
		},
		Roles:               roles,
		Symbol:              g.symbol,
		SpectralFingerprint: sfp,
		TrustScore:          0.90, // SAML from trusted IdP — higher base trust
		UpstreamProvider:    "saml2",
		UpstreamDigest:      hex.EncodeToString(digest[:]),
		ProtocolType:        "saml",
	}

	signed, err := g.signClaims(claims)
	if err != nil {
		return nil, err
	}

	adinkra.AuditSensitiveOperation(fmt.Sprintf("PQC:Issued:saml:%s", subject), true)
	return &PQCToken{Signed: signed, Claims: claims, ExpiresAt: exp}, nil
}

// =============================================================================
// Token Verification
// =============================================================================

// VerifyPQCToken parses and verifies a PQC-signed JWT string.
// Returns the embedded claims on success.
func (g *PQCAuthGateway) VerifyPQCToken(tokenString string) (*PQCTokenClaims, error) {
	claims := &PQCTokenClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
		if t.Method.Alg() != algMLDSA65 {
			return nil, fmt.Errorf("pqc-auth: unexpected alg %q", t.Method.Alg())
		}
		return g.pub, nil
	})
	if err != nil {
		adinkra.AuditSensitiveOperation("PQC:VerifyFailed", false)
		return nil, fmt.Errorf("pqc-auth: verify token: %w", err)
	}
	if !token.Valid {
		adinkra.AuditSensitiveOperation("PQC:TokenInvalid", false)
		return nil, errors.New("pqc-auth: token invalid")
	}
	adinkra.AuditSensitiveOperation(fmt.Sprintf("PQC:Verified:%s", claims.Subject), true)
	return claims, nil
}

// =============================================================================
// HTTP Middleware
// =============================================================================

// PQCTokenHeader is the HTTP header carrying the PQC-signed JWT.
const PQCTokenHeader = "X-Khepra-PQC-Token"

// ClaimsFromContext retrieves PQCTokenClaims attached to a request context by the middleware.
func ClaimsFromContext(ctx context.Context) (*PQCTokenClaims, bool) {
	claims, ok := ctx.Value(pqcClaimsKey{}).(*PQCTokenClaims)
	return claims, ok
}

// HTTPMiddleware returns an http.Handler middleware that verifies the
// X-Khepra-PQC-Token (or Bearer) header on every inbound request.
// Verified claims are attached to the request context for downstream handlers.
func (g *PQCAuthGateway) HTTPMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tokenStr := r.Header.Get(PQCTokenHeader)
			if tokenStr == "" {
				if authHdr := r.Header.Get("Authorization"); strings.HasPrefix(authHdr, "Bearer ") {
					tokenStr = strings.TrimPrefix(authHdr, "Bearer ")
				}
			}
			if tokenStr == "" {
				http.Error(w, `{"error":"missing PQC token"}`, http.StatusUnauthorized)
				return
			}
			claims, err := g.VerifyPQCToken(tokenStr)
			if err != nil {
				http.Error(w, `{"error":"invalid PQC token"}`, http.StatusUnauthorized)
				return
			}
			ctx := context.WithValue(r.Context(), pqcClaimsKey{}, claims)
			w.Header().Set("X-Khepra-Subject", claims.Subject)
			w.Header().Set("X-Khepra-Symbol", claims.Symbol)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// =============================================================================
// PQC Auth Provider (implements AuthProvider)
// =============================================================================

// PQCAuthProvider wraps any upstream AuthProvider and adds ML-DSA-65 signed
// PQC tokens on top of standard OAuth2/SAML authentication.  After the upstream
// authenticates the user, a PQCToken is issued and stored in User.Attributes["pqc_token"].
type PQCAuthProvider struct {
	BaseAuthProvider
	upstream AuthProvider
	gateway  *PQCAuthGateway
}

// NewPQCAuthProvider creates a PQC-layered provider wrapping the given upstream.
func NewPQCAuthProvider(name string, upstream AuthProvider, gateway *PQCAuthGateway) *PQCAuthProvider {
	return &PQCAuthProvider{
		BaseAuthProvider: BaseAuthProvider{name: "pqc+" + name},
		upstream:         upstream,
		gateway:          gateway,
	}
}

// Authenticate delegates to the upstream, then wraps the session with a PQC token.
func (p *PQCAuthProvider) Authenticate(ctx context.Context, creds *Credentials) (*User, error) {
	user, err := p.upstream.Authenticate(ctx, creds)
	if err != nil {
		adinkra.AuditSensitiveOperation("PQCAuth:UpstreamFailed", false)
		return nil, fmt.Errorf("pqc-auth: upstream: %w", err)
	}

	upstreamTok := creds.Token // upstream access token; may be empty for password flow
	token, err := p.gateway.WrapOAuth2Token(upstreamTok, user.ID, user.Roles, p.upstream.GetName())
	if err != nil {
		return nil, fmt.Errorf("pqc-auth: wrap token: %w", err)
	}

	if user.Attributes == nil {
		user.Attributes = make(map[string]interface{})
	}
	user.Attributes["pqc_token"] = token.Signed
	user.Attributes["pqc_symbol"] = p.gateway.symbol
	user.Attributes["pqc_trust"] = token.Claims.TrustScore
	user.ExpiresAt = token.ExpiresAt

	adinkra.AuditSensitiveOperation(fmt.Sprintf("PQCAuth:Issued:%s", user.ID), true)
	return user, nil
}

// RefreshToken refreshes the upstream token and re-issues a PQC token.
func (p *PQCAuthProvider) RefreshToken(ctx context.Context, refreshToken string) (string, error) {
	newTok, err := p.upstream.RefreshToken(ctx, refreshToken)
	if err != nil {
		return "", fmt.Errorf("pqc-auth: upstream refresh: %w", err)
	}
	pqcTok, err := p.gateway.WrapOAuth2Token(newTok, "", nil, p.upstream.GetName())
	if err != nil {
		return "", err
	}
	return pqcTok.Signed, nil
}

// ValidateToken verifies a PQC-signed token.
func (p *PQCAuthProvider) ValidateToken(ctx context.Context, tokenStr string) (bool, error) {
	_, err := p.gateway.VerifyPQCToken(tokenStr)
	return err == nil, nil
}

// GetUser delegates to upstream.
func (p *PQCAuthProvider) GetUser(ctx context.Context, userID string) (*User, error) {
	return p.upstream.GetUser(ctx, userID)
}

// ListUsers delegates to upstream.
func (p *PQCAuthProvider) ListUsers(ctx context.Context) ([]*User, error) {
	return p.upstream.ListUsers(ctx)
}

// CreateUser delegates to upstream.
func (p *PQCAuthProvider) CreateUser(ctx context.Context, user *User) error {
	return p.upstream.CreateUser(ctx, user)
}

// DeleteUser delegates to upstream.
func (p *PQCAuthProvider) DeleteUser(ctx context.Context, userID string) error {
	return p.upstream.DeleteUser(ctx, userID)
}

// UpdateUser delegates to upstream.
func (p *PQCAuthProvider) UpdateUser(ctx context.Context, user *User) error {
	return p.upstream.UpdateUser(ctx, user)
}

// AssignRole delegates to upstream.
func (p *PQCAuthProvider) AssignRole(ctx context.Context, userID, role string) error {
	return p.upstream.AssignRole(ctx, userID, role)
}

// RevokeRole delegates to upstream.
func (p *PQCAuthProvider) RevokeRole(ctx context.Context, userID, role string) error {
	return p.upstream.RevokeRole(ctx, userID, role)
}

// VerifyPermission delegates to upstream.
func (p *PQCAuthProvider) VerifyPermission(ctx context.Context, userID, resource, action string) (bool, error) {
	return p.upstream.VerifyPermission(ctx, userID, resource, action)
}

// GetName returns the provider name.
func (p *PQCAuthProvider) GetName() string { return p.BaseAuthProvider.name }

// Close closes the upstream provider.
func (p *PQCAuthProvider) Close() error { return p.upstream.Close() }

// =============================================================================
// Token Introspection  (RFC 7662 style)
// =============================================================================

// IntrospectionResponse is an RFC 7662-compatible token introspection response.
type IntrospectionResponse struct {
	Active     bool     `json:"active"`
	Subject    string   `json:"sub,omitempty"`
	Issuer     string   `json:"iss,omitempty"`
	Roles      []string `json:"roles,omitempty"`
	Symbol     string   `json:"asaf_symbol,omitempty"`
	TrustScore float64  `json:"asaf_trust,omitempty"`
	ExpiresAt  int64    `json:"exp,omitempty"`
}

// Introspect validates a PQC token and returns its metadata in RFC 7662 format.
func (g *PQCAuthGateway) Introspect(tokenString string) *IntrospectionResponse {
	claims, err := g.VerifyPQCToken(tokenString)
	if err != nil {
		return &IntrospectionResponse{Active: false}
	}
	var exp int64
	if claims.ExpiresAt != nil {
		exp = claims.ExpiresAt.Unix()
	}
	return &IntrospectionResponse{
		Active:     true,
		Subject:    claims.Subject,
		Issuer:     claims.Issuer,
		Roles:      claims.Roles,
		Symbol:     claims.Symbol,
		TrustScore: claims.TrustScore,
		ExpiresAt:  exp,
	}
}

// IntrospectionHTTPHandler returns an http.HandlerFunc implementing RFC 7662
// token introspection at a /introspect-style endpoint.
func (g *PQCAuthGateway) IntrospectionHTTPHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		tokenStr := r.FormValue("token")
		if tokenStr == "" {
			tokenStr = r.Header.Get(PQCTokenHeader)
		}
		resp := g.Introspect(tokenStr)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}

// =============================================================================
// PKCE session maintenance
// =============================================================================

// CleanExpiredPKCESessions removes expired PKCE sessions to prevent memory growth.
// Call periodically (e.g., every 5 minutes in a background goroutine).
func (g *PQCAuthGateway) CleanExpiredPKCESessions() int {
	g.pkceMu.Lock()
	defer g.pkceMu.Unlock()
	removed := 0
	for state, s := range g.pkceSessions {
		if s.IsExpired() {
			delete(g.pkceSessions, state)
			removed++
		}
	}
	return removed
}

// =============================================================================
// Utilities
// =============================================================================

// TokensEqual performs constant-time comparison of two PQC token strings.
func TokensEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// signClaims signs a PQCTokenClaims set and returns the compact JWT string.
func (g *PQCAuthGateway) signClaims(claims *PQCTokenClaims) (string, error) {
	token := jwt.NewWithClaims(mldsaMethod, claims)
	signed, err := token.SignedString(g.priv)
	if err != nil {
		adinkra.AuditSensitiveOperation("PQC:SignFailed", false)
		return "", fmt.Errorf("pqc-auth: sign claims: %w", err)
	}
	return signed, nil
}

// pqcSFPHex returns a hex-encoded spectral fingerprint for the given Adinkra symbol.
func pqcSFPHex(symbol string) string {
	fp := adinkra.GetSpectralFingerprint(symbol)
	if len(fp) > 0 {
		n := len(fp)
		if n > 16 {
			n = 16
		}
		return hex.EncodeToString(fp[:n])
	}
	h := sha256.Sum256([]byte(symbol))
	return hex.EncodeToString(h[:8])
}

// pqcRandHex generates n random bytes as a hex string.
func pqcRandHex(n int) string {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		panic(fmt.Sprintf("pqc-auth: crypto/rand: %v", err))
	}
	return hex.EncodeToString(b)
}
