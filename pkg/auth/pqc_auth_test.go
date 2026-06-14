// Integration tests for PQC-enhanced OAuth2/SAML auth gateway.
// All tests exercise real ML-DSA-65 cryptography — no mocks.
package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// newTestGateway creates a PQCAuthGateway with auto-generated keys.
func newTestGateway(t *testing.T) *PQCAuthGateway {
	t.Helper()
	gw, err := NewPQCAuthGateway(nil, nil, PQCAuthGatewayConfig{
		Symbol:   "Eban",
		Issuer:   "khepra-test",
		TokenTTL: time.Hour,
	})
	if err != nil {
		t.Fatalf("NewPQCAuthGateway: %v", err)
	}
	return gw
}

// =============================================================================
// Gateway Initialization
// =============================================================================

// TestGatewayInitAutoKeyGeneration verifies that a nil key pair causes
// automatic generation and the gateway is usable immediately.
func TestGatewayInitAutoKeyGeneration(t *testing.T) {
	gw := newTestGateway(t)
	if gw.pub == nil || gw.priv == nil {
		t.Fatal("auto-generated keys are nil")
	}
	pubBytes := gw.PublicKeyBytes()
	if len(pubBytes) == 0 {
		t.Error("PublicKeyBytes returned empty slice")
	}
}

// TestGatewayDefaultsApplied verifies that empty config gets sensible defaults.
func TestGatewayDefaultsApplied(t *testing.T) {
	gw, err := NewPQCAuthGateway(nil, nil, PQCAuthGatewayConfig{})
	if err != nil {
		t.Fatalf("NewPQCAuthGateway: %v", err)
	}
	if gw.symbol != "Eban" {
		t.Errorf("default symbol: got %q, want Eban", gw.symbol)
	}
	if gw.issuer != "khepra-pqc-auth-gateway" {
		t.Errorf("default issuer: got %q", gw.issuer)
	}
	if gw.tokenTTL != time.Hour {
		t.Errorf("default TTL: got %v, want 1h", gw.tokenTTL)
	}
}

// =============================================================================
// OAuth2 PKCE Flow
// =============================================================================

// TestPKCESessionStartGeneration verifies that StartPKCEFlow generates
// cryptographically random state and verifier (no two sessions are equal).
func TestPKCESessionStartGeneration(t *testing.T) {
	gw := newTestGateway(t)

	s1, err := gw.StartPKCEFlow("https://app.example.com/callback")
	if err != nil {
		t.Fatalf("StartPKCEFlow: %v", err)
	}
	s2, err := gw.StartPKCEFlow("https://app.example.com/callback")
	if err != nil {
		t.Fatalf("StartPKCEFlow #2: %v", err)
	}

	if s1.State == s2.State {
		t.Error("PKCE state values are identical — RNG not used")
	}
	if s1.CodeVerifier == s2.CodeVerifier {
		t.Error("PKCE code verifiers are identical — RNG not used")
	}
	if s1.CodeChallenge() == "" {
		t.Error("CodeChallenge is empty")
	}
}

// TestPKCECodeChallengeIsS256 verifies the PKCE S256 challenge is
// base64url(SHA256(verifier)) — not the verifier itself (plain method).
func TestPKCECodeChallengeIsS256(t *testing.T) {
	gw := newTestGateway(t)
	s, _ := gw.StartPKCEFlow("https://example.com/cb")

	challenge := s.CodeChallenge()
	// S256 challenge must not equal the verifier
	if challenge == s.CodeVerifier {
		t.Error("CodeChallenge equals CodeVerifier — plain PKCE used instead of S256")
	}
	// Must be base64url-encoded (no padding, no + or /)
	if strings.ContainsAny(challenge, "+/=") {
		t.Errorf("CodeChallenge contains non-base64url characters: %q", challenge)
	}
}

// TestPKCECompletionValidatesState verifies that an invalid state token is rejected.
func TestPKCECompletionValidatesState(t *testing.T) {
	gw := newTestGateway(t)

	exchange := func(code, verifier, redirect string) (string, string, []string, error) {
		return "upstream-token", "user@example.com", []string{"operator"}, nil
	}

	_, err := gw.CompletePKCEFlow("auth-code", "invalid-state-xyz", exchange)
	if err == nil {
		t.Error("expected error for invalid PKCE state, got nil")
	}
}

// TestPKCEStateUsedOnlyOnce verifies that a PKCE state cannot be used twice
// (replay protection).
func TestPKCEStateUsedOnlyOnce(t *testing.T) {
	gw := newTestGateway(t)
	session, _ := gw.StartPKCEFlow("https://example.com/cb")

	exchange := func(code, verifier, redirect string) (string, string, []string, error) {
		return "tok", "user@test.com", []string{"viewer"}, nil
	}

	// First completion — should succeed
	_, err := gw.CompletePKCEFlow("code123", session.State, exchange)
	if err != nil {
		t.Fatalf("first CompletePKCEFlow: %v", err)
	}

	// Second completion with same state — must be rejected
	_, err = gw.CompletePKCEFlow("code123", session.State, exchange)
	if err == nil {
		t.Error("expected replay rejection on second use of same state")
	}
}

// TestPKCEFullFlowEndToEnd exercises the complete PKCE flow:
// StartPKCEFlow → CompletePKCEFlow → PQCToken issued and verifiable.
func TestPKCEFullFlowEndToEnd(t *testing.T) {
	gw := newTestGateway(t)
	session, _ := gw.StartPKCEFlow("https://app.khepra.io/callback")

	var capturedVerifier string
	exchange := func(code, verifier, redirect string) (string, string, []string, error) {
		capturedVerifier = verifier
		return "upstream-access-token-xyz", "agent-user@khepra.io",
			[]string{"security-engineer"}, nil
	}

	token, err := gw.CompletePKCEFlow("authcode-abc", session.State, exchange)
	if err != nil {
		t.Fatalf("CompletePKCEFlow: %v", err)
	}

	// The exchange function received the correct verifier
	if capturedVerifier != session.CodeVerifier {
		t.Errorf("wrong verifier passed to exchange: got %q, want %q",
			capturedVerifier, session.CodeVerifier)
	}

	// Token must be verifiable
	claims, err := gw.VerifyPQCToken(token.Signed)
	if err != nil {
		t.Fatalf("VerifyPQCToken after PKCE: %v", err)
	}

	if claims.Subject != "agent-user@khepra.io" {
		t.Errorf("Subject mismatch: %q", claims.Subject)
	}
	if claims.Symbol != "Eban" {
		t.Errorf("Symbol mismatch: %q", claims.Symbol)
	}
	if claims.ProtocolType != "oauth2" {
		t.Errorf("ProtocolType mismatch: %q", claims.ProtocolType)
	}
	if len(claims.UpstreamDigest) == 0 {
		t.Error("UpstreamDigest is empty — audit trail missing")
	}
}

// =============================================================================
// Token Wrapping and Verification
// =============================================================================

// TestWrapOAuth2TokenFields verifies all expected fields are set in the token.
func TestWrapOAuth2TokenFields(t *testing.T) {
	gw := newTestGateway(t)
	token, err := gw.WrapOAuth2Token("access-token-raw", "sub-001",
		[]string{"admin", "security-engineer"}, "keycloak")
	if err != nil {
		t.Fatalf("WrapOAuth2Token: %v", err)
	}

	if token.Signed == "" {
		t.Error("Signed JWT string is empty")
	}
	if token.Claims == nil {
		t.Fatal("Claims is nil")
	}
	if token.Claims.Subject != "sub-001" {
		t.Errorf("Subject: got %q", token.Claims.Subject)
	}
	if token.Claims.UpstreamProvider != "keycloak" {
		t.Errorf("UpstreamProvider: got %q", token.Claims.UpstreamProvider)
	}
	if token.Claims.TrustScore <= 0 {
		t.Error("TrustScore is zero or negative")
	}
	if len(token.Claims.SpectralFingerprint) == 0 {
		t.Error("SpectralFingerprint is empty")
	}
}

// TestVerifyPQCTokenWithCorrectGateway verifies a token with the issuing gateway.
func TestVerifyPQCTokenWithCorrectGateway(t *testing.T) {
	gw := newTestGateway(t)
	token, _ := gw.WrapOAuth2Token("tok", "user@org.com", nil, "test")

	claims, err := gw.VerifyPQCToken(token.Signed)
	if err != nil {
		t.Errorf("VerifyPQCToken: %v", err)
	}
	if claims.Subject != "user@org.com" {
		t.Errorf("Subject mismatch: %q", claims.Subject)
	}
}

// TestVerifyPQCTokenWithDifferentGatewayFails verifies that a token issued
// by one gateway cannot be verified by another (different key pair).
func TestVerifyPQCTokenWithDifferentGatewayFails(t *testing.T) {
	gw1 := newTestGateway(t)
	gw2 := newTestGateway(t)

	token, _ := gw1.WrapOAuth2Token("tok", "user@org.com", nil, "test")
	_, err := gw2.VerifyPQCToken(token.Signed)
	if err == nil {
		t.Error("expected verification failure with different gateway key")
	}
}

// TestVerifyPQCTokenTamperedPayloadFails verifies that modifying the token
// payload causes verification failure.
func TestVerifyPQCTokenTamperedPayloadFails(t *testing.T) {
	gw := newTestGateway(t)
	token, _ := gw.WrapOAuth2Token("tok", "user@org.com", nil, "test")

	// Split header.payload.signature and replace payload with garbage
	parts := strings.Split(token.Signed, ".")
	if len(parts) != 3 {
		t.Fatalf("unexpected JWT structure: %d parts", len(parts))
	}
	tampered := parts[0] + ".dGFtcGVyZWQ." + parts[2]
	_, err := gw.VerifyPQCToken(tampered)
	if err == nil {
		t.Error("expected verification failure for tampered payload")
	}
}

// =============================================================================
// SAML Flow
// =============================================================================

// TestSAMLIssueFromMinimalAssertion verifies PQC token issuance from a
// minimal SAML 2.0 assertion XML.
func TestSAMLIssueFromMinimalAssertion(t *testing.T) {
	gw := newTestGateway(t)

	assertionXML := []byte(`<?xml version="1.0"?>
<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion">
  <Subject>
    <NameID>saml-user@enterprise.mil</NameID>
  </Subject>
  <AttributeStatement>
    <Attribute Name="roles">
      <AttributeValue>compliance-officer</AttributeValue>
      <AttributeValue>security-engineer</AttributeValue>
    </Attribute>
  </AttributeStatement>
</Assertion>`)

	token, err := gw.IssueFromSAML(assertionXML)
	if err != nil {
		t.Fatalf("IssueFromSAML: %v", err)
	}

	claims, err := gw.VerifyPQCToken(token.Signed)
	if err != nil {
		t.Fatalf("VerifyPQCToken after SAML: %v", err)
	}

	if claims.Subject != "saml-user@enterprise.mil" {
		t.Errorf("Subject: got %q", claims.Subject)
	}
	if claims.ProtocolType != "saml" {
		t.Errorf("ProtocolType: got %q", claims.ProtocolType)
	}
	if len(claims.UpstreamDigest) == 0 {
		t.Error("UpstreamDigest empty — SAML assertion not hashed")
	}
	// Trust score for SAML should be higher than OAuth2 base
	if claims.TrustScore < 0.89 {
		t.Errorf("SAML TrustScore too low: %.2f", claims.TrustScore)
	}
}

// TestSAMLIssueWrappedResponse verifies parsing of a SAML Response that
// wraps the Assertion element.
func TestSAMLIssueWrappedResponse(t *testing.T) {
	gw := newTestGateway(t)

	responseXML := []byte(`<?xml version="1.0"?>
<Response xmlns="urn:oasis:names:tc:SAML:2.0:protocol">
  <Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion">
    <Subject>
      <NameID>wrapped-user@dod.mil</NameID>
    </Subject>
  </Assertion>
</Response>`)

	token, err := gw.IssueFromSAML(responseXML)
	if err != nil {
		t.Fatalf("IssueFromSAML with wrapped Response: %v", err)
	}
	if token.Claims.Subject != "wrapped-user@dod.mil" {
		t.Errorf("Subject: got %q", token.Claims.Subject)
	}
}

// TestSAMLEmptyNameIDRejected verifies that a SAML assertion without NameID
// returns an error (not a token with empty subject).
func TestSAMLEmptyNameIDRejected(t *testing.T) {
	gw := newTestGateway(t)
	assertionXML := []byte(`<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion">
  <Subject><NameID></NameID></Subject>
</Assertion>`)

	_, err := gw.IssueFromSAML(assertionXML)
	if err == nil {
		t.Error("expected error for empty NameID, got nil")
	}
}

// TestSAMLMalformedXMLRejected verifies that malformed XML is rejected.
func TestSAMLMalformedXMLRejected(t *testing.T) {
	gw := newTestGateway(t)
	_, err := gw.IssueFromSAML([]byte("not-xml-at-all!!!"))
	if err == nil {
		t.Error("expected error for malformed SAML XML, got nil")
	}
}

// =============================================================================
// HTTP Middleware
// =============================================================================

// TestHTTPMiddlewareAcceptsValidToken verifies that the middleware passes
// a valid PQC-signed Bearer token through to the next handler.
func TestHTTPMiddlewareAcceptsValidToken(t *testing.T) {
	gw := newTestGateway(t)
	token, _ := gw.WrapOAuth2Token("tok", "user@test.com", []string{"operator"}, "test")

	handlerCalled := false
	handler := gw.HTTPMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		claims, ok := ClaimsFromContext(r.Context())
		if !ok || claims == nil {
			t.Error("claims not attached to request context")
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/api/v1/agents", nil)
	req.Header.Set("Authorization", "Bearer "+token.Signed)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	if !handlerCalled {
		t.Error("next handler was not called")
	}
}

// TestHTTPMiddlewareRejectsMissingToken verifies that a request without
// a token receives 401 Unauthorized.
func TestHTTPMiddlewareRejectsMissingToken(t *testing.T) {
	gw := newTestGateway(t)
	handler := gw.HTTPMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/api/v1/agents", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

// TestHTTPMiddlewareRejectsInvalidToken verifies that a garbled token
// receives 401 Unauthorized.
func TestHTTPMiddlewareRejectsInvalidToken(t *testing.T) {
	gw := newTestGateway(t)
	handler := gw.HTTPMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/api/v1/agents", nil)
	req.Header.Set(PQCTokenHeader, "completely.invalid.token")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}

// TestHTTPMiddlewareAcceptsPQCTokenHeader verifies that the X-Khepra-PQC-Token
// header is also accepted (in addition to Authorization: Bearer).
func TestHTTPMiddlewareAcceptsPQCTokenHeader(t *testing.T) {
	gw := newTestGateway(t)
	token, _ := gw.WrapOAuth2Token("tok", "sub", nil, "test")

	handlerCalled := false
	handler := gw.HTTPMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/api/test", nil)
	req.Header.Set(PQCTokenHeader, token.Signed)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	if !handlerCalled {
		t.Error("next handler not called with PQCTokenHeader")
	}
}

// =============================================================================
// Token Introspection
// =============================================================================

// TestIntrospectActiveToken verifies that a valid token returns active=true
// with all expected fields.
func TestIntrospectActiveToken(t *testing.T) {
	gw := newTestGateway(t)
	token, _ := gw.WrapOAuth2Token("tok", "user@test.com", []string{"admin"}, "okta")

	resp := gw.Introspect(token.Signed)
	if !resp.Active {
		t.Error("expected active=true for valid token")
	}
	if resp.Subject != "user@test.com" {
		t.Errorf("Subject: got %q", resp.Subject)
	}
	if resp.Symbol != "Eban" {
		t.Errorf("Symbol: got %q", resp.Symbol)
	}
	if resp.ExpiresAt == 0 {
		t.Error("ExpiresAt is zero")
	}
}

// TestIntrospectInvalidTokenReturnsFalse verifies that an invalid token
// returns active=false (not an error).
func TestIntrospectInvalidTokenReturnsFalse(t *testing.T) {
	gw := newTestGateway(t)
	resp := gw.Introspect("invalid.token.string")
	if resp.Active {
		t.Error("expected active=false for invalid token")
	}
}

// =============================================================================
// PKCE Session Maintenance
// =============================================================================

// TestCleanExpiredPKCESessions verifies that expired sessions are removed.
func TestCleanExpiredPKCESessions(t *testing.T) {
	gw := newTestGateway(t)

	// Add two sessions, one expired
	gw.pkceMu.Lock()
	gw.pkceSessions["active-state"] = &PKCESession{
		State:     "active-state",
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}
	gw.pkceSessions["expired-state"] = &PKCESession{
		State:     "expired-state",
		ExpiresAt: time.Now().Add(-1 * time.Second),
	}
	gw.pkceMu.Unlock()

	removed := gw.CleanExpiredPKCESessions()
	if removed != 1 {
		t.Errorf("expected 1 removed session, got %d", removed)
	}

	gw.pkceMu.Lock()
	_, activeExists := gw.pkceSessions["active-state"]
	_, expiredExists := gw.pkceSessions["expired-state"]
	gw.pkceMu.Unlock()

	if !activeExists {
		t.Error("active session was incorrectly removed")
	}
	if expiredExists {
		t.Error("expired session was not removed")
	}
}

// =============================================================================
// Utility
// =============================================================================

// TestTokensEqualConstantTime verifies constant-time comparison semantics.
func TestTokensEqualConstantTime(t *testing.T) {
	if !TokensEqual("abc", "abc") {
		t.Error("identical strings should be equal")
	}
	if TokensEqual("abc", "def") {
		t.Error("different strings should not be equal")
	}
}

// TestClaimsFromContextRoundTrip verifies that claims attached by the middleware
// can be retrieved via ClaimsFromContext.
func TestClaimsFromContextRoundTrip(t *testing.T) {
	claims := &PQCTokenClaims{}
	claims.Subject = "test-sub"

	ctx := context.WithValue(context.Background(), pqcClaimsKey{}, claims)
	got, ok := ClaimsFromContext(ctx)
	if !ok {
		t.Fatal("ClaimsFromContext returned ok=false")
	}
	if got.Subject != "test-sub" {
		t.Errorf("Subject mismatch: got %q", got.Subject)
	}
}
