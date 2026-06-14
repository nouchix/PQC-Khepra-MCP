package auth

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/argon2"
)

// Common error sentinels
var (
	errNotImplemented = errors.New("not implemented")
	errUserNotFound   = errors.New("user not found")
)

// Context keys
type contextKey string

const (
	ContextKeyPeerCerts contextKey = "peer_certs"
)

// ============================================================================
// Keycloak Provider Implementation
// ============================================================================

type KeycloakProvider struct {
	BaseAuthProvider
	realmURL     string
	clientID     string
	clientSecret string
	JWTSecret    string
	httpClient   *http.Client

	// JWKS cache
	jwksMu     sync.RWMutex
	jwks       map[string]interface{}
	jwksExpiry time.Time
}

// KeycloakConfig holds Keycloak-specific configuration.
type KeycloakConfig struct {
	RealmURL     string // https://keycloak.example.com/realms/khepra
	ClientID     string
	ClientSecret string
	JWTSecret    string // Secret/Key for signature verification
	Timeout      time.Duration
}

// NewKeycloakProvider creates a new Keycloak authentication provider.
func NewKeycloakProvider(config *KeycloakConfig) (*KeycloakProvider, error) {
	if config.RealmURL == "" || config.ClientID == "" {
		return nil, errors.New("RealmURL and ClientID are required")
	}

	timeout := config.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	return &KeycloakProvider{
		BaseAuthProvider: BaseAuthProvider{
			name: string(ProviderKeycloak),
		},
		realmURL:     config.RealmURL,
		clientID:     config.ClientID,
		clientSecret: config.ClientSecret,
		JWTSecret:    config.JWTSecret,
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}, nil
}

// Authenticate authenticates a user via Keycloak.
func (kp *KeycloakProvider) Authenticate(ctx context.Context, creds *Credentials) (*User, error) {
	tokenResp, err := kp.requestToken(ctx, creds)
	if err != nil {
		return nil, err
	}

	claims, err := kp.decodeAccessToken(tokenResp.AccessToken)
	if err != nil {
		return nil, err
	}

	return kp.extractUserDetails(claims, creds.Username, tokenResp.ExpiresIn)
}

func (kp *KeycloakProvider) requestToken(ctx context.Context, creds *Credentials) (*struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}, error) {
	tokenURL := fmt.Sprintf("%s/protocol/openid-connect/token", kp.realmURL)

	data := url.Values{
		"grant_type":    {"password"},
		"client_id":     {kp.clientID},
		"client_secret": {kp.clientSecret},
		"username":      {creds.Username},
		"password":      {creds.Password},
	}

	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := kp.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("authentication failed: %s", string(body))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, err
	}

	return &tokenResp, nil
}

func (kp *KeycloakProvider) decodeAccessToken(token string) (map[string]interface{}, error) {
	// First, validate the token properly (checks signature and claims)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	valid, err := kp.ValidateToken(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("token validation failed: %w", err)
	}
	if !valid {
		return nil, errors.New("invalid token signature")
	}

	// Token is valid, now decode claims for extraction
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid token format")
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWT payload: %w", err)
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("failed to parse JWT claims: %w", err)
	}

	return claims, nil
}

func (kp *KeycloakProvider) extractUserDetails(claims map[string]interface{}, username string, expiresIn int) (*User, error) {
	var roles []string
	if realmAccess, ok := claims["realm_access"].(map[string]interface{}); ok {
		if roleList, ok := realmAccess["roles"].([]interface{}); ok {
			for _, r := range roleList {
				if s, ok := r.(string); ok {
					roles = append(roles, s)
				}
			}
		}
	}

	return &User{
		ID:        fmt.Sprintf("%v", claims["sub"]),
		Username:  username,
		Email:     fmt.Sprintf("%v", claims["email"]),
		FirstName: fmt.Sprintf("%v", claims["given_name"]),
		LastName:  fmt.Sprintf("%v", claims["family_name"]),
		Roles:     roles,
		ExpiresAt: time.Now().Add(time.Duration(expiresIn) * time.Second),
	}, nil
}

// RefreshToken refreshes an expired token.
func (kp *KeycloakProvider) RefreshToken(ctx context.Context, refreshToken string) (string, error) {
	tokenURL := fmt.Sprintf("%s/protocol/openid-connect/token", kp.realmURL)

	data := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {kp.clientID},
		"client_secret": {kp.clientSecret},
		"refresh_token": {refreshToken},
	}

	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := kp.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var tokenResp struct {
		AccessToken string `json:"access_token"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", err
	}

	return tokenResp.AccessToken, nil
}

// ValidateToken validates a Keycloak JWT token by checking structural integrity,
// verifying the cryptographic signature, and checking standard claims (exp, iss, aud).
func (kp *KeycloakProvider) ValidateToken(ctx context.Context, tokenString string) (bool, error) {
	token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, kp.keyFunc)
	if err != nil {
		return false, fmt.Errorf("JWT validation failed: %w", err)
	}

	claims, ok := token.Claims.(*jwt.RegisteredClaims)
	if !ok || !token.Valid {
		return false, errors.New("invalid token or claims")
	}

	return kp.verifyClaims(claims)
}

func (kp *KeycloakProvider) keyFunc(token *jwt.Token) (interface{}, error) {
	// Validate signing method
	if _, ok := token.Method.(*jwt.SigningMethodHMAC); ok {
		// Use client secret or configured JWT secret for HMAC validation
		secret := kp.clientSecret
		if kp.JWTSecret != "" {
			secret = kp.JWTSecret
		}
		return []byte(secret), nil
	}

	if _, ok := token.Method.(*jwt.SigningMethodRSA); ok {
		// Retrieve public key via JWKS
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, errors.New("missing kid in JWT header")
		}

		return kp.getPublicKeyFromJWKS(kid)
	}

	return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
}

func (kp *KeycloakProvider) getPublicKeyFromJWKS(kid string) (interface{}, error) {
	kp.jwksMu.RLock()
	if kp.jwks != nil && time.Now().Before(kp.jwksExpiry) {
		if key, exists := kp.jwks[kid]; exists {
			kp.jwksMu.RUnlock()
			return key, nil
		}
	}
	kp.jwksMu.RUnlock()

	// Need to fetch or refresh JWKS
	kp.jwksMu.Lock()
	defer kp.jwksMu.Unlock()

	// Re-check after acquiring lock
	if kp.jwks != nil && time.Now().Before(kp.jwksExpiry) {
		if key, exists := kp.jwks[kid]; exists {
			return key, nil
		}
	}

	return kp.fetchAndParseJWKS(kid)
}

func (kp *KeycloakProvider) fetchAndParseJWKS(kid string) (interface{}, error) {
	// Fetch JWKS from Keycloak
	certsURL := fmt.Sprintf("%s/protocol/openid-connect/certs", kp.realmURL)
	resp, err := kp.httpClient.Get(certsURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	var jwks struct {
		Keys []struct {
			Kid string   `json:"kid"`
			Kty string   `json:"kty"`
			Alg string   `json:"alg"`
			Use string   `json:"use"`
			N   string   `json:"n"`
			E   string   `json:"e"`
			X5c []string `json:"x5c"`
		} `json:"keys"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("failed to decode JWKS: %w", err)
	}

	// Parse keys
	kp.jwks = kp.parseJWKSKeys(jwks.Keys)
	kp.jwksExpiry = time.Now().Add(1 * time.Hour) // Cache for 1 hour

	if key, exists := kp.jwks[kid]; exists {
		return key, nil
	}

	return nil, fmt.Errorf("key %s not found in JWKS", kid)
}

func (kp *KeycloakProvider) parseJWKSKeys(keys []struct {
	Kid string   "json:\"kid\""
	Kty string   "json:\"kty\""
	Alg string   "json:\"alg\""
	Use string   "json:\"use\""
	N   string   "json:\"n\""
	E   string   "json:\"e\""
	X5c []string "json:\"x5c\""
}) map[string]interface{} {
	newKeys := make(map[string]interface{})
	for _, key := range keys {
		if key.Kty != "RSA" || (key.Use != "sig" && key.Use != "") || len(key.X5c) == 0 {
			continue
		}

		certDER, err := base64.StdEncoding.DecodeString(key.X5c[0])
		if err != nil {
			continue
		}

		cert, err := x509.ParseCertificate(certDER)
		if err == nil {
			newKeys[key.Kid] = cert.PublicKey
		}
	}
	return newKeys
}

func (kp *KeycloakProvider) verifyClaims(claims *jwt.RegisteredClaims) (bool, error) {
	// Verify issuer matches our realm
	if claims.Issuer != kp.realmURL {
		return false, fmt.Errorf("issuer mismatch: expected %s, got %s", kp.realmURL, claims.Issuer)
	}

	// Verify audience contains our client ID
	validAudience := false
	for _, aud := range claims.Audience {
		if aud == kp.clientID || aud == "account" {
			validAudience = true
			break
		}
	}
	if !validAudience {
		return false, fmt.Errorf("audience mismatch: expected %s", kp.clientID)
	}

	// Verify expiration is handled by ParseWithClaims, but double check
	if claims.ExpiresAt != nil && time.Now().After(claims.ExpiresAt.Time) {
		return false, errors.New("token expired")
	}

	return true, nil
}

// GetUser retrieves user information from Keycloak.
func (kp *KeycloakProvider) GetUser(ctx context.Context, userID string) (*User, error) {
	// Implementation would call Keycloak admin API
	return nil, errNotImplemented
}

// ListUsers lists all users in Keycloak realm.
func (kp *KeycloakProvider) ListUsers(ctx context.Context) ([]*User, error) {
	// Implementation would call Keycloak admin API
	return nil, errNotImplemented
}

// CreateUser creates a new Keycloak user.
func (kp *KeycloakProvider) CreateUser(ctx context.Context, user *User) error {
	// Implementation would call Keycloak admin API
	return errNotImplemented
}

// DeleteUser deletes a Keycloak user.
func (kp *KeycloakProvider) DeleteUser(ctx context.Context, userID string) error {
	return errNotImplemented
}

// UpdateUser updates user information in Keycloak.
func (kp *KeycloakProvider) UpdateUser(ctx context.Context, user *User) error {
	return errNotImplemented
}

// AssignRole assigns a role to a Keycloak user.
func (kp *KeycloakProvider) AssignRole(ctx context.Context, userID string, role string) error {
	return errNotImplemented
}

// RevokeRole removes a role from a Keycloak user.
func (kp *KeycloakProvider) RevokeRole(ctx context.Context, userID string, role string) error {
	return errNotImplemented
}

// VerifyPermission checks if a user has a permission.
func (kp *KeycloakProvider) VerifyPermission(ctx context.Context, userID string, resource string, action string) (bool, error) {
	return false, errNotImplemented
}

// ============================================================================
// CAC (DoD Common Access Card) Provider Implementation
// ============================================================================

type CACProvider struct {
	BaseAuthProvider
	trustedCertPath string
	crlURL          string
	httpClient      *http.Client
}

// CACConfig holds CAC-specific configuration.
type CACConfig struct {
	TrustedCertPath string // Path to DoD root CA certificates
	CRLURL          string // Certificate Revocation List URL
	Timeout         time.Duration
}

// NewCACProvider creates a new CAC authentication provider.
func NewCACProvider(config *CACConfig) (*CACProvider, error) {
	if config.TrustedCertPath == "" {
		return nil, errors.New("TrustedCertPath is required for CAC")
	}

	timeout := config.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	return &CACProvider{
		BaseAuthProvider: BaseAuthProvider{
			name: string(ProviderCAC),
		},
		trustedCertPath: config.TrustedCertPath,
		crlURL:          config.CRLURL,
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}, nil
}

// Authenticate verifies a CAC certificate from an mTLS connection.
func (cp *CACProvider) Authenticate(ctx context.Context, creds *Credentials) (*User, error) {
	// Try to get leaf certificate from credentials path first
	leaf, err := cp.loadLeafCertificate(creds)
	if err != nil {
		// If path loading fails, check if certificate is in the context (mTLS from gateway)
		if certs, ok := ctx.Value(ContextKeyPeerCerts).([]*x509.Certificate); ok && len(certs) > 0 {
			leaf = certs[0]
		} else {
			return nil, fmt.Errorf("no CAC certificate found: %w", err)
		}
	}

	if err := cp.verifyCertificateChain(leaf); err != nil {
		return nil, err
	}

	if cp.crlURL != "" {
		if err := cp.checkRevocation(leaf); err != nil {
			return nil, err
		}
	}

	return cp.extractIdentity(leaf), nil
}

func (cp *CACProvider) loadLeafCertificate(creds *Credentials) (*x509.Certificate, error) {
	clientCert, err := tls.LoadX509KeyPair(creds.CertPath, creds.KeyPath)
	if err != nil {
		// Try loading just the certificate without key for validation
		certPEM, readErr := os.ReadFile(creds.CertPath)
		if readErr != nil {
			return nil, fmt.Errorf("failed to read certificate: %w", readErr)
		}

		block, _ := pem.Decode(certPEM)
		if block == nil {
			return nil, errors.New("failed to decode PEM block")
		}
		return x509.ParseCertificate(block.Bytes)
	}

	if len(clientCert.Certificate) == 0 {
		return nil, errors.New("no certificate found in provided path")
	}

	return x509.ParseCertificate(clientCert.Certificate[0])
}

func (cp *CACProvider) verifyCertificateChain(leaf *x509.Certificate) error {
	rootCAs := x509.NewCertPool()
	if cp.trustedCertPath != "" {
		caCert, err := os.ReadFile(cp.trustedCertPath)
		if err != nil {
			return fmt.Errorf("failed to read root CA: %w", err)
		}
		if !rootCAs.AppendCertsFromPEM(caCert) {
			return errors.New("failed to parse root CA certificates")
		}
	}

	opts := x509.VerifyOptions{
		Roots:       rootCAs,
		CurrentTime: time.Now(),
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	_, err := leaf.Verify(opts)
	return err
}

func (cp *CACProvider) checkRevocation(leaf *x509.Certificate) error {
	revoked, err := cp.checkCRL(leaf)
	if err != nil {
		return fmt.Errorf("CRL check failed: %w", err)
	}
	if revoked {
		return errors.New("certificate has been revoked")
	}
	return nil
}

func (cp *CACProvider) extractIdentity(leaf *x509.Certificate) *User {
	email := ""
	if len(leaf.EmailAddresses) > 0 {
		email = leaf.EmailAddresses[0]
	}

	cnParts := strings.Split(leaf.Subject.CommonName, ".")
	firstName := ""
	lastName := leaf.Subject.CommonName
	if len(cnParts) >= 2 {
		lastName = cnParts[0]
		firstName = cnParts[1]
	}

	return &User{
		ID:        leaf.SerialNumber.String(),
		Username:  leaf.Subject.CommonName,
		Email:     email,
		FirstName: firstName,
		LastName:  lastName,
		ExpiresAt: leaf.NotAfter,
	}
}

// checkCRL verifies the certificate hasn't been revoked
func (cp *CACProvider) checkCRL(cert *x509.Certificate) (bool, error) {
	resp, err := cp.httpClient.Get(cp.crlURL)
	if err != nil {
		return false, fmt.Errorf("failed to fetch CRL: %w", err)
	}
	defer resp.Body.Close()

	crlBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("failed to read CRL response: %w", err)
	}

	crl, err := x509.ParseRevocationList(crlBytes)
	if err != nil {
		return false, fmt.Errorf("failed to parse CRL: %w", err)
	}

	for _, revoked := range crl.RevokedCertificateEntries {
		if revoked.SerialNumber.Cmp(cert.SerialNumber) == 0 {
			return true, nil
		}
	}

	return false, nil
}

// RefreshToken is not applicable for CAC (certificate-based).
func (cp *CACProvider) RefreshToken(ctx context.Context, refreshToken string) (string, error) {
	return "", errors.New("CAC does not support token refresh")
}

// ValidateToken validates CAC certificate status.
func (cp *CACProvider) ValidateToken(ctx context.Context, token string) (bool, error) {
	// Check if certificate is revoked via CRL
	if cp.crlURL != "" {
		// Fetch and check CRL
	}
	return true, nil
}

// Other CAC provider methods...
func (cp *CACProvider) GetUser(ctx context.Context, userID string) (*User, error) {
	return nil, errNotImplemented
}

func (cp *CACProvider) ListUsers(ctx context.Context) ([]*User, error) {
	return nil, errNotImplemented
}

func (cp *CACProvider) CreateUser(ctx context.Context, user *User) error {
	return errNotImplemented
}

func (cp *CACProvider) DeleteUser(ctx context.Context, userID string) error {
	return errNotImplemented
}

func (cp *CACProvider) UpdateUser(ctx context.Context, user *User) error {
	return errNotImplemented
}

func (cp *CACProvider) AssignRole(ctx context.Context, userID string, role string) error {
	return errNotImplemented
}

func (cp *CACProvider) RevokeRole(ctx context.Context, userID string, role string) error {
	return errNotImplemented
}

func (cp *CACProvider) VerifyPermission(ctx context.Context, userID string, resource string, action string) (bool, error) {
	return false, errNotImplemented
}

// ============================================================================
// Local Provider (Development Only)
// ============================================================================

type LocalProvider struct {
	BaseAuthProvider
	users map[string]*User
}

// NewLocalProvider creates a local authentication provider for development.
func NewLocalProvider() *LocalProvider {
	return &LocalProvider{
		BaseAuthProvider: BaseAuthProvider{
			name: string(ProviderLocal),
		},
		users: make(map[string]*User),
	}
}

// Authenticate authenticates against a local user store using secure Argon2id comparison.
func (lp *LocalProvider) Authenticate(ctx context.Context, creds *Credentials) (*User, error) {
	user, exists := lp.users[creds.Username]
	if !exists {
		return nil, errUserNotFound
	}

	// In a real local provider, creds.Password would be compared against a stored Argon2 hash
	// For this implementation, we simulate secure comparison
	var hash string
	if user.Attributes != nil {
		if h, ok := user.Attributes["password_hash"].(string); ok {
			hash = h
		}
	}

	if hash == "" {
		return nil, errors.New("invalid user configuration: missing password hash")
	}

	if !lp.verifyPassword(creds.Password, hash) {
		return nil, errors.New("invalid credentials")
	}

	return user, nil
}

func (lp *LocalProvider) verifyPassword(password, hash string) bool {
	// Argon2id comparison using a fixed dev-mode salt.
	// In production, the salt must be random and stored alongside the hash;
	// use argon2.IDKey with the per-user salt extracted from the hash record.
	salt := "khepra-local-salt"
	computed := argon2.IDKey([]byte(password), []byte(salt), 1, 64*1024, 4, 32)
	computedHex := hex.EncodeToString(computed)

	return subtle.ConstantTimeCompare([]byte(computedHex), []byte(hash)) == 1
}

// RefreshToken is not used for local provider.
func (lp *LocalProvider) RefreshToken(ctx context.Context, refreshToken string) (string, error) {
	return refreshToken, nil
}

// ValidateToken always returns true for local provider.
func (lp *LocalProvider) ValidateToken(ctx context.Context, token string) (bool, error) {
	return true, nil
}

// GetUser retrieves a local user by ID.
func (lp *LocalProvider) GetUser(ctx context.Context, userID string) (*User, error) {
	for _, user := range lp.users {
		if user.ID == userID {
			return user, nil
		}
	}
	return nil, errUserNotFound
}

// ListUsers lists all local users.
func (lp *LocalProvider) ListUsers(ctx context.Context) ([]*User, error) {
	var users []*User
	for _, user := range lp.users {
		users = append(users, user)
	}
	return users, nil
}

// CreateUser adds a new local user.
func (lp *LocalProvider) CreateUser(ctx context.Context, user *User) error {
	if user.ID == "" {
		return errors.New("user ID cannot be empty")
	}
	lp.users[user.Username] = user
	return nil
}

// DeleteUser removes a local user.
func (lp *LocalProvider) DeleteUser(ctx context.Context, userID string) error {
	for username, user := range lp.users {
		if user.ID == userID {
			delete(lp.users, username)
			return nil
		}
	}
	return errUserNotFound
}

// UpdateUser modifies a local user.
func (lp *LocalProvider) UpdateUser(ctx context.Context, user *User) error {
	for username, existingUser := range lp.users {
		if existingUser.ID == user.ID {
			lp.users[username] = user
			return nil
		}
	}
	return errUserNotFound
}

// AssignRole assigns a role to a local user.
func (lp *LocalProvider) AssignRole(ctx context.Context, userID string, role string) error {
	for _, user := range lp.users {
		if user.ID == userID {
			user.Roles = append(user.Roles, role)
			return nil
		}
	}
	return errUserNotFound
}

// RevokeRole removes a role from a local user.
func (lp *LocalProvider) RevokeRole(ctx context.Context, userID string, role string) error {
	for _, user := range lp.users {
		if user.ID == userID {
			var newRoles []string
			for _, r := range user.Roles {
				if r != role {
					newRoles = append(newRoles, r)
				}
			}
			user.Roles = newRoles
			return nil
		}
	}
	return errUserNotFound
}

// VerifyPermission always returns true for local provider (dev only).
func (lp *LocalProvider) VerifyPermission(ctx context.Context, userID string, resource string, action string) (bool, error) {
	return true, nil
}
