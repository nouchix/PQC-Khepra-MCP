// Layer 2: Authentication - Zero-Trust Identity Verification
// "The Eye of Horus Sees All"
package gateway

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/EtherVerseCodeMate/giza-cyber-shield/pkg/adinkra"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/argon2"
)

// AuthLayer implements Layer 2 zero-trust authentication
type AuthLayer struct {
	config *AuthConfig

	// Certificate Authority for mTLS
	clientCAs *x509.CertPool

	// API Key store (in production, this would be backed by a database)
	apiKeys   map[string]*APIKeyEntry
	apiKeysMu sync.RWMutex

	// JWT signing key
	jwtKey []byte

	// Public key registry cache (for PQC signature verification)
	publicKeys   map[string][]byte
	publicKeysMu sync.RWMutex
}

// APIKeyEntry represents a stored API key with metadata
type APIKeyEntry struct {
	KeyHash      string
	Organization string
	TrustScore   float64
	Permissions  []string
	CreatedAt    time.Time
	ExpiresAt    time.Time
	LastUsed     time.Time
	Revoked      bool
}

// NewAuthLayer creates a new authentication layer
func NewAuthLayer(cfg *AuthConfig) (*AuthLayer, error) {
	auth := &AuthLayer{
		config:     cfg,
		apiKeys:    make(map[string]*APIKeyEntry),
		publicKeys: make(map[string][]byte),
	}

	// Load Client CA for mTLS if configured
	if cfg.RequireMTLS && cfg.ClientCAFile != "" {
		pool, err := loadCertPool(cfg.ClientCAFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load client CA: %w", err)
		}
		auth.clientCAs = pool
		log.Printf("[AUTH] mTLS enabled with client CA: %s", cfg.ClientCAFile)
	}

	// Initialize JWT key
	if cfg.JWTSecret != "" {
		auth.jwtKey = []byte(cfg.JWTSecret)
	}

	log.Printf("[AUTH] Layer 2 initialized - mTLS[%v] PQC[%v] APIKey[%s]",
		cfg.RequireMTLS, cfg.RequirePQCSignature, cfg.APIKeyHeader)

	return auth, nil
}

// Authenticate performs multi-factor authentication on the request
func (auth *AuthLayer) Authenticate(r *http.Request) (*Identity, error) {
	// Priority 1: mTLS
	if identity, err := auth.authenticateMTLS(r); err == nil {
		return auth.finalizeIdentity(r, identity, "mTLS")
	} else if auth.config.RequireMTLS {
		return nil, err
	}

	// Priority 2: API Key Header
	if identity, err := auth.authenticateAPIKeyHeader(r); err == nil {
		return auth.finalizeIdentity(r, identity, "API-Key")
	}

	// Priority 3: Bearer Token
	if identity, err := auth.authenticateBearer(r); err == nil {
		return auth.finalizeIdentity(r, identity, identity.Type)
	}

	// Priority 4: Enrollment
	if identity, err := auth.authenticateEnrollment(r); err == nil {
		return auth.finalizeIdentity(r, identity, "Enrollment-Token")
	}

	return nil, errors.New("no valid authentication provided")
}

func (auth *AuthLayer) authenticateMTLS(r *http.Request) (*Identity, error) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return nil, errors.New("no certificate")
	}
	cert := r.TLS.PeerCertificates[0]

	if auth.clientCAs != nil {
		opts := x509.VerifyOptions{Roots: auth.clientCAs, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
		if _, err := cert.Verify(opts); err != nil {
			return nil, err
		}
	}

	return &Identity{
		ID: cert.Subject.CommonName, Type: "mtls", Organization: getOrgFromCert(cert), TrustScore: 1.0,
		Metadata: map[string]string{"cert_serial": cert.SerialNumber.String()},
	}, nil
}

func (auth *AuthLayer) authenticateAPIKeyHeader(r *http.Request) (*Identity, error) {
	apiKey := r.Header.Get(auth.config.APIKeyHeader)
	if apiKey == "" {
		return nil, errors.New("no api key")
	}
	return auth.identityFromAPIKey(apiKey)
}

func (auth *AuthLayer) authenticateBearer(r *http.Request) (*Identity, error) {
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return nil, errors.New("no bearer")
	}
	token := strings.TrimPrefix(authHeader, "Bearer ")

	if auth.jwtKey != nil {
		if claims, err := auth.validateJWT(token); err == nil {
			return &Identity{ID: claims.Subject, Type: "jwt", Organization: claims.Issuer, TrustScore: 0.8}, nil
		}
	}
	return auth.identityFromAPIKey(token)
}

func (auth *AuthLayer) authenticateEnrollment(r *http.Request) (*Identity, error) {
	token := r.Header.Get(auth.config.EnrollmentTokenHeader)
	if token == "" {
		return nil, errors.New("no enrollment token")
	}
	return &Identity{ID: "enrolling-" + token[:8], Type: "enrollment", TrustScore: 0.3, Permissions: []string{"register"}}, nil
}

func (auth *AuthLayer) identityFromAPIKey(token string) (*Identity, error) {
	entry, err := auth.validateAPIKey(token)
	if err != nil {
		return nil, err
	}
	return &Identity{
		ID: hashAPIKey(token)[:16], Type: "api_key", Organization: entry.Organization,
		TrustScore: entry.TrustScore, Permissions: entry.Permissions,
	}, nil
}

func (auth *AuthLayer) finalizeIdentity(r *http.Request, identity *Identity, method string) (*Identity, error) {
	if auth.config.RequirePQCSignature {
		sig := r.Header.Get(auth.config.SignatureHeader)
		if sig == "" {
			return nil, errors.New("PQC signature required")
		}
		if err := auth.verifyPQCSignature(r, identity.ID, sig); err != nil {
			return nil, err
		}
		identity.TrustScore = min(identity.TrustScore+0.2, 1.0)
		if identity.Metadata == nil {
			identity.Metadata = make(map[string]string)
		}
		identity.Metadata["pqc_verified"] = "true"
	}

	log.Printf("[AUTH] Authenticated: %s via %s", identity.ID, method)
	return identity, nil
}

// validateAPIKey validates an API key against the store
func (auth *AuthLayer) validateAPIKey(key string) (*APIKeyEntry, error) {
	keyHash := hashAPIKey(key)

	auth.apiKeysMu.RLock()
	entry, exists := auth.apiKeys[keyHash]
	auth.apiKeysMu.RUnlock()

	if !exists {
		return nil, errors.New("invalid API key")
	}

	if entry.Revoked {
		return nil, errors.New("API key revoked")
	}

	if time.Now().After(entry.ExpiresAt) {
		return nil, errors.New("API key expired")
	}

	return entry, nil
}

// validateJWT validates a JWT token
func (auth *AuthLayer) validateJWT(tokenString string) (*jwt.RegisteredClaims, error) {
	if auth.jwtKey == nil {
		return nil, errors.New("JWT authentication not configured")
	}

	token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return auth.jwtKey, nil
	})

	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*jwt.RegisteredClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token claims")
	}

	return claims, auth.verifyJWTClaims(claims)
}

func (auth *AuthLayer) verifyJWTClaims(claims *jwt.RegisteredClaims) error {
	if auth.config.JWTIssuer != "" && claims.Issuer != auth.config.JWTIssuer {
		return errors.New("invalid token issuer")
	}

	if auth.config.JWTAudience != "" {
		validAudience := false
		for _, aud := range claims.Audience {
			if aud == auth.config.JWTAudience {
				validAudience = true
				break
			}
		}
		if !validAudience {
			return errors.New("invalid token audience")
		}
	}
	return nil
}

func (auth *AuthLayer) verifyPQCSignature(r *http.Request, identityID, signatureHex string) error {
	auth.publicKeysMu.RLock()
	pubKeyBytes, exists := auth.publicKeys[identityID]
	auth.publicKeysMu.RUnlock()

	if !exists {
		return errors.New("public key not found for identity")
	}

	signature, err := hex.DecodeString(signatureHex)
	if err != nil {
		return errors.New("invalid signature encoding")
	}

	timestamp := r.Header.Get("X-Khepra-Timestamp")
	message := fmt.Sprintf("%s|%s|%s", r.Method, r.URL.Path, timestamp)
	return auth.runMLDSAVerify(pubKeyBytes, message, signature)
}

func (auth *AuthLayer) runMLDSAVerify(pubKeyBytes []byte, message string, signature []byte) error {
	if len(signature) != mldsa65.SignatureSize {
		return errors.New("invalid signature size")
	}
	if len(pubKeyBytes) != mldsa65.PublicKeySize {
		return errors.New("invalid public key size")
	}

	var pubKeyBuf [mldsa65.PublicKeySize]byte
	copy(pubKeyBuf[:], pubKeyBytes)

	var publicKey mldsa65.PublicKey
	publicKey.Unpack(&pubKeyBuf)

	if !mldsa65.Verify(&publicKey, []byte(message), nil, signature) {
		return errors.New("signature verification failed")
	}
	return nil
}

// RegisterAPIKey adds a new API key to the store
func (auth *AuthLayer) RegisterAPIKey(key string, org string, permissions []string, validDays int) error {
	keyHash := hashAPIKey(key)

	auth.apiKeysMu.Lock()
	defer auth.apiKeysMu.Unlock()

	auth.apiKeys[keyHash] = &APIKeyEntry{
		KeyHash:      keyHash,
		Organization: org,
		TrustScore:   0.7, // Default trust score
		Permissions:  permissions,
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().AddDate(0, 0, validDays),
		Revoked:      false,
	}

	log.Printf("[AUTH] Registered API key for org: %s (expires in %d days)", org, validDays)
	return nil
}

// RevokeAPIKey revokes an API key
func (auth *AuthLayer) RevokeAPIKey(keyHash string) error {
	auth.apiKeysMu.Lock()
	defer auth.apiKeysMu.Unlock()

	entry, exists := auth.apiKeys[keyHash]
	if !exists {
		return errors.New("API key not found")
	}

	entry.Revoked = true
	log.Printf("[AUTH] Revoked API key: %s", keyHash[:8])
	return nil
}

// RegisterPublicKey registers a public key for PQC signature verification
func (auth *AuthLayer) RegisterPublicKey(identityID string, pubKey []byte) error {
	if len(pubKey) != mldsa65.PublicKeySize {
		return errors.New("invalid public key size")
	}

	auth.publicKeysMu.Lock()
	defer auth.publicKeysMu.Unlock()

	auth.publicKeys[identityID] = pubKey
	log.Printf("[AUTH] Registered PQC public key for: %s", identityID)
	return nil
}

// GenerateJWT generates a JWT token for an identity
func (auth *AuthLayer) GenerateJWT(identity *Identity) (string, error) {
	if auth.jwtKey == nil {
		return "", errors.New("JWT not configured")
	}

	claims := jwt.RegisteredClaims{
		Subject:   identity.ID,
		Issuer:    auth.config.JWTIssuer,
		Audience:  jwt.ClaimStrings{auth.config.JWTAudience},
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(auth.config.JWTMaxAge)),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(auth.jwtKey)
}

// Helper functions

func loadCertPool(caFile string) (*x509.CertPool, error) {
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}

	pool := x509.NewCertPool()
	block, _ := pem.Decode(caPEM)
	if block == nil {
		return nil, errors.New("failed to decode PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	pool.AddCert(cert)
	return pool, nil
}

func getOrgFromCert(cert *x509.Certificate) string {
	if len(cert.Subject.Organization) > 0 {
		return cert.Subject.Organization[0]
	}
	return cert.Subject.CommonName
}

// hashAPIKey returns a secure Argon2id hash of the API key.
// Uses OWASP-recommended parameters for key derivation.
func hashAPIKey(key string) string {
	// Use a deterministic salt derived from the key itself for lookup purposes
	// (In a full implementation, store the salt alongside the hash)
	salt := adinkra.Hash([]byte("khepra-api-key-salt:" + key))
	// Argon2id parameters per OWASP guidelines: time=1, memory=64MB, threads=4, keyLen=32
	hash := argon2.IDKey([]byte(key), []byte(salt), 1, 64*1024, 4, 32)
	return hex.EncodeToString(hash)
}

func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
