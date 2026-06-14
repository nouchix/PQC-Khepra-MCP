package gateway

import (
	"net/http/httptest"
	"testing"
	"time"
)

func TestAuthLayer_APIKeyAuthentication(t *testing.T) {
	cfg := &AuthConfig{
		APIKeyHeader: "X-Khepra-API-Key",
	}

	auth, err := NewAuthLayer(cfg)
	if err != nil {
		t.Fatalf("Failed to create auth layer: %v", err)
	}

	// Register a test API key
	testKey := "khepra-test-key-12345"
	err = auth.RegisterAPIKey(testKey, "test-org", []string{"read", "write"}, 30)
	if err != nil {
		t.Fatalf("Failed to register API key: %v", err)
	}

	tests := []struct {
		name      string
		apiKey    string
		expectErr bool
	}{
		{"Valid API key", testKey, false},
		{"Invalid API key", "invalid-key", true},
		{"Empty API key", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/api/test", nil)
			if tt.apiKey != "" {
				req.Header.Set("X-Khepra-API-Key", tt.apiKey)
			}

			identity, err := auth.Authenticate(req)
			if tt.expectErr {
				if err == nil {
					t.Error("Expected authentication error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if identity == nil {
					t.Error("Expected identity, got nil")
				}
				if identity != nil && identity.Type != "api_key" {
					t.Errorf("Expected identity type 'api_key', got '%s'", identity.Type)
				}
				if identity != nil && identity.Organization != "test-org" {
					t.Errorf("Expected organization 'test-org', got '%s'", identity.Organization)
				}
			}
		})
	}
}

func TestAuthLayer_APIKeyRevocation(t *testing.T) {
	cfg := &AuthConfig{
		APIKeyHeader: "X-Khepra-API-Key",
	}

	auth, err := NewAuthLayer(cfg)
	if err != nil {
		t.Fatalf("Failed to create auth layer: %v", err)
	}

	testKey := "khepra-revoke-test-key"
	keyHash := hashAPIKey(testKey)

	// Register and then revoke
	auth.RegisterAPIKey(testKey, "test-org", []string{"read"}, 30)
	auth.RevokeAPIKey(keyHash)

	req := httptest.NewRequest("GET", "/api/test", nil)
	req.Header.Set("X-Khepra-API-Key", testKey)

	_, err = auth.Authenticate(req)
	if err == nil {
		t.Error("Expected error for revoked key, got nil")
	}
}

func TestAuthLayer_BearerTokenAuthentication(t *testing.T) {
	cfg := &AuthConfig{
		APIKeyHeader: "X-Khepra-API-Key",
	}

	auth, err := NewAuthLayer(cfg)
	if err != nil {
		t.Fatalf("Failed to create auth layer: %v", err)
	}

	testKey := "khepra-bearer-test"
	auth.RegisterAPIKey(testKey, "bearer-org", []string{"read"}, 30)

	// Test with Bearer token in Authorization header
	req := httptest.NewRequest("GET", "/api/test", nil)
	req.Header.Set("Authorization", "Bearer "+testKey)

	identity, err := auth.Authenticate(req)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if identity == nil {
		t.Fatal("Expected identity, got nil")
	}
	if identity.Organization != "bearer-org" {
		t.Errorf("Expected organization 'bearer-org', got '%s'", identity.Organization)
	}
}

func TestAuthLayer_EnrollmentToken(t *testing.T) {
	cfg := &AuthConfig{
		EnrollmentTokenHeader: "X-Khepra-Enrollment-Token",
	}

	auth, err := NewAuthLayer(cfg)
	if err != nil {
		t.Fatalf("Failed to create auth layer: %v", err)
	}

	req := httptest.NewRequest("POST", "/license/register", nil)
	req.Header.Set("X-Khepra-Enrollment-Token", "khepra-enroll-test-abc123def456")

	identity, err := auth.Authenticate(req)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if identity == nil {
		t.Fatal("Expected identity, got nil")
	}
	if identity.Type != "enrollment" {
		t.Errorf("Expected type 'enrollment', got '%s'", identity.Type)
	}
	if identity.TrustScore != 0.3 {
		t.Errorf("Expected trust score 0.3, got %f", identity.TrustScore)
	}
	if len(identity.Permissions) != 1 || identity.Permissions[0] != "register" {
		t.Error("Expected permissions ['register']")
	}
}

func TestAuthLayer_JWTAuthentication(t *testing.T) {
	cfg := &AuthConfig{
		JWTSecret:   "test-secret-key-for-jwt-signing",
		JWTIssuer:   "khepra-gateway",
		JWTAudience: "khepra-services",
		JWTMaxAge:   24 * time.Hour,
	}

	auth, err := NewAuthLayer(cfg)
	if err != nil {
		t.Fatalf("Failed to create auth layer: %v", err)
	}

	// Generate a JWT token
	testIdentity := &Identity{
		ID:           "test-user-123",
		Organization: "jwt-org",
	}

	token, err := auth.GenerateJWT(testIdentity)
	if err != nil {
		t.Fatalf("Failed to generate JWT: %v", err)
	}

	// Authenticate with the token
	req := httptest.NewRequest("GET", "/api/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	identity, err := auth.Authenticate(req)
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if identity == nil {
		t.Fatal("Expected identity, got nil")
	}
	if identity.Type != "jwt" {
		t.Errorf("Expected type 'jwt', got '%s'", identity.Type)
	}
	if identity.ID != "test-user-123" {
		t.Errorf("Expected ID 'test-user-123', got '%s'", identity.ID)
	}
}

func TestAuthLayer_JWTInvalidToken(t *testing.T) {
	cfg := &AuthConfig{
		JWTSecret:   "test-secret-key",
		JWTIssuer:   "khepra-gateway",
		JWTAudience: "khepra-services",
	}

	auth, err := NewAuthLayer(cfg)
	if err != nil {
		t.Fatalf("Failed to create auth layer: %v", err)
	}

	tests := []struct {
		name  string
		token string
	}{
		{"Malformed token", "not-a-valid-jwt"},
		{"Wrong signature", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0In0.wrong"},
		{"Empty token", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/api/test", nil)
			if tt.token != "" {
				req.Header.Set("Authorization", "Bearer "+tt.token)
			}

			_, err := auth.Authenticate(req)
			if err == nil {
				t.Error("Expected error for invalid JWT, got nil")
			}
		})
	}
}

func TestAuthLayer_NoAuthentication(t *testing.T) {
	cfg := &AuthConfig{
		APIKeyHeader: "X-Khepra-API-Key",
	}

	auth, err := NewAuthLayer(cfg)
	if err != nil {
		t.Fatalf("Failed to create auth layer: %v", err)
	}

	// Request with no auth headers
	req := httptest.NewRequest("GET", "/api/test", nil)

	_, err = auth.Authenticate(req)
	if err == nil {
		t.Error("Expected error for unauthenticated request, got nil")
	}
}

func TestAuthLayer_PublicKeyRegistration(t *testing.T) {
	cfg := &AuthConfig{}

	auth, err := NewAuthLayer(cfg)
	if err != nil {
		t.Fatalf("Failed to create auth layer: %v", err)
	}

	// Test with invalid key size
	err = auth.RegisterPublicKey("test-id", []byte("too-short"))
	if err == nil {
		t.Error("Expected error for invalid public key size")
	}

	// Note: Valid ML-DSA-65 public key test would require actual key generation
}

func TestAuthLayer_TrustScores(t *testing.T) {
	cfg := &AuthConfig{
		APIKeyHeader: "X-Khepra-API-Key",
	}

	auth, err := NewAuthLayer(cfg)
	if err != nil {
		t.Fatalf("Failed to create auth layer: %v", err)
	}

	// Register API key with default trust score
	testKey := "khepra-trust-test"
	auth.RegisterAPIKey(testKey, "trust-org", []string{"read"}, 30)

	req := httptest.NewRequest("GET", "/api/test", nil)
	req.Header.Set("X-Khepra-API-Key", testKey)

	identity, _ := auth.Authenticate(req)
	if identity == nil {
		t.Fatal("Expected identity")
	}

	// Default trust score should be 0.7 for API keys
	if identity.TrustScore != 0.7 {
		t.Errorf("Expected trust score 0.7, got %f", identity.TrustScore)
	}
}

func BenchmarkAuthLayerAPIKey(b *testing.B) {
	cfg := &AuthConfig{
		APIKeyHeader: "X-Khepra-API-Key",
	}

	auth, _ := NewAuthLayer(cfg)
	testKey := "khepra-bench-key"
	auth.RegisterAPIKey(testKey, "bench-org", []string{"read"}, 30)

	req := httptest.NewRequest("GET", "/api/test", nil)
	req.Header.Set("X-Khepra-API-Key", testKey)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		auth.Authenticate(req)
	}
}

func BenchmarkAuthLayerJWT(b *testing.B) {
	cfg := &AuthConfig{
		JWTSecret:   "benchmark-secret-key",
		JWTIssuer:   "khepra-gateway",
		JWTAudience: "khepra-services",
		JWTMaxAge:   24 * time.Hour,
	}

	auth, _ := NewAuthLayer(cfg)
	identity := &Identity{ID: "bench-user"}
	token, _ := auth.GenerateJWT(identity)

	req := httptest.NewRequest("GET", "/api/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		auth.Authenticate(req)
	}
}
