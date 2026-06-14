package auth

import (
	"context"
	"encoding/hex"
	"testing"
	"time"

	"golang.org/x/crypto/argon2"
)

const (
	testRoleName    = "test-role"
	superReaderName = "super-reader"
	dagAdminName    = "dag-admin"
	testUserID      = "user-123"
)

func TestNewAuthManager(t *testing.T) {
	am := NewAuthManager()
	if am == nil {
		t.Fatal("expected non-nil AuthManager")
	}
	if am.providers == nil {
		t.Error("expected initialized providers map")
	}
}

func TestAuthManagerRegisterProvider(t *testing.T) {
	am := NewAuthManager()
	provider := NewLocalProvider()

	err := am.RegisterProvider(ProviderLocal, provider)
	if err != nil {
		t.Fatalf("RegisterProvider failed: %v", err)
	}

	// Test registering nil provider
	err = am.RegisterProvider(ProviderKeycloak, nil)
	if err == nil {
		t.Error("expected error when registering nil provider")
	}
}

func TestAuthManagerSetDefault(t *testing.T) {
	am := NewAuthManager()
	provider := NewLocalProvider()

	// Register provider first
	am.RegisterProvider(ProviderLocal, provider)

	// Set default
	err := am.SetDefault(ProviderLocal)
	if err != nil {
		t.Fatalf("SetDefault failed: %v", err)
	}

	// Try to set non-existent provider as default
	err = am.SetDefault(ProviderKeycloak)
	if err == nil {
		t.Error("expected error when setting non-existent provider as default")
	}
}

func TestPermissionEvaluator(t *testing.T) {
	pe := NewPermissionEvaluator()

	// Define test role
	role := &Role{
		Name: testRoleName,
		Permissions: []Permission{
			{Resource: "dag", Action: "read"},
			{Resource: "scan", Action: "write"},
		},
	}

	err := pe.DefineRole(role)
	if err != nil {
		t.Fatalf("DefineRole failed: %v", err)
	}

	// Test valid permission
	if !pe.Evaluate([]string{testRoleName}, "dag", "read") {
		t.Error("expected permission to be granted for dag:read")
	}

	// Test invalid permission
	if pe.Evaluate([]string{testRoleName}, "dag", "delete") {
		t.Error("expected permission to be denied for dag:delete")
	}
}

func TestPermissionEvaluatorWildcards(t *testing.T) {
	pe := NewPermissionEvaluator()

	// Role with wildcard resource
	superReaderRole := &Role{
		Name: superReaderName,
		Permissions: []Permission{
			{Resource: "*", Action: "read"},
		},
	}
	pe.DefineRole(superReaderRole)

	// Should match any resource with read action
	if !pe.Evaluate([]string{superReaderName}, "dag", "read") {
		t.Error("expected wildcard resource permission to match dag:read")
	}
	if !pe.Evaluate([]string{superReaderName}, "scan", "read") {
		t.Error("expected wildcard resource permission to match scan:read")
	}

	// Should NOT match write action
	if pe.Evaluate([]string{superReaderName}, "dag", "write") {
		t.Error("expected wildcard resource permission to NOT match dag:write")
	}

	// Role with wildcard action
	dagAdminRole := &Role{
		Name: dagAdminName,
		Permissions: []Permission{
			{Resource: "dag", Action: "*"},
		},
	}
	pe.DefineRole(dagAdminRole)

	// Should match any action on dag resource
	if !pe.Evaluate([]string{dagAdminName}, "dag", "read") {
		t.Error("expected wildcard action permission to match dag:read")
	}
	if !pe.Evaluate([]string{dagAdminName}, "dag", "delete") {
		t.Error("expected wildcard action permission to match dag:delete")
	}

	// Should NOT match other resources
	if pe.Evaluate([]string{dagAdminName}, "scan", "read") {
		t.Error("expected wildcard action permission to NOT match scan:read")
	}
}

func TestSessionManager(t *testing.T) {
	sm := NewSessionManager()

	user := &User{
		ID:       testUserID,
		Username: "testuser",
		Email:    "test@example.com",
	}

	// Create session
	session, err := sm.CreateSession(user, []string{"admin"}, 1*time.Hour)
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	if session.UserID != testUserID {
		t.Errorf("expected UserID %s, got %s", testUserID, session.UserID)
	}

	// Get session
	retrieved, err := sm.GetSession(session.SessionID)
	if err != nil {
		t.Fatalf("GetSession failed: %v", err)
	}
	if retrieved.SessionID != session.SessionID {
		t.Error("retrieved session mismatch")
	}

	// Invalidate session
	sm.InvalidateSession(session.SessionID)

	_, err = sm.GetSession(session.SessionID)
	if err == nil {
		t.Error("expected error getting invalidated session")
	}
}

func TestSessionIsValid(t *testing.T) {
	// Valid session
	validSession := &Session{
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}
	if !validSession.IsValid() {
		t.Error("expected session to be valid")
	}

	// Expired session
	expiredSession := &Session{
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	}
	if expiredSession.IsValid() {
		t.Error("expected session to be invalid")
	}
}

func TestTokenClaims(t *testing.T) {
	claims := &TokenClaims{
		Subject:        "user-123",
		Roles:          []string{"admin", "operator"},
		ExpirationTime: time.Now().Add(1 * time.Hour),
		Permissions: []Permission{
			{Resource: "dag", Action: "read"},
		},
	}

	// Test not expired
	if claims.IsExpired() {
		t.Error("expected claims to not be expired")
	}

	// Test HasRole
	if !claims.HasRole("admin") {
		t.Error("expected to have admin role")
	}
	if claims.HasRole("unknown") {
		t.Error("expected to not have unknown role")
	}

	// Test HasPermission
	if !claims.HasPermission("dag", "read") {
		t.Error("expected to have dag:read permission")
	}
	if claims.HasPermission("dag", "write") {
		t.Error("expected to not have dag:write permission")
	}
}

func TestLocalProvider(t *testing.T) {
	lp := NewLocalProvider()

	ctx := context.Background()

	// Create user
	// For local provider, we compute the hash dynamically to ensure it matches
	salt := "khepra-local-salt"
	computed := argon2.IDKey([]byte("password123"), []byte(salt), 1, 64*1024, 4, 32)
	passwordHash := hex.EncodeToString(computed)

	user := &User{
		ID:       "user-123",
		Username: "testuser",
		Email:    "test@example.com",
		Attributes: map[string]interface{}{
			"password_hash": passwordHash,
		},
	}

	err := lp.CreateUser(ctx, user)
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	// Authenticate
	creds := &Credentials{
		Username: "testuser",
		Password: "password123",
	}

	authUser, err := lp.Authenticate(ctx, creds)
	if err != nil {
		t.Fatalf("Authenticate failed: %v", err)
	}
	if authUser.Username != user.Username {
		t.Error("authenticated user mismatch")
	}

	// List users
	users, err := lp.ListUsers(ctx)
	if err != nil {
		t.Fatalf("ListUsers failed: %v", err)
	}
	if len(users) != 1 {
		t.Errorf("expected 1 user, got %d", len(users))
	}

	// Assign role
	err = lp.AssignRole(ctx, user.ID, "admin")
	if err != nil {
		t.Fatalf("AssignRole failed: %v", err)
	}

	// Verify role assigned
	updatedUser, _ := lp.GetUser(ctx, user.ID)
	if len(updatedUser.Roles) != 1 || updatedUser.Roles[0] != "admin" {
		t.Error("role not assigned correctly")
	}

	// Revoke role
	err = lp.RevokeRole(ctx, user.ID, "admin")
	if err != nil {
		t.Fatalf("RevokeRole failed: %v", err)
	}

	// Delete user
	err = lp.DeleteUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("DeleteUser failed: %v", err)
	}

	users, _ = lp.ListUsers(ctx)
	if len(users) != 0 {
		t.Error("expected no users after deletion")
	}
}

func TestPredefinedRoles(t *testing.T) {
	// Verify predefined roles exist
	expectedRoles := []string{"admin", "compliance-officer", "security-engineer", "operator", "viewer"}

	for _, roleName := range expectedRoles {
		role, exists := PredefinedRoles[roleName]
		if !exists {
			t.Errorf("missing predefined role: %s", roleName)
			continue
		}
		if role.Name != roleName {
			t.Errorf("role name mismatch for %s", roleName)
		}
		if len(role.Permissions) == 0 {
			t.Errorf("role %s has no permissions", roleName)
		}
	}

	// Verify admin has wildcard permission
	adminRole := PredefinedRoles["admin"]
	if len(adminRole.Permissions) != 1 || adminRole.Permissions[0].Resource != "*" {
		t.Error("admin role should have wildcard permission")
	}
}

func TestBaseAuthProvider(t *testing.T) {
	base := &BaseAuthProvider{
		name: "test-provider",
	}

	if base.GetName() != "test-provider" {
		t.Errorf("expected name 'test-provider', got '%s'", base.GetName())
	}

	// Close should return nil
	if err := base.Close(); err != nil {
		t.Errorf("Close returned error: %v", err)
	}
}
