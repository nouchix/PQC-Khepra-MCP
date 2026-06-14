package auth

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"time"
)

// Provider represents authentication provider types.
type Provider string

const (
	ProviderKeycloak Provider = "keycloak"
	ProviderOkta     Provider = "okta"
	ProviderCAC      Provider = "cac" // DoD CAC (Common Access Card)
	ProviderAzureAD  Provider = "azure-ad"
	ProviderGoogle   Provider = "google"
	ProviderLocal    Provider = "local" // Local credential store (dev only)
)

// User represents an authenticated user with role/permission data.
type User struct {
	ID            string
	Username      string
	Email         string
	FirstName     string
	LastName      string
	Organizations []string
	Roles         []string
	Groups        []string
	Attributes    map[string]interface{}
	ExpiresAt     time.Time
}

// Credentials represents authentication credentials.
type Credentials struct {
	Username      string
	Password      string
	Token         string
	ClientID      string
	ClientSecret  string
	SAMLAssertion string
	CertPath      string
	KeyPath       string
}

// AuthProvider defines the interface for authentication adapters.
type AuthProvider interface {
	// Authenticate verifies credentials and returns a User.
	Authenticate(ctx context.Context, creds *Credentials) (*User, error)

	// RefreshToken refreshes an expired token/session.
	RefreshToken(ctx context.Context, refreshToken string) (string, error)

	// ValidateToken checks if a token is still valid.
	ValidateToken(ctx context.Context, token string) (bool, error)

	// GetUser retrieves user information by ID.
	GetUser(ctx context.Context, userID string) (*User, error)

	// ListUsers lists all users in the provider.
	ListUsers(ctx context.Context) ([]*User, error)

	// CreateUser creates a new user account.
	CreateUser(ctx context.Context, user *User) error

	// DeleteUser removes a user account.
	DeleteUser(ctx context.Context, userID string) error

	// UpdateUser modifies user information.
	UpdateUser(ctx context.Context, user *User) error

	// AssignRole grants a role to a user.
	AssignRole(ctx context.Context, userID string, role string) error

	// RevokeRole removes a role from a user.
	RevokeRole(ctx context.Context, userID string, role string) error

	// VerifyPermission checks if user has required permission.
	VerifyPermission(ctx context.Context, userID string, resource string, action string) (bool, error)

	// GetName returns the provider name.
	GetName() string

	// Close closes the provider connection.
	Close() error
}

// AuthManager manages multiple authentication providers.
type AuthManager struct {
	providers        map[Provider]AuthProvider
	default_provider Provider
}

// NewAuthManager creates a new authentication manager.
func NewAuthManager() *AuthManager {
	return &AuthManager{
		providers: make(map[Provider]AuthProvider),
	}
}

// RegisterProvider registers an authentication provider.
func (am *AuthManager) RegisterProvider(p Provider, provider AuthProvider) error {
	if provider == nil {
		return errors.New("provider cannot be nil")
	}
	am.providers[p] = provider
	return nil
}

// SetDefault sets the default authentication provider.
func (am *AuthManager) SetDefault(p Provider) error {
	if _, exists := am.providers[p]; !exists {
		return fmt.Errorf("provider %s not registered", p)
	}
	am.default_provider = p
	return nil
}

// Authenticate authenticates against the default provider.
func (am *AuthManager) Authenticate(ctx context.Context, creds *Credentials) (*User, error) {
	provider, exists := am.providers[am.default_provider]
	if !exists {
		return nil, fmt.Errorf("default provider %s not configured", am.default_provider)
	}
	return provider.Authenticate(ctx, creds)
}

// AuthenticateWith authenticates against a specific provider.
func (am *AuthManager) AuthenticateWith(ctx context.Context, p Provider, creds *Credentials) (*User, error) {
	provider, exists := am.providers[p]
	if !exists {
		return nil, fmt.Errorf("provider %s not registered", p)
	}
	return provider.Authenticate(ctx, creds)
}

// ValidateToken validates a token across all providers.
func (am *AuthManager) ValidateToken(ctx context.Context, token string) (bool, error) {
	for _, provider := range am.providers {
		valid, err := provider.ValidateToken(ctx, token)
		if err == nil && valid {
			return true, nil
		}
	}
	return false, nil
}

// Close closes all providers.
func (am *AuthManager) Close() error {
	var lastErr error
	for _, provider := range am.providers {
		if err := provider.Close(); err != nil {
			lastErr = err
		}
	}
	return lastErr
}

// ============================================================================
// Base Implementation (Common Methods)
// ============================================================================

// BaseAuthProvider provides common functionality for auth adapters.
type BaseAuthProvider struct {
	name string
}

// GetName returns the provider name.
func (b *BaseAuthProvider) GetName() string {
	return b.name
}

// Close is a no-op for base implementation.
func (b *BaseAuthProvider) Close() error {
	return nil
}

// ============================================================================
// Authorization Helper Types
// ============================================================================

// Permission represents a specific permission.
type Permission struct {
	Resource string // e.g., "dag", "attest", "scan"
	Action   string // e.g., "read", "write", "delete"
}

// Role represents a role with associated permissions.
type Role struct {
	Name        string
	Description string
	Permissions []Permission
}

// PermissionEvaluator evaluates permissions based on roles.
type PermissionEvaluator struct {
	roles map[string]*Role
}

// NewPermissionEvaluator creates a new permission evaluator.
func NewPermissionEvaluator() *PermissionEvaluator {
	return &PermissionEvaluator{
		roles: make(map[string]*Role),
	}
}

// DefineRole adds a role definition.
func (pe *PermissionEvaluator) DefineRole(role *Role) error {
	if role.Name == "" {
		return errors.New("role name cannot be empty")
	}
	pe.roles[role.Name] = role
	return nil
}

// Evaluate checks if a user with given roles can perform an action on a resource.
func (pe *PermissionEvaluator) Evaluate(userRoles []string, resource string, action string) bool {
	for _, roleName := range userRoles {
		role, exists := pe.roles[roleName]
		if !exists {
			continue
		}

		for _, perm := range role.Permissions {
			if (perm.Resource == resource || perm.Resource == "*") && (perm.Action == action || perm.Action == "*") {
				return true
			}
		}
	}
	return false
}

// ============================================================================
// Predefined Roles for ADINKHEPRA
// ============================================================================

var PredefinedRoles = map[string]*Role{
	"admin": {
		Name:        "admin",
		Description: "Full system access",
		Permissions: []Permission{
			{Resource: "*", Action: "*"},
		},
	},
	"compliance-officer": {
		Name:        "compliance-officer",
		Description: "Compliance auditing and reporting",
		Permissions: []Permission{
			{Resource: "attest", Action: "read"},
			{Resource: "attest", Action: "write"},
			{Resource: "stig", Action: "read"},
			{Resource: "compliance", Action: "read"},
			{Resource: "compliance", Action: "write"},
			{Resource: "report", Action: "read"},
		},
	},
	"security-engineer": {
		Name:        "security-engineer",
		Description: "Security scanning and vulnerability management",
		Permissions: []Permission{
			{Resource: "scan", Action: "read"},
			{Resource: "scan", Action: "write"},
			{Resource: "vuln", Action: "read"},
			{Resource: "dag", Action: "read"},
			{Resource: "remediation", Action: "write"},
		},
	},
	"operator": {
		Name:        "operator",
		Description: "System operation and monitoring",
		Permissions: []Permission{
			{Resource: "dag", Action: "read"},
			{Resource: "scan", Action: "read"},
			{Resource: "attest", Action: "read"},
			{Resource: "report", Action: "read"},
		},
	},
	"viewer": {
		Name:        "viewer",
		Description: "Read-only access",
		Permissions: []Permission{
			{Resource: "dag", Action: "read"},
			{Resource: "attest", Action: "read"},
			{Resource: "report", Action: "read"},
		},
	},
}

// ============================================================================
// Token Helper Utilities
// ============================================================================

// TokenClaims represents standard JWT claims.
type TokenClaims struct {
	Subject          string
	Issuer           string
	Audience         []string
	ExpirationTime   time.Time
	IssuedAt         time.Time
	NotBefore        time.Time
	ID               string
	Roles            []string
	Permissions      []Permission
	CustomAttributes map[string]interface{}
}

// IsExpired checks if the token claims have expired.
func (tc *TokenClaims) IsExpired() bool {
	return time.Now().After(tc.ExpirationTime)
}

// HasRole checks if the claims include a specific role.
func (tc *TokenClaims) HasRole(role string) bool {
	for _, r := range tc.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// HasPermission checks if the claims include a specific permission.
func (tc *TokenClaims) HasPermission(resource string, action string) bool {
	for _, perm := range tc.Permissions {
		if perm.Resource == resource && perm.Action == action {
			return true
		}
	}
	return false
}

// ============================================================================
// Session Management
// ============================================================================

// Session represents an authenticated user session.
type Session struct {
	SessionID    string
	UserID       string
	Username     string
	Roles        []string
	Permissions  []Permission
	CreatedAt    time.Time
	LastActivity time.Time
	ExpiresAt    time.Time
	Metadata     map[string]interface{}
}

// IsValid checks if the session is still active.
func (s *Session) IsValid() bool {
	return time.Now().Before(s.ExpiresAt)
}

// SessionManager manages user sessions.
type SessionManager struct {
	sessions map[string]*Session
}

// NewSessionManager creates a new session manager.
func NewSessionManager() *SessionManager {
	return &SessionManager{
		sessions: make(map[string]*Session),
	}
}

// CreateSession creates a new user session.
func (sm *SessionManager) CreateSession(user *User, roles []string, ttl time.Duration) (*Session, error) {
	session := &Session{
		SessionID:    generateSessionID(),
		UserID:       user.ID,
		Username:     user.Username,
		Roles:        roles,
		CreatedAt:    time.Now(),
		LastActivity: time.Now(),
		ExpiresAt:    time.Now().Add(ttl),
	}

	sm.sessions[session.SessionID] = session
	return session, nil
}

// GetSession retrieves a session by ID.
func (sm *SessionManager) GetSession(sessionID string) (*Session, error) {
	session, exists := sm.sessions[sessionID]
	if !exists {
		return nil, errors.New("session not found")
	}

	if !session.IsValid() {
		delete(sm.sessions, sessionID)
		return nil, errors.New("session expired")
	}

	// Update last activity
	session.LastActivity = time.Now()
	return session, nil
}

// InvalidateSession closes a session.
func (sm *SessionManager) InvalidateSession(sessionID string) error {
	delete(sm.sessions, sessionID)
	return nil
}

// generateSessionID creates a cryptographically secure session identifier
func generateSessionID() string {
	b := make([]byte, 32) // 256-bit entropy
	if _, err := rand.Read(b); err != nil {
		// Fallback should never happen, but don't silently fail
		panic(fmt.Sprintf("crypto/rand failed: %v", err))
	}
	return fmt.Sprintf("khepra_session_%x", b)
}
