package souhimbou

import (
	"fmt"
	"time"
)

// Role definitions for RBAC
type Role string

const (
	RoleViewer   Role = "viewer"
	RoleOperator Role = "operator"
	RoleAdmin    Role = "admin"
)

// User represents an authenticated entity in SouHimBou
type User struct {
	ID    string
	Email string
	Role  Role
}

// Command represents an action requested by a user
type Command struct {
	Action       string
	Target       string
	RequiredRole Role
}

// AuthorizationError indicates a permission failure
type AuthorizationError struct {
	User     string
	Role     Role
	Required Role
}

func (e *AuthorizationError) Error() string {
	return fmt.Sprintf("access denied for user %s (role: %s): requires %s", e.User, e.Role, e.Required)
}

// Authorize verifies if a user has sufficient permissions for a command
func Authorize(user *User, cmd *Command) error {
	if !hasPermission(user.Role, cmd.RequiredRole) {
		// Log this security event!
		// log.Printf("[SECURITY] Unauthorized access attempt by %s on %s", user.Email, cmd.Action)
		return &AuthorizationError{
			User:     user.Email,
			Role:     user.Role,
			Required: cmd.RequiredRole,
		}
	}
	return nil
}

// hasPermission checks role hierarchy (Admin > Operator > Viewer)
func hasPermission(userRole, requiredRole Role) bool {
	if userRole == RoleAdmin {
		return true
	}
	if userRole == RoleOperator && (requiredRole == RoleOperator || requiredRole == RoleViewer) {
		return true
	}
	if userRole == RoleViewer && requiredRole == RoleViewer {
		return true
	}
	return false
}

// AuditLogEntry represents a recorded action
type AuditLogEntry struct {
	Timestamp time.Time
	UserEmail string
	Action    string
	Success   bool
}
