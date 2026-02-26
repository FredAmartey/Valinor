package tenant

import (
	"errors"
	"time"
)

var (
	ErrRoleNotFound   = errors.New("role not found")
	ErrRoleNameEmpty  = errors.New("role name is required")
	ErrRoleDuplicate  = errors.New("role name already exists in tenant")
	ErrRoleIsSystem   = errors.New("system roles cannot be modified")
	ErrRoleHasUsers   = errors.New("role is assigned to users")
	ErrWildcardDenied = errors.New("wildcard permission not allowed for custom roles")
)

// Role represents a role within a tenant.
type Role struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"tenant_id"`
	Name        string    `json:"name"`
	Permissions []string  `json:"permissions"`
	IsSystem    bool      `json:"is_system"`
	CreatedAt   time.Time `json:"created_at"`
}

// UserRole represents a role assignment for a user, scoped to an org or department.
type UserRole struct {
	UserID    string `json:"user_id"`
	RoleID    string `json:"role_id"`
	RoleName  string `json:"role_name"`
	ScopeType string `json:"scope_type"` // "org" or "department"
	ScopeID   string `json:"scope_id"`
}
