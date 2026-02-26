package rbac

import (
	"context"
	"fmt"
	"sync"

	"github.com/valinor-ai/valinor/internal/auth"
)

// Store defines the database interface for RBAC (for loading resource policies).
type Store interface {
	GetResourcePolicies(ctx context.Context, subjectType string, subjectID string, action string, resourceType string, resourceID string) ([]ResourcePolicy, error)
}

// ResourcePolicy represents a fine-grained resource-level policy.
type ResourcePolicy struct {
	Effect       string // "allow" or "deny"
	Action       string
	ResourceType string
	ResourceID   string
}

// RoleDef is a role name with its permission strings, used by RoleLoader.
type RoleDef struct {
	TenantID    string
	Name        string
	Permissions []string
}

// RoleLoader loads role definitions from a backing store.
type RoleLoader interface {
	LoadRoles(ctx context.Context) ([]RoleDef, error)
}

// EvaluatorOption configures the Evaluator.
type EvaluatorOption func(*Evaluator)

// WithRoleLoader sets a RoleLoader for DB-backed role loading.
func WithRoleLoader(loader RoleLoader) EvaluatorOption {
	return func(e *Evaluator) {
		e.loader = loader
	}
}

// Evaluator is the in-memory RBAC policy evaluation engine.
type Evaluator struct {
	store  Store // can be nil for unit testing
	loader RoleLoader
	roles  map[string]map[string][]string // tenantID → roleName → permissions
	mu     sync.RWMutex
}

func NewEvaluator(store Store, opts ...EvaluatorOption) *Evaluator {
	e := &Evaluator{
		store: store,
		roles: make(map[string]map[string][]string),
	}
	for _, opt := range opts {
		opt(e)
	}
	return e
}

// ReloadRoles loads roles from the RoleLoader and replaces the in-memory map.
// If loading fails, the existing map is preserved.
func (e *Evaluator) ReloadRoles(ctx context.Context) error {
	if e.loader == nil {
		return fmt.Errorf("no role loader configured")
	}

	defs, err := e.loader.LoadRoles(ctx)
	if err != nil {
		return fmt.Errorf("loading roles: %w", err)
	}

	newRoles := make(map[string]map[string][]string)
	for _, d := range defs {
		tenant := newRoles[d.TenantID]
		if tenant == nil {
			tenant = make(map[string][]string)
			newRoles[d.TenantID] = tenant
		}
		tenant[d.Name] = d.Permissions
	}

	e.mu.Lock()
	e.roles = newRoles
	e.mu.Unlock()

	return nil
}

// RegisterRole adds a role with its permissions to the in-memory cache for a tenant.
func (e *Evaluator) RegisterRole(tenantID, name string, permissions []string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	tenant := e.roles[tenantID]
	if tenant == nil {
		tenant = make(map[string][]string)
		e.roles[tenantID] = tenant
	}
	tenant[name] = permissions
}

// Authorize checks if the identity has the required permission.
// Evaluation order: deny-by-default -> role permissions -> resource policies.
func (e *Evaluator) Authorize(ctx context.Context, identity *auth.Identity, action string, resourceType string, resourceID string) (*Decision, error) {
	if identity == nil {
		return &Decision{Allowed: false, Reason: "no identity"}, nil
	}

	// Phase 1: Check role-based permissions
	if e.checkRolePermissions(identity.TenantID, identity.Roles, action) {
		// Phase 2: If resource specified, check resource policies for explicit deny
		if resourceType != "" && resourceID != "" && e.store != nil {
			denied, err := e.checkResourceDeny(ctx, identity, action, resourceType, resourceID)
			if err != nil {
				return nil, fmt.Errorf("checking resource policies: %w", err)
			}
			if denied {
				return &Decision{
					Allowed: false,
					Reason:  fmt.Sprintf("resource policy denies %s on %s/%s", action, resourceType, resourceID),
				}, nil
			}
		}
		return &Decision{Allowed: true}, nil
	}

	// Phase 3: If role check failed, check for explicit resource-level allow
	if resourceType != "" && resourceID != "" && e.store != nil {
		allowed, err := e.checkResourceAllow(ctx, identity, action, resourceType, resourceID)
		if err != nil {
			return nil, fmt.Errorf("checking resource policies: %w", err)
		}
		if allowed {
			return &Decision{Allowed: true}, nil
		}
	}

	return &Decision{
		Allowed: false,
		Reason:  fmt.Sprintf("no permission for %s", action),
	}, nil
}

func (e *Evaluator) checkRolePermissions(tenantID string, roles []string, action string) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()

	tenantRoles := e.roles[tenantID]
	if tenantRoles == nil {
		return false
	}

	for _, role := range roles {
		perms, ok := tenantRoles[role]
		if !ok {
			continue
		}
		for _, perm := range perms {
			if perm == "*" || perm == action {
				return true
			}
		}
	}
	return false
}

func (e *Evaluator) checkResourceDeny(ctx context.Context, identity *auth.Identity, action, resourceType, resourceID string) (bool, error) {
	policies, err := e.store.GetResourcePolicies(ctx, "user", identity.UserID, action, resourceType, resourceID)
	if err != nil {
		return false, err
	}

	for _, p := range policies {
		if p.Effect == "deny" {
			return true, nil
		}
	}
	return false, nil
}

func (e *Evaluator) checkResourceAllow(ctx context.Context, identity *auth.Identity, action, resourceType, resourceID string) (bool, error) {
	policies, err := e.store.GetResourcePolicies(ctx, "user", identity.UserID, action, resourceType, resourceID)
	if err != nil {
		return false, err
	}

	for _, p := range policies {
		if p.Effect == "allow" {
			return true, nil
		}
	}
	return false, nil
}
