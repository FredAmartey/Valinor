package rbac

import (
	"context"

	"github.com/valinor-ai/valinor/internal/auth"
)

// Decision represents the result of an authorization check.
type Decision struct {
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason,omitempty"`
}

// PolicyEngine defines the authorization interface.
type PolicyEngine interface {
	// Authorize checks if the identity has permission to perform the action
	// on the given resource. resourceType and resourceID can be empty for
	// broad permission checks.
	Authorize(ctx context.Context, identity *auth.Identity, action string, resourceType string, resourceID string) (*Decision, error)
}
