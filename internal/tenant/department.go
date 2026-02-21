package tenant

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	ErrDepartmentNotFound  = errors.New("department not found")
	ErrDepartmentNameEmpty = errors.New("department name is required")
)

// Department represents a department within a tenant.
type Department struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	Name      string    `json:"name"`
	ParentID  *string   `json:"parent_id,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// ValidateDepartmentName checks that a department name is non-empty and within length limits.
func ValidateDepartmentName(name string) error {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return ErrDepartmentNameEmpty
	}
	if len(trimmed) > 255 {
		return fmt.Errorf("%w: must not exceed 255 characters", ErrDepartmentNameEmpty)
	}
	return nil
}
