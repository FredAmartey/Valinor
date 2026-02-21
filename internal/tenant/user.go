package tenant

import (
	"errors"
	"fmt"
	"net/mail"
	"time"
)

var (
	ErrUserNotFound   = errors.New("user not found")
	ErrEmailInvalid   = errors.New("invalid email address")
	ErrEmailDuplicate = errors.New("email already exists in tenant")
)

// User represents a user within a tenant (management domain model).
type User struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"tenant_id"`
	Email       string    `json:"email"`
	DisplayName string    `json:"display_name,omitempty"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"created_at"`
}

// ValidateEmail checks that an email address is syntactically valid.
func ValidateEmail(email string) error {
	if email == "" {
		return fmt.Errorf("%w: email is required", ErrEmailInvalid)
	}
	_, err := mail.ParseAddress(email)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrEmailInvalid, err)
	}
	return nil
}
