package auth

import (
	"errors"
)

var (
	ErrTokenExpired = errors.New("token expired")
	ErrTokenInvalid = errors.New("token invalid")
	ErrUserNotFound = errors.New("user not found")
	ErrUnauthorized   = errors.New("unauthorized")
	ErrTenantNotFound = errors.New("tenant not found")
)

// Identity represents an authenticated user's claims.
type Identity struct {
	UserID      string   `json:"user_id"`
	TenantID    string   `json:"tenant_id"`
	Email       string   `json:"email"`
	DisplayName string   `json:"display_name"`
	Roles       []string `json:"roles"`
	Departments []string `json:"departments"`
	TokenType   string   `json:"token_type"` // "access" or "refresh"
}