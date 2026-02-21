package auth

import (
	"context"
	"errors"
)

var (
	ErrTokenExpired = errors.New("token expired")
	ErrTokenInvalid = errors.New("token invalid")
	ErrUserNotFound = errors.New("user not found")
	ErrUnauthorized    = errors.New("unauthorized")
	ErrTenantNotFound  = errors.New("tenant not found")
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

// Service defines the authentication interface.
type Service interface {
	// CreateAccessToken creates a JWT access token for the given identity.
	CreateAccessToken(identity *Identity) (string, error)
	// CreateRefreshToken creates a JWT refresh token for the given identity.
	CreateRefreshToken(identity *Identity) (string, error)
	// ValidateToken validates a JWT and returns the identity.
	ValidateToken(tokenString string) (*Identity, error)
	// GetIdentityByOIDC looks up a user by OIDC issuer and subject.
	GetIdentityByOIDC(ctx context.Context, issuer, subject string) (*Identity, error)
}
