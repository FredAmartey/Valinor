package tenant

import (
	"errors"
	"time"
)

type Invite struct {
	ID        string     `json:"id"`
	TenantID  string     `json:"tenant_id"`
	Code      string     `json:"code"`
	Role      string     `json:"role"`
	CreatedBy string     `json:"created_by"`
	ExpiresAt time.Time  `json:"expires_at"`
	UsedBy    *string    `json:"used_by,omitempty"`
	UsedAt    *time.Time `json:"used_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

var (
	ErrInviteNotFound = errors.New("invite not found")
	ErrInviteExpired  = errors.New("invite has expired")
	ErrInviteUsed     = errors.New("invite has already been used")
)
