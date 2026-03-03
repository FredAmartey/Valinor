package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
)

// Sentinel errors for invite redemption. These mirror the tenant package
// sentinels and are translated by the adapter in cmd/valinor/main.go.
var (
	ErrInviteNotFound = errors.New("invite not found")
	ErrInviteExpired  = errors.New("invite has expired")
	ErrInviteUsed     = errors.New("invite has already been used")
)

// InviteInfo holds the fields needed from a redeemed invite.
type InviteInfo struct {
	TenantID string
	Role     string
}

// InviteRedeemer abstracts the invite store operations needed for redemption,
// breaking the import cycle between auth and tenant packages.
type InviteRedeemer interface {
	// Redeem atomically marks an invite as used and returns its info.
	Redeem(ctx context.Context, code, userID string) (*InviteInfo, error)
}

// InviteRedeemHandler handles invite code redemption — assigns user to a
// tenant and grants the role embedded in the invite.
type InviteRedeemHandler struct {
	authStore *Store
	invites   InviteRedeemer
	tokenSvc  *TokenService
}

func NewInviteRedeemHandler(authStore *Store, invites InviteRedeemer, tokenSvc *TokenService) *InviteRedeemHandler {
	return &InviteRedeemHandler{
		authStore: authStore,
		invites:   invites,
		tokenSvc:  tokenSvc,
	}
}

func (h *InviteRedeemHandler) HandleRedeem(w http.ResponseWriter, r *http.Request) {
	identity := GetIdentity(r.Context())
	if identity == nil {
		writeAuthError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	var req struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Code == "" {
		writeAuthError(w, http.StatusBadRequest, "invite code required")
		return
	}

	// Redeem atomically (validates expiry + used status in SQL)
	inv, err := h.invites.Redeem(r.Context(), req.Code, identity.UserID)
	if err != nil {
		switch {
		case errors.Is(err, ErrInviteNotFound):
			writeAuthError(w, http.StatusBadRequest, "invite not found")
		case errors.Is(err, ErrInviteExpired):
			writeAuthError(w, http.StatusBadRequest, "invite has expired")
		case errors.Is(err, ErrInviteUsed):
			writeAuthError(w, http.StatusBadRequest, "invite has already been used")
		default:
			writeAuthError(w, http.StatusInternalServerError, "failed to redeem invite")
		}
		return
	}

	// Assign user to tenant
	if assignErr := h.authStore.UpdateUserTenant(r.Context(), identity.UserID, inv.TenantID); assignErr != nil {
		writeAuthError(w, http.StatusInternalServerError, "failed to assign user to tenant")
		return
	}

	// Assign the invite's role
	if roleErr := h.authStore.AssignRole(r.Context(), identity.UserID, inv.TenantID, inv.Role); roleErr != nil {
		writeAuthError(w, http.StatusInternalServerError, "failed to assign role")
		return
	}

	// Re-issue tokens with updated tenant
	updatedIdentity, err := h.authStore.GetIdentityWithRoles(r.Context(), identity.UserID)
	if err != nil {
		writeAuthError(w, http.StatusInternalServerError, "failed to load updated identity")
		return
	}

	accessToken, err := h.tokenSvc.CreateAccessToken(updatedIdentity)
	if err != nil {
		writeAuthError(w, http.StatusInternalServerError, "failed to create access token")
		return
	}

	refreshToken, err := h.tokenSvc.CreateRefreshToken(updatedIdentity)
	if err != nil {
		writeAuthError(w, http.StatusInternalServerError, "failed to create refresh token")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if encErr := json.NewEncoder(w).Encode(map[string]interface{}{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"token_type":    "Bearer",
		"expires_in":    86400,
		"user": map[string]interface{}{
			"id":                updatedIdentity.UserID,
			"email":             updatedIdentity.Email,
			"display_name":      updatedIdentity.DisplayName,
			"tenant_id":         updatedIdentity.TenantID,
			"is_platform_admin": updatedIdentity.IsPlatformAdmin,
		},
	}); encErr != nil {
		writeAuthError(w, http.StatusInternalServerError, "failed to encode response")
	}
}
