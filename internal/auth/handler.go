package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

// OIDCProvider is an interface for OIDC operations (allows mocking).
type OIDCProvider interface {
	AuthCodeURL(state string) string
	Exchange(ctx context.Context, code string) (*OIDCUserInfo, error)
}

// HandlerConfig holds dependencies for the auth Handler.
type HandlerConfig struct {
	TokenSvc       *TokenService
	Store          *Store
	RefreshStore   *RefreshTokenStore
	OIDC           OIDCProvider
	StateStore     *StateStore
	TenantResolver *TenantResolver
}

// Handler handles authentication HTTP endpoints.
type Handler struct {
	tokenSvc       *TokenService
	store          *Store
	refreshStore   *RefreshTokenStore
	oidc           OIDCProvider
	stateStore     *StateStore
	tenantResolver *TenantResolver
}

func NewHandler(cfg HandlerConfig) *Handler {
	return &Handler{
		tokenSvc:       cfg.TokenSvc,
		store:          cfg.Store,
		refreshStore:   cfg.RefreshStore,
		oidc:           cfg.OIDC,
		stateStore:     cfg.StateStore,
		tenantResolver: cfg.TenantResolver,
	}
}

// RegisterRoutes registers auth routes on the given mux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /auth/login", h.HandleLogin)
	mux.HandleFunc("GET /auth/callback", h.HandleCallback)
	mux.HandleFunc("POST /auth/token/refresh", h.HandleRefresh)
}

// HandleLogin initiates the OIDC login flow.
func (h *Handler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	if h.oidc == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "OIDC not configured",
		})
		return
	}

	state, err := h.stateStore.Generate()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "failed to generate state",
		})
		return
	}

	// Set state cookie so we can validate it on callback.
	// __Host- prefix enforces Secure, no Domain, Path=/.
	http.SetCookie(w, &http.Cookie{
		Name:     "__Host-oidc_state",
		Value:    state,
		Path:     "/",
		MaxAge:   600, // 10 minutes
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	url := h.oidc.AuthCodeURL(state)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

// HandleCallback processes the OIDC callback.
func (h *Handler) HandleCallback(w http.ResponseWriter, r *http.Request) {
	if h.oidc == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "OIDC not configured",
		})
		return
	}

	// Validate state parameter against cookie (CSRF protection — must happen first)
	queryState := r.URL.Query().Get("state")
	if queryState == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "missing state parameter",
		})
		return
	}

	cookie, err := r.Cookie("__Host-oidc_state")
	if err != nil || cookie.Value != queryState {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "invalid state parameter",
		})
		return
	}

	if !h.stateStore.Validate(queryState) {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "invalid state parameter",
		})
		return
	}

	// Clear state cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "__Host-oidc_state",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
	})

	if h.store == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "user store not configured",
		})
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "missing code parameter",
		})
		return
	}

	// Resolve tenant from subdomain
	if h.tenantResolver == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "tenant resolution not configured",
		})
		return
	}
	tenantID, err := h.tenantResolver.ResolveFromRequest(r.Context(), r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "cannot resolve tenant",
		})
		return
	}

	// Exchange code for user info
	userInfo, err := h.oidc.Exchange(r.Context(), code)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{
			"error": "OIDC exchange failed",
		})
		return
	}

	// Find or create user
	identity, _, err := h.store.FindOrCreateByOIDC(r.Context(), *userInfo, tenantID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "user lookup failed",
		})
		return
	}

	// Load full identity with roles
	fullIdentity, err := h.store.GetIdentityWithRoles(r.Context(), identity.UserID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "identity loading failed",
		})
		return
	}

	// Issue access token
	accessToken, err := h.tokenSvc.CreateAccessToken(fullIdentity)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "token creation failed",
		})
		return
	}

	// Issue refresh token — with family tracking if store is available
	var refreshToken string
	if h.refreshStore != nil {
		familyID, famErr := h.refreshStore.CreateFamilyAndReturnID(r.Context(), fullIdentity.TenantID, fullIdentity.UserID)
		if famErr != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{
				"error": "token family creation failed",
			})
			return
		}

		refreshIdentity := *fullIdentity
		refreshIdentity.FamilyID = familyID
		refreshIdentity.Generation = 1

		refreshToken, err = h.tokenSvc.CreateRefreshToken(&refreshIdentity)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{
				"error": "token creation failed",
			})
			return
		}

		if hashErr := h.refreshStore.SetInitialTokenHash(r.Context(), familyID, fullIdentity.TenantID, HashToken(refreshToken)); hashErr != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{
				"error": "token family initialization failed",
			})
			return
		}
	} else {
		refreshToken, err = h.tokenSvc.CreateRefreshToken(fullIdentity)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{
				"error": "token creation failed",
			})
			return
		}
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"token_type":    "Bearer",
	})
}

// HandleRefresh exchanges a refresh token for new access + refresh tokens.
// When a RefreshTokenStore is available, this implements RFC 6819 §5.2.2.3
// token family rotation with reuse detection. Legacy tokens (without family
// claims) are automatically upgraded on first refresh.
func (h *Handler) HandleRefresh(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 10<<10) // 10 KB limit

	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "invalid request body",
		})
		return
	}

	// Validate refresh token (JWT signature + expiry)
	identity, err := h.tokenSvc.ValidateToken(req.RefreshToken)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{
			"error": "invalid refresh token",
		})
		return
	}

	if identity.TokenType != "refresh" {
		writeJSON(w, http.StatusUnauthorized, map[string]string{
			"error": "refresh token required",
		})
		return
	}

	// If refresh store is available, perform family rotation
	if h.refreshStore != nil {
		newIdentity, newRefreshJWT, rotateErr := h.rotateRefreshToken(r.Context(), identity, req.RefreshToken)
		if rotateErr != nil {
			status, msg := classifyRotationError(rotateErr)
			writeJSON(w, status, map[string]string{"error": msg})
			return
		}

		accessToken, accessErr := h.tokenSvc.CreateAccessToken(newIdentity)
		if accessErr != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{
				"error": "token creation failed",
			})
			return
		}

		writeJSON(w, http.StatusOK, map[string]string{
			"access_token":  accessToken,
			"refresh_token": newRefreshJWT,
			"token_type":    "Bearer",
		})
		return
	}

	// Fallback: stateless mode (no DB / dev mode)
	accessToken, err := h.tokenSvc.CreateAccessToken(identity)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "token creation failed",
		})
		return
	}

	refreshToken, err := h.tokenSvc.CreateRefreshToken(identity)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "token creation failed",
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"token_type":    "Bearer",
	})
}

// rotateRefreshToken handles the full rotation flow:
// 1. If legacy token (no FamilyID), upgrade to family-tracked token
// 2. Create new refresh JWT with incremented generation
// 3. Atomic DB rotation (validate old hash, store new hash)
func (h *Handler) rotateRefreshToken(ctx context.Context, identity *Identity, presentedJWT string) (*Identity, string, error) {
	// Legacy token (no FamilyID): create a new family
	if identity.FamilyID == "" {
		return h.upgradeLegacyToken(ctx, identity)
	}

	// Build new identity with incremented generation
	newIdentity := *identity
	newIdentity.Generation = identity.Generation + 1

	// Create the new refresh JWT so we can hash it
	newRefreshJWT, err := h.tokenSvc.CreateRefreshToken(&newIdentity)
	if err != nil {
		return nil, "", fmt.Errorf("creating rotated refresh token: %w", err)
	}

	// Atomic rotation: validate presented token + store new hash
	presentedHash := HashToken(presentedJWT)
	newHash := HashToken(newRefreshJWT)
	_, err = h.refreshStore.RotateToken(ctx, identity.FamilyID, identity.TenantID, presentedHash, identity.Generation, newHash)
	if err != nil {
		return nil, "", err
	}

	return &newIdentity, newRefreshJWT, nil
}

// upgradeLegacyToken handles the transition from a stateless refresh
// token (pre-rotation) to a family-tracked token.
func (h *Handler) upgradeLegacyToken(ctx context.Context, identity *Identity) (*Identity, string, error) {
	familyID, err := h.refreshStore.CreateFamilyAndReturnID(ctx, identity.TenantID, identity.UserID)
	if err != nil {
		return nil, "", fmt.Errorf("upgrading legacy token: %w", err)
	}

	newIdentity := *identity
	newIdentity.FamilyID = familyID
	newIdentity.Generation = 1

	newRefreshJWT, err := h.tokenSvc.CreateRefreshToken(&newIdentity)
	if err != nil {
		return nil, "", fmt.Errorf("creating refresh token for legacy upgrade: %w", err)
	}

	if hashErr := h.refreshStore.SetInitialTokenHash(ctx, familyID, identity.TenantID, HashToken(newRefreshJWT)); hashErr != nil {
		return nil, "", fmt.Errorf("setting hash for legacy upgrade: %w", hashErr)
	}

	return &newIdentity, newRefreshJWT, nil
}

func classifyRotationError(err error) (int, string) {
	switch {
	case errors.Is(err, ErrTokenReuse):
		return http.StatusUnauthorized, "token reuse detected"
	case errors.Is(err, ErrFamilyRevoked):
		return http.StatusUnauthorized, "token family revoked"
	case errors.Is(err, ErrFamilyNotFound):
		return http.StatusUnauthorized, "invalid token family"
	default:
		return http.StatusInternalServerError, "token rotation failed"
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
