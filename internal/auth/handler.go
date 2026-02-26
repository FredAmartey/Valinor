package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
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
	tokenSvc         *TokenService
	store            *Store
	refreshStore     *RefreshTokenStore
	oidc             OIDCProvider
	stateStore       *StateStore
	tenantResolver   *TenantResolver
	idTokenValidator *IDTokenValidator
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

// SetIDTokenValidator configures the handler for external id_token exchange.
func (h *Handler) SetIDTokenValidator(v *IDTokenValidator) {
	h.idTokenValidator = v
}

// RegisterRoutes registers auth routes on the given mux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /auth/login", h.HandleLogin)
	mux.HandleFunc("GET /auth/callback", h.HandleCallback)
	mux.HandleFunc("POST /auth/token/refresh", h.HandleRefresh)
	mux.HandleFunc("POST /auth/exchange", h.HandleExchange)
}

// RegisterDevRoutes registers dev-only auth routes.
// Call this only when devmode is enabled.
func (h *Handler) RegisterDevRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /auth/dev/login", h.HandleDevLogin)
}

type devLoginResponse struct {
	AccessToken  string           `json:"access_token"`
	RefreshToken string           `json:"refresh_token"`
	TokenType    string           `json:"token_type"`
	ExpiresIn    int              `json:"expires_in"`
	User         devLoginUserInfo `json:"user"`
}

type devLoginUserInfo struct {
	ID              string `json:"id"`
	Email           string `json:"email"`
	DisplayName     string `json:"display_name"`
	TenantID        string `json:"tenant_id"`
	IsPlatformAdmin bool   `json:"is_platform_admin"`
}

// HandleDevLogin authenticates by email in dev mode.
// Looks up the user, issues real access + refresh tokens.
func (h *Handler) HandleDevLogin(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 10<<10)

	var req struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "invalid request body",
		})
		return
	}

	if req.Email == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "email is required",
		})
		return
	}

	if h.store == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "user store not configured",
		})
		return
	}

	// Find user by email
	userID, err := h.store.FindUserIDByEmail(r.Context(), req.Email)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			slog.Warn("dev login: user not found", "email", req.Email)
			writeJSON(w, http.StatusNotFound, map[string]string{
				"error": "user not found",
			})
			return
		}
		slog.Error("dev login failed", "error", err, "email", req.Email)
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "user lookup failed",
		})
		return
	}

	// Load full identity with roles
	identity, err := h.store.GetIdentityWithRoles(r.Context(), userID)
	if err != nil {
		slog.Error("dev login failed", "error", err, "email", req.Email)
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "identity loading failed",
		})
		return
	}

	// Issue access token
	accessToken, err := h.tokenSvc.CreateAccessToken(identity)
	if err != nil {
		slog.Error("dev login failed", "error", err, "email", req.Email)
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "token creation failed",
		})
		return
	}

	// Dev mode: issue stateless refresh token without family tracking.
	// This is intentional — HandleRefresh handles legacy tokens via the
	// upgrade path (see upgradeLegacyToken). Family rotation is not
	// critical in dev mode where tokens cannot be compromised.
	refreshToken, err := h.tokenSvc.CreateRefreshToken(identity)
	if err != nil {
		slog.Error("dev login failed", "error", err, "email", req.Email)
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "token creation failed",
		})
		return
	}

	slog.Info("dev login successful", "email", req.Email, "user_id", userID)
	writeJSON(w, http.StatusOK, devLoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    h.tokenSvc.AccessTokenExpirySeconds(),
		User: devLoginUserInfo{
			ID:              identity.UserID,
			Email:           identity.Email,
			DisplayName:     identity.DisplayName,
			TenantID:        identity.TenantID,
			IsPlatformAdmin: identity.IsPlatformAdmin,
		},
	})
}

// HandleExchange validates an external OIDC id_token and returns Valinor tokens.
// Used by the dashboard to exchange Clerk id_tokens for platform JWTs.
func (h *Handler) HandleExchange(w http.ResponseWriter, r *http.Request) {
	if h.idTokenValidator == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "OIDC token exchange not configured",
		})
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 10<<10)

	var req struct {
		IDToken    string `json:"id_token"`
		TenantSlug string `json:"tenant_slug,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.IDToken == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "missing or invalid id_token",
		})
		return
	}

	userInfo, err := h.idTokenValidator.Validate(r.Context(), req.IDToken)
	if err != nil {
		slog.Warn("id_token validation failed", "error", err)
		writeJSON(w, http.StatusUnauthorized, map[string]string{
			"error": "invalid id_token",
		})
		return
	}

	if h.store == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"error": "auth store not configured",
		})
		return
	}

	// Resolve tenant: prefer explicit slug from body, fall back to Origin header.
	var tenantID string
	if h.tenantResolver != nil {
		if req.TenantSlug != "" {
			tid, resolveErr := h.tenantResolver.ResolveBySlug(r.Context(), req.TenantSlug)
			if resolveErr != nil {
				slog.Warn("tenant slug resolution failed", "slug", req.TenantSlug, "error", resolveErr)
			} else {
				tenantID = tid
			}
		}
		if tenantID == "" {
			origin := r.Header.Get("Origin")
			if origin != "" {
				tid, resolveErr := h.tenantResolver.ResolveFromOrigin(r.Context(), origin)
				if resolveErr != nil {
					slog.Warn("tenant resolution from origin failed", "origin", origin, "error", resolveErr)
				} else {
					tenantID = tid
				}
			}
		}
	}

	// No tenant resolved: check if user is a platform admin.
	if tenantID == "" {
		adminIdentity, adminErr := h.store.LookupPlatformAdminByOIDC(r.Context(), userInfo.Issuer, userInfo.Subject)
		if adminErr != nil || adminIdentity == nil {
			writeJSON(w, http.StatusNotFound, map[string]string{
				"error": "tenant not found",
			})
			return
		}
		// Platform admin — proceed without tenant scope.
	}

	identity, _, err := h.store.FindOrCreateByOIDC(r.Context(), *userInfo, tenantID)
	if err != nil {
		slog.Error("exchange: user resolution failed", "error", err, "subject", userInfo.Subject)
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "user resolution failed",
		})
		return
	}

	fullIdentity, err := h.store.GetIdentityWithRoles(r.Context(), identity.UserID)
	if err != nil {
		slog.Error("exchange: loading identity failed", "error", err, "user_id", identity.UserID)
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "loading identity failed",
		})
		return
	}

	accessToken, err := h.tokenSvc.CreateAccessToken(fullIdentity)
	if err != nil {
		slog.Error("exchange: access token creation failed", "error", err)
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
			slog.Error("exchange: failed to create token family", "error", famErr, "user_id", fullIdentity.UserID)
			// fall through to stateless
		} else {
			fullIdentity.FamilyID = familyID
			fullIdentity.Generation = 1
			refreshToken, err = h.tokenSvc.CreateRefreshToken(fullIdentity)
			if err == nil {
				tokenHash := HashToken(refreshToken)
				_ = h.refreshStore.SetInitialTokenHash(r.Context(), familyID, fullIdentity.TenantID, tokenHash)
			}
		}
	}
	if refreshToken == "" {
		refreshToken, err = h.tokenSvc.CreateRefreshToken(fullIdentity)
		if err != nil {
			slog.Error("exchange: refresh token creation failed", "error", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{
				"error": "token creation failed",
			})
			return
		}
	}

	slog.Info("token exchange successful",
		"subject", userInfo.Subject,
		"email", userInfo.Email,
		"user_id", fullIdentity.UserID,
	)

	writeJSON(w, http.StatusOK, devLoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    h.tokenSvc.AccessTokenExpirySeconds(),
		User: devLoginUserInfo{
			ID:              fullIdentity.UserID,
			Email:           fullIdentity.Email,
			DisplayName:     fullIdentity.DisplayName,
			TenantID:        fullIdentity.TenantID,
			IsPlatformAdmin: fullIdentity.IsPlatformAdmin,
		},
	})
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

	// Exchange code for user info (must happen before tenant resolution
	// so we can check for platform admin on the tenantless path)
	userInfo, err := h.oidc.Exchange(r.Context(), code)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{
			"error": "OIDC exchange failed",
		})
		return
	}

	// Resolve tenant from subdomain
	var tenantID string
	if h.tenantResolver != nil {
		tid, resolveErr := h.tenantResolver.ResolveFromRequest(r.Context(), r)
		if resolveErr != nil {
			// No tenant resolved — check if this is a platform admin on the base domain
			if h.tryPlatformAdminCallback(r.Context(), w, userInfo) {
				return
			}
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "cannot resolve tenant"})
			return
		}
		tenantID = tid
	} else {
		// No TenantResolver configured — check for platform admin via OIDC
		if h.tryPlatformAdminCallback(r.Context(), w, userInfo) {
			return
		}
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "tenant resolution not configured"})
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

// tryPlatformAdminCallback checks if the OIDC user is a platform admin and,
// if so, issues tokens without tenant scope. Returns true if it handled the response.
func (h *Handler) tryPlatformAdminCallback(ctx context.Context, w http.ResponseWriter, userInfo *OIDCUserInfo) bool {
	if h.store == nil {
		return false
	}

	adminIdentity, err := h.store.LookupPlatformAdminByOIDC(ctx, userInfo.Issuer, userInfo.Subject)
	if err != nil || adminIdentity == nil {
		return false
	}

	// Clear tenant scope so platform-admin tokens are tenantless.
	adminIdentity.TenantID = ""

	accessToken, err := h.tokenSvc.CreateAccessToken(adminIdentity)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "token creation failed"})
		return true
	}

	refreshToken, err := h.tokenSvc.CreateRefreshToken(adminIdentity)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "token creation failed"})
		return true
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"token_type":    "Bearer",
	})
	return true
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
		return h.upgradeLegacyToken(ctx, identity, presentedJWT)
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
// token (pre-rotation) to a family-tracked token. It records the legacy
// token's hash to reject replay attempts of the same legacy JWT.
func (h *Handler) upgradeLegacyToken(ctx context.Context, identity *Identity, presentedJWT string) (*Identity, string, error) {
	legacyHash := HashToken(presentedJWT)

	// Reject if this legacy token was already upgraded
	upgraded, err := h.refreshStore.IsLegacyTokenUpgraded(ctx, identity.UserID, identity.TenantID, legacyHash)
	if err != nil {
		return nil, "", fmt.Errorf("checking legacy token upgrade: %w", err)
	}
	if upgraded {
		return nil, "", ErrLegacyTokenReplay
	}

	familyID, err := h.refreshStore.CreateFamilyForLegacyUpgrade(ctx, identity.TenantID, identity.UserID, legacyHash)
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
	case errors.Is(err, ErrLegacyTokenReplay):
		return http.StatusUnauthorized, "legacy token already upgraded"
	default:
		return http.StatusInternalServerError, "token rotation failed"
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
