package auth

import (
	"context"
	"encoding/json"
	"net/http"
)

// OIDCProvider is an interface for OIDC operations (allows mocking).
type OIDCProvider interface {
	AuthCodeURL(state string) string
	Exchange(ctx context.Context, code string) (*OIDCUserInfo, error)
}

// Handler handles authentication HTTP endpoints.
type Handler struct {
	tokenSvc   *TokenService
	store      *Store
	oidc       OIDCProvider
	stateStore *StateStore
}

func NewHandler(tokenSvc *TokenService, store *Store, oidc OIDCProvider, stateStore *StateStore) *Handler {
	return &Handler{
		tokenSvc:   tokenSvc,
		store:      store,
		oidc:       oidc,
		stateStore: stateStore,
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

	// Set state cookie so we can validate it on callback
	http.SetCookie(w, &http.Cookie{
		Name:     "oidc_state",
		Value:    state,
		Path:     "/auth/callback",
		MaxAge:   600, // 10 minutes
		HttpOnly: true,
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

	cookie, err := r.Cookie("oidc_state")
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
		Name:     "oidc_state",
		Value:    "",
		Path:     "/auth/callback",
		MaxAge:   -1,
		HttpOnly: true,
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

	// Exchange code for user info
	userInfo, err := h.oidc.Exchange(r.Context(), code)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{
			"error": "OIDC exchange failed",
		})
		return
	}

	// Find or create user
	identity, _, err := h.store.FindOrCreateByOIDC(r.Context(), *userInfo, "")
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

	// Issue tokens
	accessToken, err := h.tokenSvc.CreateAccessToken(fullIdentity)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": "token creation failed",
		})
		return
	}

	refreshToken, err := h.tokenSvc.CreateRefreshToken(fullIdentity)
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

// HandleRefresh exchanges a refresh token for new access + refresh tokens.
func (h *Handler) HandleRefresh(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "invalid request body",
		})
		return
	}

	// Validate refresh token
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

	// Issue new tokens
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

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
