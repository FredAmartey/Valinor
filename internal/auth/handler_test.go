package auth_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valinor-ai/valinor/internal/auth"
)

func TestHandler_RefreshToken(t *testing.T) {
	tokenSvc := newTestTokenService()
	handler := auth.NewHandler(tokenSvc, nil, nil) // nil store/oidc for unit test

	identity := &auth.Identity{
		UserID:   "user-123",
		TenantID: "tenant-456",
		Email:    "scout@chelsea.com",
		Roles:    []string{"standard_user"},
	}

	refreshToken, err := tokenSvc.CreateRefreshToken(identity)
	require.NoError(t, err)

	body := `{"refresh_token":"` + refreshToken + `"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/token/refresh", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.HandleRefresh(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]string
	err = json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.NotEmpty(t, resp["access_token"])
	assert.NotEmpty(t, resp["refresh_token"])
	assert.Equal(t, "Bearer", resp["token_type"])
}

func TestHandler_RefreshToken_InvalidToken(t *testing.T) {
	tokenSvc := newTestTokenService()
	handler := auth.NewHandler(tokenSvc, nil, nil)

	body := `{"refresh_token":"invalid-token"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/token/refresh", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.HandleRefresh(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestHandler_RefreshToken_AccessTokenRejected(t *testing.T) {
	tokenSvc := newTestTokenService()
	handler := auth.NewHandler(tokenSvc, nil, nil)

	identity := &auth.Identity{UserID: "user-123", TenantID: "tenant-456"}
	accessToken, err := tokenSvc.CreateAccessToken(identity)
	require.NoError(t, err)

	body := `{"refresh_token":"` + accessToken + `"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/token/refresh", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.HandleRefresh(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}
