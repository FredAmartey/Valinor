package server_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valinor-ai/valinor/internal/auth"
	"github.com/valinor-ai/valinor/internal/platform/server"
	"github.com/valinor-ai/valinor/internal/rbac"
)

func TestServer_HealthCheck(t *testing.T) {
	srv := server.New(":0", server.Dependencies{})

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var body map[string]any
	err := json.Unmarshal(w.Body.Bytes(), &body)
	require.NoError(t, err)
	assert.Equal(t, "ok", body["status"])
}

func TestServer_ReadinessCheck_NoDB(t *testing.T) {
	srv := server.New(":0", server.Dependencies{})

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	w := httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestServer_NotFound(t *testing.T) {
	srv := server.New(":0", server.Dependencies{})

	req := httptest.NewRequest(http.MethodGet, "/nonexistent", nil)
	w := httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestServer_StartStop(t *testing.T) {
	srv := server.New("127.0.0.1:0", server.Dependencies{})

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Start(ctx)
	}()

	// Give server time to start, then cancel
	cancel()

	err := <-errCh
	assert.NoError(t, err)
}

func newTestDeps() (server.Dependencies, *auth.TokenService) {
	tokenSvc := auth.NewTokenService("test-signing-key-must-be-32-chars!!", "valinor", 24, 168)
	rbacEngine := rbac.NewEvaluator(nil)
	rbacEngine.RegisterRole("standard_user", []string{"agents:read", "agents:message"})
	rbacEngine.RegisterRole("read_only", []string{"agents:read"})
	return server.Dependencies{
		Auth: tokenSvc,
		RBAC: rbacEngine,
	}, tokenSvc
}

func TestServer_Agents_WithPermission(t *testing.T) {
	deps, tokenSvc := newTestDeps()
	srv := server.New(":0", deps)

	identity := &auth.Identity{
		UserID:   "user-1",
		TenantID: "tenant-1",
		Roles:    []string{"standard_user"},
	}
	token, err := tokenSvc.CreateAccessToken(identity)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/agents", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestServer_Agents_WithoutPermission(t *testing.T) {
	deps, tokenSvc := newTestDeps()
	// Register a role with no agents:read permission
	deps.RBAC.RegisterRole("no_agents", []string{"users:read"})
	srv := server.New(":0", deps)

	identity := &auth.Identity{
		UserID:   "user-2",
		TenantID: "tenant-1",
		Roles:    []string{"no_agents"},
	}
	token, err := tokenSvc.CreateAccessToken(identity)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/agents", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestServer_Agents_NoToken(t *testing.T) {
	deps, _ := newTestDeps()
	srv := server.New(":0", deps)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/agents", nil)
	w := httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}
