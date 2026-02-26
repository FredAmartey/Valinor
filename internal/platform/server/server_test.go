package server_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valinor-ai/valinor/internal/auth"
	"github.com/valinor-ai/valinor/internal/channels"
	"github.com/valinor-ai/valinor/internal/connectors"
	"github.com/valinor-ai/valinor/internal/orchestrator"
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

const testTenant = "test-tenant"

func newTestDeps() (server.Dependencies, *auth.TokenService) {
	tokenSvc := auth.NewTokenService("test-signing-key-must-be-32-chars!!", "valinor", 24, 168)
	rbacEngine := rbac.NewEvaluator(nil)
	// Register roles for both a named test tenant and the empty tenant.
	// Tests that use identities without TenantID rely on the empty-tenant
	// registrations so RBAC passes and the handler's own tenant check is reached.
	for _, tid := range []string{testTenant, ""} {
		rbacEngine.RegisterRole(tid, "standard_user", []string{"agents:read", "agents:message"})
		rbacEngine.RegisterRole(tid, "read_only", []string{"agents:read"})
		rbacEngine.RegisterRole(tid, "connectors_user", []string{"connectors:read", "connectors:write"})
		rbacEngine.RegisterRole(tid, "channels_user", []string{"channels:links:read", "channels:links:write"})
		rbacEngine.RegisterRole(tid, "channels_provider_user", []string{"channels:providers:read", "channels:providers:write"})
		rbacEngine.RegisterRole(tid, "channels_outbox_user", []string{"channels:outbox:read", "channels:outbox:write"})
	}

	// Wire a minimal agent handler (nil pool — will fail on DB calls but routes exist)
	driver := orchestrator.NewMockDriver()
	store := orchestrator.NewStore()
	mgr := orchestrator.NewManager(nil, driver, store, orchestrator.ManagerConfig{Driver: "mock"})
	agentHandler := orchestrator.NewHandler(mgr, nil, nil, nil, nil)
	connectorHandler := connectors.NewHandler(nil, connectors.NewStore())
	channelHandler := channels.NewHandler(nil)

	return server.Dependencies{
		Auth:             tokenSvc,
		RBAC:             rbacEngine,
		AgentHandler:     agentHandler,
		ConnectorHandler: connectorHandler,
		ChannelHandler:   channelHandler,
	}, tokenSvc
}

func TestServer_Agents_WithPermission(t *testing.T) {
	deps, tokenSvc := newTestDeps()
	srv := server.New(":0", deps)

	identity := &auth.Identity{
		UserID: "user-1",
		Roles:  []string{"standard_user"},
	}
	token, err := tokenSvc.CreateAccessToken(identity)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/agents", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestServer_Agents_WithoutPermission(t *testing.T) {
	deps, tokenSvc := newTestDeps()
	// Register a role with no agents:read permission
	deps.RBAC.RegisterRole("tenant-1", "no_agents", []string{"users:read"})
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

func TestServer_Connectors_RouteNormalized(t *testing.T) {
	deps, tokenSvc := newTestDeps()
	srv := server.New(":0", deps)

	identity := &auth.Identity{
		UserID: "user-connectors",
		Roles:  []string{"connectors_user"},
	}
	token, err := tokenSvc.CreateAccessToken(identity)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/connectors", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestServer_Connectors_LegacyTenantPathNotRegistered(t *testing.T) {
	deps, tokenSvc := newTestDeps()
	srv := server.New(":0", deps)

	identity := &auth.Identity{
		UserID: "user-connectors",
		Roles:  []string{"connectors_user"},
	}
	token, err := tokenSvc.CreateAccessToken(identity)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/tenant-1/connectors", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestServer_ChannelsLinks_RouteNormalized(t *testing.T) {
	deps, tokenSvc := newTestDeps()
	srv := server.New(":0", deps)

	identity := &auth.Identity{
		UserID: "user-channels",
		Roles:  []string{"channels_user"},
	}
	token, err := tokenSvc.CreateAccessToken(identity)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/channels/links", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestServer_ChannelsLinks_LegacyTenantPathNotRegistered(t *testing.T) {
	deps, tokenSvc := newTestDeps()
	srv := server.New(":0", deps)

	identity := &auth.Identity{
		UserID: "user-channels",
		Roles:  []string{"channels_user"},
	}
	token, err := tokenSvc.CreateAccessToken(identity)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/tenant-1/channels/links", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestServer_ChannelProviderCredentials_RouteNormalized(t *testing.T) {
	deps, tokenSvc := newTestDeps()
	srv := server.New(":0", deps)

	identity := &auth.Identity{
		UserID: "user-channel-provider",
		Roles:  []string{"channels_provider_user"},
	}
	token, err := tokenSvc.CreateAccessToken(identity)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/channels/providers/slack/credentials", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestServer_ChannelProviderCredentials_LegacyTenantPathNotRegistered(t *testing.T) {
	deps, tokenSvc := newTestDeps()
	srv := server.New(":0", deps)

	identity := &auth.Identity{
		UserID: "user-channel-provider",
		Roles:  []string{"channels_provider_user"},
	}
	token, err := tokenSvc.CreateAccessToken(identity)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/tenant-1/channels/providers/slack/credentials", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestServer_ChannelOutbox_RouteNormalized(t *testing.T) {
	deps, tokenSvc := newTestDeps()
	srv := server.New(":0", deps)

	identity := &auth.Identity{
		UserID: "user-channel-outbox",
		Roles:  []string{"channels_outbox_user"},
	}
	token, err := tokenSvc.CreateAccessToken(identity)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/channels/outbox", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestServer_ChannelOutbox_LegacyTenantPathNotRegistered(t *testing.T) {
	deps, tokenSvc := newTestDeps()
	srv := server.New(":0", deps)

	identity := &auth.Identity{
		UserID: "user-channel-outbox",
		Roles:  []string{"channels_outbox_user"},
	}
	token, err := tokenSvc.CreateAccessToken(identity)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/tenant-1/channels/outbox", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestServer_ChannelsWebhook_TenantScopedRouteRegistered(t *testing.T) {
	deps, _ := newTestDeps()
	srv := server.New(":0", deps)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/190f3a21-3b2c-42ce-b26e-2f448a58ec14/channels/whatsapp/webhook", strings.NewReader(`{}`))
	w := httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)

	// Route should resolve to channel handler (which returns JSON 4xx), not mux 404 plain text.
	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
}

func TestServer_ChannelsWebhook_LegacyPathNotRegistered(t *testing.T) {
	deps, tokenSvc := newTestDeps()
	srv := server.New(":0", deps)

	identity := &auth.Identity{
		UserID: "user-channels",
		Roles:  []string{"channels_user"},
	}
	token, err := tokenSvc.CreateAccessToken(identity)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/channels/whatsapp/webhook", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Contains(t, w.Body.String(), "404 page not found")
}
