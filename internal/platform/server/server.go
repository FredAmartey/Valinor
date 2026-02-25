package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/valinor-ai/valinor/internal/audit"
	"github.com/valinor-ai/valinor/internal/auth"
	"github.com/valinor-ai/valinor/internal/channels"
	"github.com/valinor-ai/valinor/internal/connectors"
	"github.com/valinor-ai/valinor/internal/orchestrator"
	"github.com/valinor-ai/valinor/internal/platform/middleware"
	"github.com/valinor-ai/valinor/internal/proxy"
	"github.com/valinor-ai/valinor/internal/rbac"
	"github.com/valinor-ai/valinor/internal/tenant"
)

// Dependencies holds all injected dependencies for the server.
type Dependencies struct {
	Pool               *pgxpool.Pool
	Auth               *auth.TokenService
	AuthHandler        *auth.Handler
	RBAC               *rbac.Evaluator
	TenantHandler      *tenant.Handler
	DepartmentHandler  *tenant.DepartmentHandler
	UserHandler        *tenant.UserHandler
	RoleHandler        *tenant.RoleHandler
	AgentHandler       *orchestrator.Handler
	ProxyHandler       *proxy.Handler
	AuditHandler       *audit.Handler
	ConnectorHandler   *connectors.Handler
	ChannelHandler     *channels.Handler
	RBACAuditLogger    rbac.AuditLogger
	DevMode            bool
	DevIdentity        *auth.Identity
	Logger             *slog.Logger
	CORSAllowedOrigins []string
}

type Server struct {
	httpServer   *http.Server
	protectedMux *http.ServeMux
	pool         *pgxpool.Pool
	handler      http.Handler
}

func New(addr string, deps Dependencies) *Server {
	// Protected routes mux — wrapped with auth middleware
	protectedMux := http.NewServeMux()

	// Build protected handler with middleware chain
	var protectedHandler http.Handler = protectedMux
	protectedHandler = middleware.TenantContext(protectedHandler)
	if deps.Auth != nil {
		if deps.DevMode && deps.DevIdentity != nil {
			protectedHandler = auth.MiddlewareWithDevMode(deps.Auth, deps.DevIdentity)(protectedHandler)
		} else {
			protectedHandler = auth.Middleware(deps.Auth)(protectedHandler)
		}
	}

	// Top-level mux: public routes + protected catch-all
	topMux := http.NewServeMux()

	s := &Server{
		httpServer: &http.Server{
			Addr:         addr,
			ReadTimeout:  15 * time.Second,
			WriteTimeout: 30 * time.Second,
			IdleTimeout:  60 * time.Second,
		},
		protectedMux: protectedMux,
		pool:         deps.Pool,
	}

	// Public routes (no auth required)
	topMux.HandleFunc("GET /healthz", s.handleHealth)
	topMux.HandleFunc("GET /readyz", s.handleReadiness)
	if deps.AuthHandler != nil {
		deps.AuthHandler.RegisterRoutes(topMux)
	}
	// Dev-only login route (no auth required)
	if deps.DevMode && deps.AuthHandler != nil {
		deps.AuthHandler.RegisterDevRoutes(topMux)
	}
	if deps.ChannelHandler != nil {
		topMux.Handle("POST /api/v1/tenants/{tenantID}/channels/{provider}/webhook",
			http.HandlerFunc(deps.ChannelHandler.HandleWebhook),
		)
	}

	// Build RBAC middleware options (audit logger if available)
	var rbacOpts []rbac.MiddlewareOption
	if deps.RBACAuditLogger != nil {
		rbacOpts = append(rbacOpts, rbac.WithAuditLogger(deps.RBACAuditLogger))
	}

	// Agent routes (orchestrator)
	if deps.AgentHandler != nil && deps.RBAC != nil {
		protectedMux.Handle("POST /api/v1/agents",
			rbac.RequirePermission(deps.RBAC, "agents:write", rbacOpts...)(
				http.HandlerFunc(deps.AgentHandler.HandleProvision),
			),
		)
		protectedMux.Handle("GET /api/v1/agents",
			rbac.RequirePermission(deps.RBAC, "agents:read", rbacOpts...)(
				http.HandlerFunc(deps.AgentHandler.HandleListAgents),
			),
		)
		protectedMux.Handle("GET /api/v1/agents/{id}",
			rbac.RequirePermission(deps.RBAC, "agents:read", rbacOpts...)(
				http.HandlerFunc(deps.AgentHandler.HandleGetAgent),
			),
		)
		protectedMux.Handle("DELETE /api/v1/agents/{id}",
			rbac.RequirePermission(deps.RBAC, "agents:write", rbacOpts...)(
				http.HandlerFunc(deps.AgentHandler.HandleDestroyAgent),
			),
		)
		protectedMux.Handle("POST /api/v1/agents/{id}/configure",
			rbac.RequirePermission(deps.RBAC, "agents:write", rbacOpts...)(
				http.HandlerFunc(deps.AgentHandler.HandleConfigure),
			),
		)
	}

	// Proxy routes (agent messaging)
	if deps.ProxyHandler != nil && deps.RBAC != nil {
		protectedMux.Handle("POST /api/v1/agents/{id}/message",
			rbac.RequirePermission(deps.RBAC, "agents:write", rbacOpts...)(
				http.HandlerFunc(deps.ProxyHandler.HandleMessage),
			),
		)
		protectedMux.Handle("POST /api/v1/agents/{id}/stream",
			rbac.RequirePermission(deps.RBAC, "agents:write", rbacOpts...)(
				http.HandlerFunc(deps.ProxyHandler.HandleStream),
			),
		)
		protectedMux.Handle("POST /api/v1/agents/{id}/context",
			rbac.RequirePermission(deps.RBAC, "agents:write", rbacOpts...)(
				http.HandlerFunc(deps.ProxyHandler.HandleContext),
			),
		)
	}

	// Platform admin routes (tenant provisioning)
	if deps.TenantHandler != nil {
		protectedMux.Handle("POST /api/v1/tenants",
			auth.RequirePlatformAdmin(http.HandlerFunc(deps.TenantHandler.HandleCreate)),
		)
		protectedMux.Handle("GET /api/v1/tenants/{id}",
			auth.RequirePlatformAdmin(http.HandlerFunc(deps.TenantHandler.HandleGet)),
		)
		protectedMux.Handle("GET /api/v1/tenants",
			auth.RequirePlatformAdmin(http.HandlerFunc(deps.TenantHandler.HandleList)),
		)
	}

	// Department routes (tenant-scoped, RBAC-protected)
	if deps.DepartmentHandler != nil && deps.RBAC != nil {
		protectedMux.Handle("POST /api/v1/departments",
			rbac.RequirePermission(deps.RBAC, "departments:write", rbacOpts...)(
				http.HandlerFunc(deps.DepartmentHandler.HandleCreate),
			),
		)
		protectedMux.Handle("GET /api/v1/departments/{id}",
			rbac.RequirePermission(deps.RBAC, "departments:read", rbacOpts...)(
				http.HandlerFunc(deps.DepartmentHandler.HandleGet),
			),
		)
		protectedMux.Handle("GET /api/v1/departments",
			rbac.RequirePermission(deps.RBAC, "departments:read", rbacOpts...)(
				http.HandlerFunc(deps.DepartmentHandler.HandleList),
			),
		)
	}

	// User routes (tenant-scoped, RBAC-protected)
	if deps.UserHandler != nil && deps.RBAC != nil {
		protectedMux.Handle("POST /api/v1/users",
			rbac.RequirePermission(deps.RBAC, "users:write", rbacOpts...)(
				http.HandlerFunc(deps.UserHandler.HandleCreate),
			),
		)
		protectedMux.Handle("GET /api/v1/users/{id}",
			rbac.RequirePermission(deps.RBAC, "users:read", rbacOpts...)(
				http.HandlerFunc(deps.UserHandler.HandleGet),
			),
		)
		protectedMux.Handle("GET /api/v1/users",
			rbac.RequirePermission(deps.RBAC, "users:read", rbacOpts...)(
				http.HandlerFunc(deps.UserHandler.HandleList),
			),
		)
		protectedMux.Handle("POST /api/v1/users/{id}/departments",
			rbac.RequirePermission(deps.RBAC, "users:write", rbacOpts...)(
				http.HandlerFunc(deps.UserHandler.HandleAddToDepartment),
			),
		)
		protectedMux.Handle("DELETE /api/v1/users/{id}/departments/{deptId}",
			rbac.RequirePermission(deps.RBAC, "users:write", rbacOpts...)(
				http.HandlerFunc(deps.UserHandler.HandleRemoveFromDepartment),
			),
		)
	}

	// Role routes (tenant-scoped, RBAC-protected)
	if deps.RoleHandler != nil && deps.RBAC != nil {
		protectedMux.Handle("POST /api/v1/roles",
			rbac.RequirePermission(deps.RBAC, "users:manage", rbacOpts...)(
				http.HandlerFunc(deps.RoleHandler.HandleCreate),
			),
		)
		protectedMux.Handle("GET /api/v1/roles",
			rbac.RequirePermission(deps.RBAC, "users:read", rbacOpts...)(
				http.HandlerFunc(deps.RoleHandler.HandleList),
			),
		)
		protectedMux.Handle("POST /api/v1/users/{id}/roles",
			rbac.RequirePermission(deps.RBAC, "users:manage", rbacOpts...)(
				http.HandlerFunc(deps.RoleHandler.HandleAssignRole),
			),
		)
		protectedMux.Handle("DELETE /api/v1/users/{id}/roles",
			rbac.RequirePermission(deps.RBAC, "users:manage", rbacOpts...)(
				http.HandlerFunc(deps.RoleHandler.HandleRemoveRole),
			),
		)
		protectedMux.Handle("GET /api/v1/users/{id}/roles",
			rbac.RequirePermission(deps.RBAC, "users:read", rbacOpts...)(
				http.HandlerFunc(deps.RoleHandler.HandleListUserRoles),
			),
		)
	}

	// Audit routes
	if deps.AuditHandler != nil && deps.RBAC != nil {
		protectedMux.Handle("GET /api/v1/audit/events",
			rbac.RequirePermission(deps.RBAC, "audit:read", rbacOpts...)(
				http.HandlerFunc(deps.AuditHandler.HandleListEvents),
			),
		)
	}

	// Connector routes (tenant-scoped, RBAC-protected)
	if deps.ConnectorHandler != nil && deps.RBAC != nil {
		protectedMux.Handle("POST /api/v1/connectors",
			rbac.RequirePermission(deps.RBAC, "connectors:write", rbacOpts...)(
				http.HandlerFunc(deps.ConnectorHandler.HandleCreate),
			),
		)
		protectedMux.Handle("GET /api/v1/connectors",
			rbac.RequirePermission(deps.RBAC, "connectors:read", rbacOpts...)(
				http.HandlerFunc(deps.ConnectorHandler.HandleList),
			),
		)
		protectedMux.Handle("DELETE /api/v1/connectors/{id}",
			rbac.RequirePermission(deps.RBAC, "connectors:write", rbacOpts...)(
				http.HandlerFunc(deps.ConnectorHandler.HandleDelete),
			),
		)
	}

	// Channel link routes (tenant-scoped, RBAC-protected)
	if deps.ChannelHandler != nil && deps.RBAC != nil {
		protectedMux.Handle("GET /api/v1/channels/links",
			rbac.RequirePermission(deps.RBAC, "channels:links:read", rbacOpts...)(
				http.HandlerFunc(deps.ChannelHandler.HandleListLinks),
			),
		)
		protectedMux.Handle("POST /api/v1/channels/links",
			rbac.RequirePermission(deps.RBAC, "channels:links:write", rbacOpts...)(
				http.HandlerFunc(deps.ChannelHandler.HandleCreateLink),
			),
		)
		protectedMux.Handle("DELETE /api/v1/channels/links/{id}",
			rbac.RequirePermission(deps.RBAC, "channels:links:write", rbacOpts...)(
				http.HandlerFunc(deps.ChannelHandler.HandleDeleteLink),
			),
		)
		protectedMux.Handle("GET /api/v1/channels/outbox",
			rbac.RequirePermission(deps.RBAC, "channels:outbox:read", rbacOpts...)(
				http.HandlerFunc(deps.ChannelHandler.HandleListOutbox),
			),
		)
		protectedMux.Handle("POST /api/v1/channels/outbox/{id}/requeue",
			rbac.RequirePermission(deps.RBAC, "channels:outbox:write", rbacOpts...)(
				http.HandlerFunc(deps.ChannelHandler.HandleRequeueOutboxDead),
			),
		)
		protectedMux.Handle("GET /api/v1/channels/providers/{provider}/credentials",
			rbac.RequirePermission(deps.RBAC, "channels:providers:read", rbacOpts...)(
				http.HandlerFunc(deps.ChannelHandler.HandleGetProviderCredential),
			),
		)
		protectedMux.Handle("PUT /api/v1/channels/providers/{provider}/credentials",
			rbac.RequirePermission(deps.RBAC, "channels:providers:write", rbacOpts...)(
				http.HandlerFunc(deps.ChannelHandler.HandleUpsertProviderCredential),
			),
		)
		protectedMux.Handle("DELETE /api/v1/channels/providers/{provider}/credentials",
			rbac.RequirePermission(deps.RBAC, "channels:providers:write", rbacOpts...)(
				http.HandlerFunc(deps.ChannelHandler.HandleDeleteProviderCredential),
			),
		)
	}

	// All other routes go through auth middleware
	topMux.Handle("/", protectedHandler)

	// Wrap top-level mux with observability middleware
	var handler http.Handler = topMux
	if deps.Logger != nil {
		handler = middleware.Logging(deps.Logger)(handler)
	}
	handler = middleware.RequestID(handler)
	if len(deps.CORSAllowedOrigins) > 0 {
		handler = middleware.CORS(deps.CORSAllowedOrigins)(handler)
	}

	s.handler = handler
	s.httpServer.Handler = handler
	return s
}

// Handler returns the full middleware-wrapped handler chain (for testing).
func (s *Server) Handler() http.Handler {
	return s.handler
}

// ProtectedMux returns the mux for authenticated routes.
// Use this to register routes that require authentication.
func (s *Server) ProtectedMux() *http.ServeMux {
	return s.protectedMux
}

func (s *Server) Start(ctx context.Context) error {
	lc := net.ListenConfig{}
	listener, err := lc.Listen(ctx, "tcp", s.httpServer.Addr)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", s.httpServer.Addr, err)
	}

	slog.Info("server starting", "addr", listener.Addr().String())

	errCh := make(chan error, 1)
	go func() {
		if err := s.httpServer.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		slog.Info("server shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return s.httpServer.Shutdown(shutdownCtx)
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleReadiness(w http.ResponseWriter, r *http.Request) {
	if s.pool == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"status": "not ready",
			"reason": "database not connected",
		})
		return
	}

	if err := s.pool.Ping(r.Context()); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"status": "not ready",
			"reason": "database ping failed",
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
