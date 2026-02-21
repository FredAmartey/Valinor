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
	"github.com/valinor-ai/valinor/internal/auth"
	"github.com/valinor-ai/valinor/internal/platform/middleware"
	"github.com/valinor-ai/valinor/internal/rbac"
)

// Dependencies holds all injected dependencies for the server.
type Dependencies struct {
	Pool        *pgxpool.Pool
	Auth        *auth.TokenService
	AuthHandler *auth.Handler
	RBAC        *rbac.Evaluator
	DevMode     bool
	DevIdentity *auth.Identity
	Logger      *slog.Logger
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
			WriteTimeout: 15 * time.Second,
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

	// Wire RBAC-protected routes
	if deps.RBAC != nil {
		protectedMux.Handle("GET /api/v1/agents",
			rbac.RequirePermission(deps.RBAC, "agents:read")(
				http.HandlerFunc(s.handleListAgents),
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

func (s *Server) handleListAgents(w http.ResponseWriter, r *http.Request) {
	// Placeholder — will be replaced with real agent listing once the agents domain is built.
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "agents": []any{}})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
