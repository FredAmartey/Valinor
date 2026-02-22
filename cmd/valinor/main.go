package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/valinor-ai/valinor/internal/auth"
	"github.com/valinor-ai/valinor/internal/orchestrator"
	"github.com/valinor-ai/valinor/internal/platform/config"
	"github.com/valinor-ai/valinor/internal/platform/database"
	"github.com/valinor-ai/valinor/internal/platform/server"
	"github.com/valinor-ai/valinor/internal/platform/telemetry"
	"github.com/valinor-ai/valinor/internal/rbac"
	"github.com/valinor-ai/valinor/internal/tenant"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	// Load configuration
	cfg, err := config.Load("config.yaml")
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	// Setup logging
	logger := telemetry.NewLogger(cfg.Log.Level, cfg.Log.Format)
	telemetry.SetDefault(logger)

	slog.Info("valinor starting",
		"version", "0.2.0",
		"port", cfg.Server.Port,
	)

	// Connect to database (optional for startup — will retry)
	ctx := context.Background()
	var pool *database.Pool

	if cfg.Database.URL != "" {
		slog.Info("connecting to database")
		p, err := database.Connect(ctx, cfg.Database.URL, cfg.Database.MaxConns)
		if err != nil {
			slog.Warn("database connection failed, starting without DB", "error", err)
		} else {
			pool = p
			defer pool.Close()

			// Run migrations
			migrationsURL := fmt.Sprintf("file://%s", cfg.Database.MigrationsPath)
			if err := database.RunMigrations(cfg.Database.URL, migrationsURL); err != nil {
				return fmt.Errorf("running migrations: %w", err)
			}
			slog.Info("migrations complete")
		}
	}

	// Auth
	tokenSvc := auth.NewTokenService(
		cfg.Auth.JWT.SigningKey,
		cfg.Auth.JWT.Issuer,
		cfg.Auth.JWT.ExpiryHours,
		cfg.Auth.JWT.RefreshExpiryHours,
	)

	var authStore *auth.Store
	var refreshStore *auth.RefreshTokenStore
	if pool != nil {
		authStore = auth.NewStore(pool)
		refreshStore = auth.NewRefreshTokenStore(pool)
	}

	stateStore := auth.NewStateStore([]byte(cfg.Auth.JWT.SigningKey), 10*time.Minute)

	var tenantResolver *auth.TenantResolver
	if pool != nil {
		tenantResolver = auth.NewTenantResolver(pool, cfg.Server.BaseDomain)
	}

	authHandler := auth.NewHandler(auth.HandlerConfig{
		TokenSvc:       tokenSvc,
		Store:          authStore,
		RefreshStore:   refreshStore,
		StateStore:     stateStore,
		TenantResolver: tenantResolver,
		// OIDC provider wired when configured
	})

	// Tenant provisioning
	var tenantHandler *tenant.Handler
	if pool != nil {
		tenantStore := tenant.NewStore(pool)
		tenantHandler = tenant.NewHandler(tenantStore)
	}

	// Department, user, and role management (tenant-scoped)
	var deptHandler *tenant.DepartmentHandler
	var userHandler *tenant.UserHandler
	var roleHandler *tenant.RoleHandler
	if pool != nil {
		deptStore := tenant.NewDepartmentStore()
		userMgmtStore := tenant.NewUserStore()
		roleStore := tenant.NewRoleStore()
		deptHandler = tenant.NewDepartmentHandler(pool, deptStore)
		userHandler = tenant.NewUserHandler(pool, userMgmtStore, deptStore)
		roleHandler = tenant.NewRoleHandler(pool, roleStore, userMgmtStore, deptStore)
	}

	// RBAC
	rbacEngine := rbac.NewEvaluator(nil)

	// Register default system roles
	rbacEngine.RegisterRole("org_admin", []string{"*"})
	rbacEngine.RegisterRole("dept_head", []string{
		"agents:read", "agents:write", "agents:message",
		"users:read", "users:write",
		"departments:read",
	})
	rbacEngine.RegisterRole("standard_user", []string{
		"agents:read", "agents:message",
	})
	rbacEngine.RegisterRole("read_only", []string{
		"agents:read",
	})

	// Orchestrator — build manager and handler; background loops start after signal context.
	var agentHandler *orchestrator.Handler
	var orchManager *orchestrator.Manager
	if pool != nil {
		orchStore := orchestrator.NewStore()
		orchDriver := orchestrator.NewMockDriver() // TODO: select driver from config
		orchCfg := orchestrator.ManagerConfig{
			Driver:                 cfg.Orchestrator.Driver,
			WarmPoolSize:           cfg.Orchestrator.WarmPoolSize,
			HealthInterval:         time.Duration(cfg.Orchestrator.HealthIntervalSecs) * time.Second,
			ReconcileInterval:      time.Duration(cfg.Orchestrator.ReconcileIntervalSecs) * time.Second,
			MaxConsecutiveFailures: cfg.Orchestrator.MaxConsecutiveFailures,
		}
		orchManager = orchestrator.NewManager(pool, orchDriver, orchStore, orchCfg)
		agentHandler = orchestrator.NewHandler(orchManager)
	}

	// Dev mode identity
	var devIdentity *auth.Identity
	if cfg.Auth.DevMode {
		slog.Warn("running in dev mode — authentication bypassed with 'Bearer dev'")
		devIdentity = &auth.Identity{
			UserID:   "dev-user",
			TenantID: "dev-tenant",
			Roles:    []string{"org_admin"},
		}
	}

	// Create and start server
	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	srv := server.New(addr, server.Dependencies{
		Pool:              pool,
		Auth:              tokenSvc,
		AuthHandler:       authHandler,
		RBAC:              rbacEngine,
		TenantHandler:     tenantHandler,
		DepartmentHandler: deptHandler,
		UserHandler:       userHandler,
		RoleHandler:       roleHandler,
		AgentHandler:      agentHandler,
		DevMode:           cfg.Auth.DevMode,
		DevIdentity:       devIdentity,
		Logger:            logger,
	})

	// Graceful shutdown on SIGINT/SIGTERM
	ctx, cancel := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Start orchestrator background loops with the signal-aware context.
	if orchManager != nil {
		go func() {
			if err := orchManager.Run(ctx); err != nil {
				slog.Error("orchestrator background loops stopped", "error", err)
			}
		}()
		slog.Info("orchestrator started", "driver", cfg.Orchestrator.Driver, "warm_pool", cfg.Orchestrator.WarmPoolSize)
	}

	slog.Info("server ready", "addr", addr, "dev_mode", cfg.Auth.DevMode)
	return srv.Start(ctx)
}
