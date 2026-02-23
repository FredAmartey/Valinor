package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/valinor-ai/valinor/internal/audit"
	"github.com/valinor-ai/valinor/internal/auth"
	"github.com/valinor-ai/valinor/internal/channels"
	"github.com/valinor-ai/valinor/internal/connectors"
	"github.com/valinor-ai/valinor/internal/orchestrator"
	"github.com/valinor-ai/valinor/internal/platform/config"
	"github.com/valinor-ai/valinor/internal/platform/database"
	"github.com/valinor-ai/valinor/internal/platform/middleware"
	"github.com/valinor-ai/valinor/internal/platform/server"
	"github.com/valinor-ai/valinor/internal/platform/telemetry"
	"github.com/valinor-ai/valinor/internal/proxy"
	"github.com/valinor-ai/valinor/internal/rbac"
	"github.com/valinor-ai/valinor/internal/sentinel"
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
		p, dbErr := database.Connect(ctx, cfg.Database.URL, cfg.Database.MaxConns)
		if dbErr != nil {
			slog.Warn("database connection failed, starting without DB", "error", dbErr)
		} else {
			pool = p
			defer pool.Close()

			// Run migrations
			migrationsURL := fmt.Sprintf("file://%s", cfg.Database.MigrationsPath)
			if migrateErr := database.RunMigrations(cfg.Database.URL, migrationsURL); migrateErr != nil {
				return fmt.Errorf("running migrations: %w", migrateErr)
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
	connectorHandler := buildConnectorHandler(pool)
	channelHandler, err := buildChannelHandler(pool, cfg.Channels)
	if err != nil {
		return fmt.Errorf("building channel handler: %w", err)
	}

	// RBAC
	rbacEngine := rbac.NewEvaluator(nil)

	// Register default system roles
	rbacEngine.RegisterRole("org_admin", []string{"*"})
	rbacEngine.RegisterRole("dept_head", []string{
		"agents:read", "agents:write", "agents:message",
		"users:read", "users:write",
		"departments:read",
		"connectors:read", "connectors:write",
		"channels:links:read", "channels:links:write", "channels:messages:write",
	})
	rbacEngine.RegisterRole("standard_user", []string{
		"agents:read", "agents:message",
		"channels:messages:write",
	})
	rbacEngine.RegisterRole("read_only", []string{
		"agents:read",
	})

	// Audit
	var auditLogger audit.Logger = audit.NopLogger{}
	if pool != nil {
		auditStore := audit.NewStore()
		auditLogger = audit.NewAsyncLogger(pool, auditStore, audit.LoggerConfig{
			BufferSize:    cfg.Audit.BufferSize,
			BatchSize:     cfg.Audit.BatchSize,
			FlushInterval: time.Duration(cfg.Audit.FlushInterval) * time.Millisecond,
		})
		defer auditLogger.Close()
		slog.Info("audit logger started")
	}

	// Audit query handler
	var auditHandler *audit.Handler
	if pool != nil {
		auditHandler = audit.NewHandler(pool)
	}

	// Sentinel
	var sentinelScanner sentinel.Sentinel = sentinel.NopSentinel{}
	if cfg.Sentinel.Enabled {
		patterns := sentinel.NewPatternMatcher(sentinel.DefaultPatterns())
		var llm sentinel.Sentinel
		if cfg.Sentinel.LLMEnabled && cfg.Sentinel.AnthropicKey != "" {
			llm = sentinel.NewLLMClassifier(sentinel.LLMConfig{
				BaseURL:        "https://api.anthropic.com",
				APIKey:         cfg.Sentinel.AnthropicKey,
				BlockThreshold: cfg.Sentinel.BlockThreshold,
			})
		}
		sentinelScanner = sentinel.NewComposite(patterns, llm)
		slog.Info("sentinel enabled", "llm", cfg.Sentinel.LLMEnabled)
	}

	// Orchestrator — build manager and handler; background loops start after signal context.
	var agentHandler *orchestrator.Handler
	var orchManager *orchestrator.Manager
	var proxyHandler *proxy.Handler
	var connPool *proxy.ConnPool
	if pool != nil {
		orchStore := orchestrator.NewStore()
		orchDriver, err := selectVMDriver(cfg.Orchestrator, cfg.Auth.DevMode)
		if err != nil {
			return fmt.Errorf("selecting orchestrator driver: %w", err)
		}
		orchCfg := orchestrator.ManagerConfig{
			Driver:                 cfg.Orchestrator.Driver,
			WarmPoolSize:           cfg.Orchestrator.WarmPoolSize,
			HealthInterval:         time.Duration(cfg.Orchestrator.HealthIntervalSecs) * time.Second,
			ReconcileInterval:      time.Duration(cfg.Orchestrator.ReconcileIntervalSecs) * time.Second,
			MaxConsecutiveFailures: cfg.Orchestrator.MaxConsecutiveFailures,
		}
		orchManager = orchestrator.NewManager(pool, orchDriver, orchStore, orchCfg)

		// Proxy — agent messaging and config push
		transport := proxy.NewTCPTransport(cfg.Proxy.TCPBasePort)
		connPool = proxy.NewConnPool(transport)

		var pusher orchestrator.ConfigPusher = &configPusherAdapter{
			pool:    connPool,
			timeout: time.Duration(cfg.Proxy.ConfigTimeout) * time.Second,
		}

		agentHandler = orchestrator.NewHandler(orchManager, pusher)

		proxyHandler = proxy.NewHandler(connPool, orchManager, proxy.HandlerConfig{
			MessageTimeout: time.Duration(cfg.Proxy.MessageTimeout) * time.Second,
			ConfigTimeout:  time.Duration(cfg.Proxy.ConfigTimeout) * time.Second,
			PingTimeout:    time.Duration(cfg.Proxy.PingTimeout) * time.Second,
		}, &sentinelAdapter{s: sentinelScanner}, &auditAdapter{l: auditLogger})
	}
	if connPool != nil {
		defer connPool.Close()
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
		ProxyHandler:      proxyHandler,
		AuditHandler:      auditHandler,
		ConnectorHandler:  connectorHandler,
		ChannelHandler:    channelHandler,
		RBACAuditLogger:   &rbacAuditAdapter{l: auditLogger},
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

func buildConnectorHandler(pool *database.Pool) *connectors.Handler {
	if pool == nil {
		return nil
	}
	return connectors.NewHandler(pool, connectors.NewStore())
}

func buildChannelHandler(pool *database.Pool, cfg config.ChannelsConfig) (*channels.Handler, error) {
	if !cfg.Ingress.Enabled {
		return nil, nil
	}
	if pool == nil {
		return nil, fmt.Errorf("database pool is required when channels ingress is enabled")
	}

	replayWindow := time.Duration(cfg.Ingress.ReplayWindowSeconds) * time.Second
	if replayWindow <= 0 {
		replayWindow = 24 * time.Hour
	}

	store := channels.NewStore()
	resolveLink := func(ctx context.Context, platform, platformUserID string) (*channels.ChannelLink, error) {
		tenantID := middleware.GetTenantID(ctx)
		if tenantID == "" {
			return nil, fmt.Errorf("tenant context required")
		}

		var link *channels.ChannelLink
		err := database.WithTenantConnection(ctx, pool, tenantID, func(ctx context.Context, q database.Querier) error {
			var lookupErr error
			link, lookupErr = store.GetLinkByIdentity(ctx, q, platform, platformUserID)
			return lookupErr
		})
		return link, err
	}
	insertIdempotency := func(ctx context.Context, msg channels.IngressMessage) (bool, error) {
		tenantID := middleware.GetTenantID(ctx)
		if tenantID == "" {
			return false, fmt.Errorf("tenant context required")
		}

		var firstSeen bool
		err := database.WithTenantConnection(ctx, pool, tenantID, func(ctx context.Context, q database.Querier) error {
			var insertErr error
			firstSeen, insertErr = store.InsertIdempotency(
				ctx,
				q,
				msg.Platform,
				msg.PlatformUserID,
				msg.PlatformMessageID,
				msg.IdempotencyKey,
				msg.PayloadFingerprint,
				msg.CorrelationID,
				msg.ExpiresAt,
			)
			return insertErr
		})
		return firstSeen, err
	}

	ingressByProvider := map[string]*channels.IngressGuard{}

	if cfg.Providers.Slack.Enabled {
		if cfg.Providers.Slack.SigningSecret == "" {
			return nil, fmt.Errorf("slack signing secret is required when provider is enabled")
		}
		ingressByProvider["slack"] = channels.NewIngressGuard(
			channels.NewSlackVerifier(cfg.Providers.Slack.SigningSecret, 5*time.Minute),
			replayWindow,
			resolveLink,
			insertIdempotency,
		)
	}

	if cfg.Providers.WhatsApp.Enabled {
		if cfg.Providers.WhatsApp.SigningSecret == "" {
			return nil, fmt.Errorf("whatsapp signing secret is required when provider is enabled")
		}
		ingressByProvider["whatsapp"] = channels.NewIngressGuard(
			channels.NewWhatsAppVerifier(cfg.Providers.WhatsApp.SigningSecret),
			replayWindow,
			resolveLink,
			insertIdempotency,
		)
	}

	if cfg.Providers.Telegram.Enabled {
		if cfg.Providers.Telegram.SecretToken == "" {
			return nil, fmt.Errorf("telegram secret token is required when provider is enabled")
		}
		ingressByProvider["telegram"] = channels.NewIngressGuard(
			channels.NewTelegramVerifier(cfg.Providers.Telegram.SecretToken),
			replayWindow,
			resolveLink,
			insertIdempotency,
		)
	}

	if len(ingressByProvider) == 0 {
		slog.Warn("channels ingress enabled but no providers configured")
		return nil, nil
	}

	return channels.NewHandler(ingressByProvider), nil
}

// configPusherAdapter wraps proxy.ConnPool to implement orchestrator.ConfigPusher.
type configPusherAdapter struct {
	pool    *proxy.ConnPool
	timeout time.Duration
}

func (a *configPusherAdapter) PushConfig(ctx context.Context, agentID string, cid uint32, config map[string]any, toolAllowlist []string, toolPolicies map[string]any, canaryTokens []string) error {
	return proxy.PushConfig(ctx, a.pool, agentID, cid, config, toolAllowlist, toolPolicies, canaryTokens, a.timeout)
}

// sentinelAdapter bridges sentinel.Sentinel to proxy.Sentinel.
type sentinelAdapter struct {
	s sentinel.Sentinel
}

func (a *sentinelAdapter) Scan(ctx context.Context, input proxy.SentinelInput) (proxy.SentinelResult, error) {
	result, err := a.s.Scan(ctx, sentinel.ScanInput{
		TenantID: input.TenantID,
		UserID:   input.UserID,
		Content:  input.Content,
	})
	if err != nil {
		return proxy.SentinelResult{}, err
	}
	return proxy.SentinelResult{
		Allowed:    result.Allowed,
		Score:      result.Score,
		Reason:     result.Reason,
		Quarantine: result.Quarantine,
	}, nil
}

// auditAdapter bridges audit.Logger to proxy.AuditLogger.
type auditAdapter struct {
	l audit.Logger
}

func (a *auditAdapter) Log(ctx context.Context, event proxy.AuditEvent) {
	a.l.Log(ctx, audit.Event{
		TenantID:     event.TenantID,
		UserID:       event.UserID,
		Action:       event.Action,
		ResourceType: event.ResourceType,
		ResourceID:   event.ResourceID,
		Metadata:     event.Metadata,
		Source:       event.Source,
	})
}

// rbacAuditAdapter bridges audit.Logger to rbac.AuditLogger.
type rbacAuditAdapter struct {
	l audit.Logger
}

func (a *rbacAuditAdapter) Log(ctx context.Context, event rbac.AuditEvent) {
	a.l.Log(ctx, audit.Event{
		TenantID:     event.TenantID,
		UserID:       event.UserID,
		Action:       event.Action,
		ResourceType: event.ResourceType,
		ResourceID:   event.ResourceID,
		Metadata:     event.Metadata,
		Source:       event.Source,
	})
}
