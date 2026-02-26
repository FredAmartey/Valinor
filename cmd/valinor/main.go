package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
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

	// RBAC
	roleLoader := tenant.NewRoleLoaderAdapter(tenant.NewRoleStore(), pool)
	rbacEngine := rbac.NewEvaluator(nil, rbac.WithRoleLoader(roleLoader))
	if pool != nil {
		if reloadErr := rbacEngine.ReloadRoles(ctx); reloadErr != nil {
			return fmt.Errorf("loading roles from database: %w", reloadErr)
		}
		slog.Info("RBAC roles loaded from database")
	} else {
		// Fallback for no-DB mode: register defaults in-memory with dev tenant
		const devTenant = "00000000-0000-0000-0000-000000000000"
		rbacEngine.RegisterRole(devTenant, "org_admin", []string{"*"})
		rbacEngine.RegisterRole(devTenant, "dept_head", []string{
			"agents:read", "agents:write", "agents:message",
			"users:read", "users:write",
			"departments:read",
			"connectors:read", "connectors:write",
			"channels:links:read", "channels:links:write", "channels:messages:write",
			"channels:outbox:read", "channels:outbox:write",
			"channels:providers:read", "channels:providers:write",
		})
		rbacEngine.RegisterRole(devTenant, "standard_user", []string{
			"agents:read", "agents:message",
			"channels:messages:write",
		})
		rbacEngine.RegisterRole(devTenant, "read_only", []string{
			"agents:read",
		})
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
		roleHandler = tenant.NewRoleHandler(pool, roleStore, userMgmtStore, deptStore, rbacEngine)
	}
	connectorHandler := buildConnectorHandler(pool)
	channelHandler, err := buildChannelHandler(pool, cfg.Channels)
	if err != nil {
		return fmt.Errorf("building channel handler: %w", err)
	}
	channelRetentionWorker := buildChannelRetentionWorker(pool, cfg.Channels)
	channelOutboxWorker, err := buildChannelOutboxWorker(pool, cfg.Channels)
	if err != nil {
		return fmt.Errorf("building channel outbox worker: %w", err)
	}

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
	var orchStore *orchestrator.Store
	var proxyHandler *proxy.Handler
	var connPool *proxy.ConnPool
	var userContextStore proxy.UserContextStore
	if pool != nil {
		orchStore = orchestrator.NewStore()
		orchDriver, err := selectVMDriver(cfg.Orchestrator, cfg.Auth.DevMode)
		if err != nil {
			return fmt.Errorf("selecting orchestrator driver: %w", err)
		}
		workspaceQuotaMB := 0
		if strings.EqualFold(cfg.Orchestrator.Driver, "firecracker") && cfg.Orchestrator.Firecracker.Workspace.Enabled {
			workspaceQuotaMB = cfg.Orchestrator.Firecracker.Workspace.QuotaMB
		}
		orchCfg := orchestrator.ManagerConfig{
			Driver:                 cfg.Orchestrator.Driver,
			WarmPoolSize:           cfg.Orchestrator.WarmPoolSize,
			HealthInterval:         time.Duration(cfg.Orchestrator.HealthIntervalSecs) * time.Second,
			ReconcileInterval:      time.Duration(cfg.Orchestrator.ReconcileIntervalSecs) * time.Second,
			MaxConsecutiveFailures: cfg.Orchestrator.MaxConsecutiveFailures,
			WorkspaceDataQuotaMB:   workspaceQuotaMB,
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

		userContextStore = proxy.NewDBUserContextStore(pool)
		proxyHandler = proxy.NewHandler(connPool, orchManager, proxy.HandlerConfig{
			MessageTimeout: time.Duration(cfg.Proxy.MessageTimeout) * time.Second,
			ConfigTimeout:  time.Duration(cfg.Proxy.ConfigTimeout) * time.Second,
			PingTimeout:    time.Duration(cfg.Proxy.PingTimeout) * time.Second,
		}, &sentinelAdapter{s: sentinelScanner}, &auditAdapter{l: auditLogger}).WithUserContextStore(userContextStore)
	}
	if connPool != nil {
		defer connPool.Close()
	}

	if channelHandler != nil {
		executor := newChannelExecutor(
			func(ctx context.Context, userID string) (*auth.Identity, error) {
				if authStore == nil {
					return nil, fmt.Errorf("auth store is not configured")
				}
				return authStore.GetIdentityWithRoles(ctx, userID)
			},
			func(ctx context.Context, identity *auth.Identity, action string) (*rbac.Decision, error) {
				return rbacEngine.Authorize(ctx, identity, action, "", "")
			},
			func(ctx context.Context, tenantID string) ([]orchestrator.AgentInstance, error) {
				if orchStore == nil || pool == nil {
					return nil, fmt.Errorf("orchestrator store is not configured")
				}
				return orchStore.ListByTenant(ctx, pool, tenantID)
			},
			func(ctx context.Context, agent orchestrator.AgentInstance, content string, history []channels.ChannelConversationTurn, userContext string) (string, error) {
				return dispatchChannelMessageToAgent(
					ctx,
					connPool,
					agent,
					content,
					history,
					userContext,
					time.Duration(cfg.Proxy.MessageTimeout)*time.Second,
				)
			},
			func(ctx context.Context, tenantID, agentID, userID string) (string, error) {
				if userContextStore == nil {
					return "", proxy.ErrUserContextNotFound
				}
				return userContextStore.GetUserContext(ctx, tenantID, agentID, userID)
			},
			func(ctx context.Context, tenantID, userID, content string) (sentinel.ScanResult, error) {
				if sentinelScanner == nil {
					return sentinel.ScanResult{Allowed: true}, nil
				}
				return sentinelScanner.Scan(ctx, sentinel.ScanInput{
					TenantID: tenantID,
					UserID:   userID,
					Content:  content,
				})
			},
			auditLogger,
		)
		channelHandler.WithExecutor(executor)
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
		Pool:               pool,
		Auth:               tokenSvc,
		AuthHandler:        authHandler,
		RBAC:               rbacEngine,
		TenantHandler:      tenantHandler,
		DepartmentHandler:  deptHandler,
		UserHandler:        userHandler,
		RoleHandler:        roleHandler,
		AgentHandler:       agentHandler,
		ProxyHandler:       proxyHandler,
		AuditHandler:       auditHandler,
		ConnectorHandler:   connectorHandler,
		ChannelHandler:     channelHandler,
		RBACAuditLogger:    &rbacAuditAdapter{l: auditLogger},
		DevMode:            cfg.Auth.DevMode,
		DevIdentity:        devIdentity,
		Logger:             logger,
		CORSAllowedOrigins: cfg.CORS.AllowedOrigins,
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
	if channelRetentionWorker != nil {
		go func() {
			if err := channelRetentionWorker.Run(ctx); err != nil {
				slog.Error("channel retention worker stopped", "error", err)
			}
		}()
		slog.Info(
			"channel retention worker started",
			"interval", channelRetentionWorker.interval,
			"batch_size", channelRetentionWorker.batchSize,
			"tenant_scan_page_size", channelRetentionWorker.tenantScanPageSize,
		)
	}
	if channelOutboxWorker != nil {
		go func() {
			if err := channelOutboxWorker.Run(ctx); err != nil {
				slog.Error("channel outbox worker stopped", "error", err)
			}
		}()
		slog.Info(
			"channel outbox worker started",
			"poll_interval", channelOutboxWorker.pollInterval,
			"tenant_scan_page_size", channelOutboxWorker.tenantScanPageSize,
		)
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

	store, err := buildChannelStore(cfg)
	if err != nil {
		return nil, err
	}
	resolveVerifier := newChannelVerifierResolver(pool, store)
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
		ingressByProvider["slack"] = channels.NewIngressGuard(
			resolveVerifier.slackVerifier(),
			replayWindow,
			resolveLink,
			insertIdempotency,
		)
	}

	if cfg.Providers.WhatsApp.Enabled {
		ingressByProvider["whatsapp"] = channels.NewIngressGuard(
			resolveVerifier.whatsAppVerifier(),
			replayWindow,
			resolveLink,
			insertIdempotency,
		)
	}

	if cfg.Providers.Telegram.Enabled {
		ingressByProvider["telegram"] = channels.NewIngressGuard(
			resolveVerifier.telegramVerifier(),
			replayWindow,
			resolveLink,
			insertIdempotency,
		)
	}

	if len(ingressByProvider) == 0 {
		slog.Warn("channels ingress enabled but no providers configured")
		return nil, fmt.Errorf("channels ingress enabled but no providers configured")
	}

	return channels.NewHandler(ingressByProvider).WithLinkStore(pool, store), nil
}

func buildChannelStore(cfg config.ChannelsConfig) (*channels.Store, error) {
	credentialKey := strings.TrimSpace(cfg.Credentials.Key)
	if credentialKey == "" {
		return channels.NewStore(), nil
	}

	crypto, err := channels.NewCredentialCrypto(credentialKey)
	if err != nil {
		return nil, fmt.Errorf("provider credential encryption key is invalid: %w", err)
	}
	return channels.NewStore(channels.WithCredentialCrypto(crypto)), nil
}

type dynamicVerifier struct {
	resolve func(ctx context.Context) (channels.Verifier, error)
}

func (v dynamicVerifier) Verify(headers http.Header, body []byte, now time.Time) error {
	return v.VerifyContext(context.Background(), headers, body, now)
}

func (v dynamicVerifier) VerifyContext(ctx context.Context, headers http.Header, body []byte, now time.Time) error {
	if v.resolve == nil {
		return channels.ErrMissingSignature
	}
	resolved, err := v.resolve(ctx)
	if err != nil {
		if errors.Is(err, channels.ErrProviderCredentialNotFound) ||
			errors.Is(err, channels.ErrProviderSigningSecretRequired) ||
			errors.Is(err, channels.ErrProviderSecretTokenRequired) {
			return channels.ErrMissingSignature
		}
		return err
	}
	return resolved.Verify(headers, body, now)
}

type channelVerifierResolver struct {
	pool  *database.Pool
	store *channels.Store
}

func newChannelVerifierResolver(pool *database.Pool, store *channels.Store) channelVerifierResolver {
	return channelVerifierResolver{
		pool:  pool,
		store: store,
	}
}

func (r channelVerifierResolver) credentialForTenant(ctx context.Context, provider string) (*channels.ProviderCredential, error) {
	if r.pool == nil || r.store == nil {
		return nil, fmt.Errorf("channel verifier resolver is not configured")
	}
	tenantID := middleware.GetTenantID(ctx)
	if tenantID == "" {
		return nil, fmt.Errorf("tenant context required")
	}

	var credential *channels.ProviderCredential
	err := database.WithTenantConnection(ctx, r.pool, tenantID, func(ctx context.Context, q database.Querier) error {
		var lookupErr error
		credential, lookupErr = r.store.GetProviderCredential(ctx, q, provider)
		return lookupErr
	})
	if err != nil {
		return nil, err
	}
	return credential, nil
}

func (r channelVerifierResolver) slackVerifier() channels.Verifier {
	return dynamicVerifier{
		resolve: func(ctx context.Context) (channels.Verifier, error) {
			credential, err := r.credentialForTenant(ctx, "slack")
			if err != nil {
				return nil, err
			}
			secret := strings.TrimSpace(credential.SigningSecret)
			if secret == "" {
				return nil, channels.ErrProviderSigningSecretRequired
			}
			return channels.NewSlackVerifier(secret, 5*time.Minute), nil
		},
	}
}

func (r channelVerifierResolver) whatsAppVerifier() channels.Verifier {
	return dynamicVerifier{
		resolve: func(ctx context.Context) (channels.Verifier, error) {
			credential, err := r.credentialForTenant(ctx, "whatsapp")
			if err != nil {
				return nil, err
			}
			secret := strings.TrimSpace(credential.SigningSecret)
			if secret == "" {
				return nil, channels.ErrProviderSigningSecretRequired
			}
			return channels.NewWhatsAppVerifier(secret), nil
		},
	}
}

func (r channelVerifierResolver) telegramVerifier() channels.Verifier {
	return dynamicVerifier{
		resolve: func(ctx context.Context) (channels.Verifier, error) {
			credential, err := r.credentialForTenant(ctx, "telegram")
			if err != nil {
				return nil, err
			}
			secretToken := strings.TrimSpace(credential.SecretToken)
			if secretToken == "" {
				return nil, channels.ErrProviderSecretTokenRequired
			}
			return channels.NewTelegramVerifier(secretToken), nil
		},
	}
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
