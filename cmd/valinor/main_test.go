package main

import (
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valinor-ai/valinor/internal/platform/config"
	"github.com/valinor-ai/valinor/internal/platform/database"
)

func TestBuildConnectorHandler(t *testing.T) {
	assert.Nil(t, buildConnectorHandler(nil))

	pool := (*database.Pool)(&pgxpool.Pool{})
	assert.NotNil(t, buildConnectorHandler(pool))
}

func TestBuildChannelHandler(t *testing.T) {
	t.Run("disabled ingress returns nil handler", func(t *testing.T) {
		handler, err := buildChannelHandler(nil, config.ChannelsConfig{})
		require.NoError(t, err)
		assert.Nil(t, handler)
	})

	t.Run("enabled ingress without database pool fails", func(t *testing.T) {
		_, err := buildChannelHandler(nil, config.ChannelsConfig{
			Ingress: config.ChannelsIngressConfig{
				Enabled: true,
			},
			Providers: config.ChannelsProvidersConfig{
				Slack: config.ChannelProviderConfig{
					Enabled:       true,
					SigningSecret: "slack-secret",
				},
			},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "database")
	})

	t.Run("enabled provider missing secret fails", func(t *testing.T) {
		pool := (*database.Pool)(&pgxpool.Pool{})
		_, err := buildChannelHandler(pool, config.ChannelsConfig{
			Ingress: config.ChannelsIngressConfig{
				Enabled: true,
			},
			Providers: config.ChannelsProvidersConfig{
				Slack: config.ChannelProviderConfig{
					Enabled: true,
				},
			},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "signing secret")
	})

	t.Run("enabled ingress with no providers fails", func(t *testing.T) {
		pool := (*database.Pool)(&pgxpool.Pool{})
		_, err := buildChannelHandler(pool, config.ChannelsConfig{
			Ingress: config.ChannelsIngressConfig{
				Enabled: true,
			},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no providers")
	})

	t.Run("enabled provider with secret returns handler", func(t *testing.T) {
		pool := (*database.Pool)(&pgxpool.Pool{})
		handler, err := buildChannelHandler(pool, config.ChannelsConfig{
			Ingress: config.ChannelsIngressConfig{
				Enabled: true,
			},
			Providers: config.ChannelsProvidersConfig{
				Slack: config.ChannelProviderConfig{
					Enabled:       true,
					SigningSecret: "slack-secret",
				},
			},
		})
		require.NoError(t, err)
		assert.NotNil(t, handler)
	})
}

func TestBuildChannelOutboxWorker(t *testing.T) {
	pool := (*database.Pool)(&pgxpool.Pool{})

	t.Run("disabled ingress returns nil worker", func(t *testing.T) {
		worker, err := buildChannelOutboxWorker(pool, config.ChannelsConfig{
			Ingress: config.ChannelsIngressConfig{Enabled: false},
			Outbox:  config.ChannelsOutboxConfig{Enabled: true},
		})
		require.NoError(t, err)
		assert.Nil(t, worker)
	})

	t.Run("enabled ingress and outbox returns worker", func(t *testing.T) {
		worker, err := buildChannelOutboxWorker(pool, config.ChannelsConfig{
			Ingress: config.ChannelsIngressConfig{Enabled: true},
			Outbox: config.ChannelsOutboxConfig{
				Enabled: true,
			},
		})
		require.NoError(t, err)
		assert.NotNil(t, worker)
		assert.Equal(t, 500, worker.tenantScanPageSize)
	})

	t.Run("non-positive tenant scan page size falls back to default", func(t *testing.T) {
		worker, err := buildChannelOutboxWorker(pool, config.ChannelsConfig{
			Ingress: config.ChannelsIngressConfig{Enabled: true},
			Outbox: config.ChannelsOutboxConfig{
				Enabled:            true,
				TenantScanPageSize: 0,
			},
		})
		require.NoError(t, err)
		require.NotNil(t, worker)
		assert.Equal(t, 500, worker.tenantScanPageSize)
	})

	t.Run("explicit tenant scan page size is respected", func(t *testing.T) {
		worker, err := buildChannelOutboxWorker(pool, config.ChannelsConfig{
			Ingress: config.ChannelsIngressConfig{Enabled: true},
			Outbox: config.ChannelsOutboxConfig{
				Enabled:            true,
				TenantScanPageSize: 275,
			},
		})
		require.NoError(t, err)
		require.NotNil(t, worker)
		assert.Equal(t, 275, worker.tenantScanPageSize)
	})

	t.Run("whatsapp enabled without global outbound credentials still builds worker", func(t *testing.T) {
		worker, err := buildChannelOutboxWorker(pool, config.ChannelsConfig{
			Ingress: config.ChannelsIngressConfig{Enabled: true},
			Outbox: config.ChannelsOutboxConfig{
				Enabled: true,
			},
			Providers: config.ChannelsProvidersConfig{
				WhatsApp: config.ChannelProviderConfig{
					Enabled:       true,
					SigningSecret: "wa-signing-secret",
				},
			},
		})
		require.NoError(t, err)
		assert.NotNil(t, worker)
	})

	t.Run("slack enabled without global outbound credentials still builds worker", func(t *testing.T) {
		worker, err := buildChannelOutboxWorker(pool, config.ChannelsConfig{
			Ingress: config.ChannelsIngressConfig{Enabled: true},
			Outbox: config.ChannelsOutboxConfig{
				Enabled: true,
			},
			Providers: config.ChannelsProvidersConfig{
				Slack: config.ChannelProviderConfig{
					Enabled:       true,
					SigningSecret: "slack-signing-secret",
				},
			},
		})
		require.NoError(t, err)
		assert.NotNil(t, worker)
	})

	t.Run("telegram enabled without global outbound credentials still builds worker", func(t *testing.T) {
		worker, err := buildChannelOutboxWorker(pool, config.ChannelsConfig{
			Ingress: config.ChannelsIngressConfig{Enabled: true},
			Outbox: config.ChannelsOutboxConfig{
				Enabled: true,
			},
			Providers: config.ChannelsProvidersConfig{
				Telegram: config.ChannelProviderConfig{
					Enabled:     true,
					SecretToken: "telegram-secret-token",
				},
			},
		})
		require.NoError(t, err)
		assert.NotNil(t, worker)
	})
}

func TestBuildChannelRetentionWorker(t *testing.T) {
	pool := (*database.Pool)(&pgxpool.Pool{})

	t.Run("disabled ingress returns nil worker", func(t *testing.T) {
		worker := buildChannelRetentionWorker(pool, config.ChannelsConfig{
			Ingress: config.ChannelsIngressConfig{Enabled: false},
		})
		assert.Nil(t, worker)
	})

	t.Run("enabled ingress with cleanup disabled returns nil worker", func(t *testing.T) {
		worker := buildChannelRetentionWorker(pool, config.ChannelsConfig{
			Ingress: config.ChannelsIngressConfig{
				Enabled:                 true,
				RetentionCleanupEnabled: false,
			},
		})
		assert.Nil(t, worker)
	})

	t.Run("enabled ingress cleanup returns worker with defaults", func(t *testing.T) {
		worker := buildChannelRetentionWorker(pool, config.ChannelsConfig{
			Ingress: config.ChannelsIngressConfig{
				Enabled:                 true,
				RetentionCleanupEnabled: true,
			},
		})
		require.NotNil(t, worker)
		assert.Equal(t, time.Hour, worker.interval)
		assert.Equal(t, 500, worker.batchSize)
		assert.Equal(t, 500, worker.tenantScanPageSize)
	})

	t.Run("non-positive cleanup settings fall back to defaults", func(t *testing.T) {
		worker := buildChannelRetentionWorker(pool, config.ChannelsConfig{
			Ingress: config.ChannelsIngressConfig{
				Enabled:                         true,
				RetentionCleanupEnabled:         true,
				RetentionCleanupIntervalSeconds: -1,
				RetentionCleanupBatchSize:       0,
			},
		})
		require.NotNil(t, worker)
		assert.Equal(t, time.Hour, worker.interval)
		assert.Equal(t, 500, worker.batchSize)
		assert.Equal(t, 500, worker.tenantScanPageSize)
	})

	t.Run("non-positive tenant scan page size falls back to default", func(t *testing.T) {
		worker := buildChannelRetentionWorker(pool, config.ChannelsConfig{
			Ingress: config.ChannelsIngressConfig{
				Enabled:                         true,
				RetentionCleanupEnabled:         true,
				RetentionCleanupIntervalSeconds: 120,
				RetentionCleanupBatchSize:       250,
				TenantScanPageSize:              0,
			},
		})
		require.NotNil(t, worker)
		assert.Equal(t, 2*time.Minute, worker.interval)
		assert.Equal(t, 250, worker.batchSize)
		assert.Equal(t, 500, worker.tenantScanPageSize)
	})

	t.Run("explicit cleanup settings are respected", func(t *testing.T) {
		worker := buildChannelRetentionWorker(pool, config.ChannelsConfig{
			Ingress: config.ChannelsIngressConfig{
				Enabled:                         true,
				RetentionCleanupEnabled:         true,
				RetentionCleanupIntervalSeconds: 120,
				RetentionCleanupBatchSize:       250,
				TenantScanPageSize:              125,
			},
		})
		require.NotNil(t, worker)
		assert.Equal(t, 2*time.Minute, worker.interval)
		assert.Equal(t, 250, worker.batchSize)
		assert.Equal(t, 125, worker.tenantScanPageSize)
	})
}
