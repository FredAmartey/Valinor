package main

import (
	"testing"

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
	})

	t.Run("whatsapp enabled without outbound credentials fails", func(t *testing.T) {
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
		require.Error(t, err)
		assert.Nil(t, worker)
		assert.Contains(t, err.Error(), "access token")
	})

	t.Run("slack enabled without outbound credentials fails", func(t *testing.T) {
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
		require.Error(t, err)
		assert.Nil(t, worker)
		assert.Contains(t, err.Error(), "access token")
	})
}
