package config_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valinor-ai/valinor/internal/platform/config"
)

func TestLoad_Defaults(t *testing.T) {
	cfg, err := config.Load()
	require.NoError(t, err)

	assert.Equal(t, 8080, cfg.Server.Port)
	assert.Equal(t, "info", cfg.Log.Level)
	assert.Equal(t, "json", cfg.Log.Format)
}

func TestLoad_EnvOverrides(t *testing.T) {
	os.Setenv("VALINOR_SERVER_PORT", "9090")
	os.Setenv("VALINOR_DATABASE_URL", "postgres://test:test@localhost:5432/valinor_test")
	defer func() {
		os.Unsetenv("VALINOR_SERVER_PORT")
		os.Unsetenv("VALINOR_DATABASE_URL")
	}()

	cfg, err := config.Load()
	require.NoError(t, err)

	assert.Equal(t, 9090, cfg.Server.Port)
	assert.Equal(t, "postgres://test:test@localhost:5432/valinor_test", cfg.Database.URL)
}

func TestLoad_AuthDefaults(t *testing.T) {
	cfg, err := config.Load()
	require.NoError(t, err)

	assert.Equal(t, false, cfg.Auth.DevMode)
	assert.Equal(t, "valinor", cfg.Auth.JWT.Issuer)
	assert.Equal(t, 24, cfg.Auth.JWT.ExpiryHours)
	assert.Equal(t, 168, cfg.Auth.JWT.RefreshExpiryHours)
}

func TestLoad_AuthEnvOverrides(t *testing.T) {
	os.Setenv("VALINOR_AUTH_DEVMODE", "true")
	os.Setenv("VALINOR_AUTH_OIDC_ISSUERURL", "https://accounts.google.com")
	os.Setenv("VALINOR_AUTH_OIDC_CLIENTID", "test-client-id")
	os.Setenv("VALINOR_AUTH_OIDC_CLIENTSECRET", "test-secret")
	os.Setenv("VALINOR_AUTH_JWT_SIGNINGKEY", "super-secret-key-at-least-32-chars!!")
	defer func() {
		os.Unsetenv("VALINOR_AUTH_DEVMODE")
		os.Unsetenv("VALINOR_AUTH_OIDC_ISSUERURL")
		os.Unsetenv("VALINOR_AUTH_OIDC_CLIENTID")
		os.Unsetenv("VALINOR_AUTH_OIDC_CLIENTSECRET")
		os.Unsetenv("VALINOR_AUTH_JWT_SIGNINGKEY")
	}()

	cfg, err := config.Load()
	require.NoError(t, err)

	assert.True(t, cfg.Auth.DevMode)
	assert.Equal(t, "https://accounts.google.com", cfg.Auth.OIDC.IssuerURL)
	assert.Equal(t, "test-client-id", cfg.Auth.OIDC.ClientID)
	assert.Equal(t, "test-secret", cfg.Auth.OIDC.ClientSecret)
	assert.Equal(t, "super-secret-key-at-least-32-chars!!", cfg.Auth.JWT.SigningKey)
}

func TestLoad_ChannelsDefaults(t *testing.T) {
	cfg, err := config.Load()
	require.NoError(t, err)

	assert.False(t, cfg.Channels.Ingress.Enabled)
	assert.Equal(t, 86400, cfg.Channels.Ingress.ReplayWindowSeconds)
	assert.False(t, cfg.Channels.Providers.Slack.Enabled)
	assert.False(t, cfg.Channels.Providers.WhatsApp.Enabled)
	assert.False(t, cfg.Channels.Providers.Telegram.Enabled)
}

func TestLoad_ChannelsEnvOverrides(t *testing.T) {
	os.Setenv("VALINOR_CHANNELS_INGRESS_ENABLED", "true")
	os.Setenv("VALINOR_CHANNELS_PROVIDERS_WHATSAPP_ENABLED", "true")
	os.Setenv("VALINOR_CHANNELS_PROVIDERS_WHATSAPP_SIGNINGSECRET", "wa-secret")
	defer func() {
		os.Unsetenv("VALINOR_CHANNELS_INGRESS_ENABLED")
		os.Unsetenv("VALINOR_CHANNELS_PROVIDERS_WHATSAPP_ENABLED")
		os.Unsetenv("VALINOR_CHANNELS_PROVIDERS_WHATSAPP_SIGNINGSECRET")
	}()

	cfg, err := config.Load()
	require.NoError(t, err)

	assert.True(t, cfg.Channels.Ingress.Enabled)
	assert.True(t, cfg.Channels.Providers.WhatsApp.Enabled)
	assert.Equal(t, "wa-secret", cfg.Channels.Providers.WhatsApp.SigningSecret)
}
