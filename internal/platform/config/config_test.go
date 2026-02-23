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
	assert.True(t, cfg.Channels.Ingress.RetentionCleanupEnabled)
	assert.Equal(t, 3600, cfg.Channels.Ingress.RetentionCleanupIntervalSeconds)
	assert.Equal(t, 500, cfg.Channels.Ingress.RetentionCleanupBatchSize)
	assert.Equal(t, 500, cfg.Channels.Ingress.TenantScanPageSize)
	assert.False(t, cfg.Channels.Providers.Slack.Enabled)
	assert.Equal(t, "https://slack.com", cfg.Channels.Providers.Slack.APIBaseURL)
	assert.False(t, cfg.Channels.Providers.WhatsApp.Enabled)
	assert.Equal(t, "https://graph.facebook.com", cfg.Channels.Providers.WhatsApp.APIBaseURL)
	assert.Equal(t, "v22.0", cfg.Channels.Providers.WhatsApp.APIVersion)
	assert.False(t, cfg.Channels.Providers.Telegram.Enabled)
	assert.Equal(t, "https://api.telegram.org", cfg.Channels.Providers.Telegram.APIBaseURL)
}

func TestLoad_ChannelsEnvOverrides(t *testing.T) {
	os.Setenv("VALINOR_CHANNELS_INGRESS_ENABLED", "true")
	os.Setenv("VALINOR_CHANNELS_INGRESS_RETENTIONCLEANUPENABLED", "false")
	os.Setenv("VALINOR_CHANNELS_INGRESS_RETENTIONCLEANUPINTERVALSECONDS", "1800")
	os.Setenv("VALINOR_CHANNELS_INGRESS_RETENTIONCLEANUPBATCHSIZE", "333")
	os.Setenv("VALINOR_CHANNELS_INGRESS_TENANTSCANPAGESIZE", "777")
	os.Setenv("VALINOR_CHANNELS_PROVIDERS_SLACK_ENABLED", "true")
	os.Setenv("VALINOR_CHANNELS_PROVIDERS_SLACK_APIBASEURL", "https://slack.test")
	os.Setenv("VALINOR_CHANNELS_PROVIDERS_SLACK_ACCESSTOKEN", "xoxb-slack-token")
	os.Setenv("VALINOR_CHANNELS_PROVIDERS_WHATSAPP_ENABLED", "true")
	os.Setenv("VALINOR_CHANNELS_PROVIDERS_WHATSAPP_SIGNINGSECRET", "wa-secret")
	os.Setenv("VALINOR_CHANNELS_PROVIDERS_WHATSAPP_APIBASEURL", "https://graph.test")
	os.Setenv("VALINOR_CHANNELS_PROVIDERS_WHATSAPP_APIVERSION", "v99.0")
	os.Setenv("VALINOR_CHANNELS_PROVIDERS_WHATSAPP_ACCESSTOKEN", "wa-access-token")
	os.Setenv("VALINOR_CHANNELS_PROVIDERS_WHATSAPP_PHONENUMBERID", "123456789")
	os.Setenv("VALINOR_CHANNELS_PROVIDERS_TELEGRAM_ENABLED", "true")
	os.Setenv("VALINOR_CHANNELS_PROVIDERS_TELEGRAM_APIBASEURL", "https://telegram.test")
	os.Setenv("VALINOR_CHANNELS_PROVIDERS_TELEGRAM_ACCESSTOKEN", "123456:ABCDEF")
	defer func() {
		os.Unsetenv("VALINOR_CHANNELS_INGRESS_ENABLED")
		os.Unsetenv("VALINOR_CHANNELS_INGRESS_RETENTIONCLEANUPENABLED")
		os.Unsetenv("VALINOR_CHANNELS_INGRESS_RETENTIONCLEANUPINTERVALSECONDS")
		os.Unsetenv("VALINOR_CHANNELS_INGRESS_RETENTIONCLEANUPBATCHSIZE")
		os.Unsetenv("VALINOR_CHANNELS_INGRESS_TENANTSCANPAGESIZE")
		os.Unsetenv("VALINOR_CHANNELS_PROVIDERS_SLACK_ENABLED")
		os.Unsetenv("VALINOR_CHANNELS_PROVIDERS_SLACK_APIBASEURL")
		os.Unsetenv("VALINOR_CHANNELS_PROVIDERS_SLACK_ACCESSTOKEN")
		os.Unsetenv("VALINOR_CHANNELS_PROVIDERS_WHATSAPP_ENABLED")
		os.Unsetenv("VALINOR_CHANNELS_PROVIDERS_WHATSAPP_SIGNINGSECRET")
		os.Unsetenv("VALINOR_CHANNELS_PROVIDERS_WHATSAPP_APIBASEURL")
		os.Unsetenv("VALINOR_CHANNELS_PROVIDERS_WHATSAPP_APIVERSION")
		os.Unsetenv("VALINOR_CHANNELS_PROVIDERS_WHATSAPP_ACCESSTOKEN")
		os.Unsetenv("VALINOR_CHANNELS_PROVIDERS_WHATSAPP_PHONENUMBERID")
		os.Unsetenv("VALINOR_CHANNELS_PROVIDERS_TELEGRAM_ENABLED")
		os.Unsetenv("VALINOR_CHANNELS_PROVIDERS_TELEGRAM_APIBASEURL")
		os.Unsetenv("VALINOR_CHANNELS_PROVIDERS_TELEGRAM_ACCESSTOKEN")
	}()

	cfg, err := config.Load()
	require.NoError(t, err)

	assert.True(t, cfg.Channels.Ingress.Enabled)
	assert.False(t, cfg.Channels.Ingress.RetentionCleanupEnabled)
	assert.Equal(t, 1800, cfg.Channels.Ingress.RetentionCleanupIntervalSeconds)
	assert.Equal(t, 333, cfg.Channels.Ingress.RetentionCleanupBatchSize)
	assert.Equal(t, 777, cfg.Channels.Ingress.TenantScanPageSize)
	assert.True(t, cfg.Channels.Providers.Slack.Enabled)
	assert.Equal(t, "https://slack.test", cfg.Channels.Providers.Slack.APIBaseURL)
	assert.Equal(t, "xoxb-slack-token", cfg.Channels.Providers.Slack.AccessToken)
	assert.True(t, cfg.Channels.Providers.WhatsApp.Enabled)
	assert.Equal(t, "wa-secret", cfg.Channels.Providers.WhatsApp.SigningSecret)
	assert.Equal(t, "https://graph.test", cfg.Channels.Providers.WhatsApp.APIBaseURL)
	assert.Equal(t, "v99.0", cfg.Channels.Providers.WhatsApp.APIVersion)
	assert.Equal(t, "wa-access-token", cfg.Channels.Providers.WhatsApp.AccessToken)
	assert.Equal(t, "123456789", cfg.Channels.Providers.WhatsApp.PhoneNumberID)
	assert.True(t, cfg.Channels.Providers.Telegram.Enabled)
	assert.Equal(t, "https://telegram.test", cfg.Channels.Providers.Telegram.APIBaseURL)
	assert.Equal(t, "123456:ABCDEF", cfg.Channels.Providers.Telegram.AccessToken)
}

func TestLoad_ChannelsOutboxDefaults(t *testing.T) {
	cfg, err := config.Load()
	require.NoError(t, err)

	assert.True(t, cfg.Channels.Outbox.Enabled)
	assert.Equal(t, 2, cfg.Channels.Outbox.PollIntervalSeconds)
	assert.Equal(t, 10, cfg.Channels.Outbox.ClaimBatchSize)
	assert.Equal(t, 10, cfg.Channels.Outbox.RecoveryBatchSize)
	assert.Equal(t, 30, cfg.Channels.Outbox.LockTimeoutSeconds)
	assert.Equal(t, 5, cfg.Channels.Outbox.MaxAttempts)
	assert.Equal(t, 5, cfg.Channels.Outbox.BaseRetrySeconds)
	assert.Equal(t, 120, cfg.Channels.Outbox.MaxRetrySeconds)
	assert.Equal(t, 0.2, cfg.Channels.Outbox.JitterFraction)
	assert.Equal(t, 500, cfg.Channels.Outbox.TenantScanPageSize)
}

func TestLoad_ChannelsOutboxEnvOverrides(t *testing.T) {
	os.Setenv("VALINOR_CHANNELS_OUTBOX_ENABLED", "false")
	os.Setenv("VALINOR_CHANNELS_OUTBOX_POLLINTERVALSECONDS", "9")
	os.Setenv("VALINOR_CHANNELS_OUTBOX_CLAIMBATCHSIZE", "17")
	os.Setenv("VALINOR_CHANNELS_OUTBOX_RECOVERYBATCHSIZE", "13")
	os.Setenv("VALINOR_CHANNELS_OUTBOX_LOCKTIMEOUTSECONDS", "44")
	os.Setenv("VALINOR_CHANNELS_OUTBOX_MAXATTEMPTS", "8")
	os.Setenv("VALINOR_CHANNELS_OUTBOX_BASERETRYSECONDS", "7")
	os.Setenv("VALINOR_CHANNELS_OUTBOX_MAXRETRYSECONDS", "180")
	os.Setenv("VALINOR_CHANNELS_OUTBOX_JITTERFRACTION", "0.35")
	os.Setenv("VALINOR_CHANNELS_OUTBOX_TENANTSCANPAGESIZE", "444")
	defer func() {
		os.Unsetenv("VALINOR_CHANNELS_OUTBOX_ENABLED")
		os.Unsetenv("VALINOR_CHANNELS_OUTBOX_POLLINTERVALSECONDS")
		os.Unsetenv("VALINOR_CHANNELS_OUTBOX_CLAIMBATCHSIZE")
		os.Unsetenv("VALINOR_CHANNELS_OUTBOX_RECOVERYBATCHSIZE")
		os.Unsetenv("VALINOR_CHANNELS_OUTBOX_LOCKTIMEOUTSECONDS")
		os.Unsetenv("VALINOR_CHANNELS_OUTBOX_MAXATTEMPTS")
		os.Unsetenv("VALINOR_CHANNELS_OUTBOX_BASERETRYSECONDS")
		os.Unsetenv("VALINOR_CHANNELS_OUTBOX_MAXRETRYSECONDS")
		os.Unsetenv("VALINOR_CHANNELS_OUTBOX_JITTERFRACTION")
		os.Unsetenv("VALINOR_CHANNELS_OUTBOX_TENANTSCANPAGESIZE")
	}()

	cfg, err := config.Load()
	require.NoError(t, err)

	assert.False(t, cfg.Channels.Outbox.Enabled)
	assert.Equal(t, 9, cfg.Channels.Outbox.PollIntervalSeconds)
	assert.Equal(t, 17, cfg.Channels.Outbox.ClaimBatchSize)
	assert.Equal(t, 13, cfg.Channels.Outbox.RecoveryBatchSize)
	assert.Equal(t, 44, cfg.Channels.Outbox.LockTimeoutSeconds)
	assert.Equal(t, 8, cfg.Channels.Outbox.MaxAttempts)
	assert.Equal(t, 7, cfg.Channels.Outbox.BaseRetrySeconds)
	assert.Equal(t, 180, cfg.Channels.Outbox.MaxRetrySeconds)
	assert.Equal(t, 0.35, cfg.Channels.Outbox.JitterFraction)
	assert.Equal(t, 444, cfg.Channels.Outbox.TenantScanPageSize)
}
