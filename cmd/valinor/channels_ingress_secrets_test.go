package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valinor-ai/valinor/internal/platform/config"
	"github.com/valinor-ai/valinor/internal/platform/database"
)

func TestBuildChannelHandler_UsesTenantScopedVerifierSecrets(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupWorkerTestDB(t)
	defer cleanup()

	ctx := context.Background()
	tenantA := seedChannelTenant(t, ctx, pool, "Verifier Tenant A", "verifier-tenant-a", "a")
	tenantB := seedChannelTenant(t, ctx, pool, "Verifier Tenant B", "verifier-tenant-b", "b")

	cfg := config.ChannelsConfig{
		Ingress: config.ChannelsIngressConfig{
			Enabled: true,
		},
		Providers: config.ChannelsProvidersConfig{
			Slack: config.ChannelProviderConfig{
				Enabled: true,
			},
			WhatsApp: config.ChannelProviderConfig{
				Enabled: true,
			},
			Telegram: config.ChannelProviderConfig{
				Enabled: true,
			},
		},
	}
	handler, err := buildChannelHandler(pool, cfg)
	require.NoError(t, err)
	require.NotNil(t, handler)

	now := time.Now().UTC()

	t.Run("slack verifies per tenant secret", func(t *testing.T) {
		body := fmt.Sprintf(`{"type":"event_callback","event_id":"Ev-%d","event":{"user":"U-shared","text":"hello"}}`, now.UnixNano())
		ts := strconv.FormatInt(now.Unix(), 10)

		validReq := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/"+tenantA.id+"/channels/slack/webhook", strings.NewReader(body))
		validReq.SetPathValue("provider", "slack")
		validReq.SetPathValue("tenantID", tenantA.id)
		validReq.Header.Set("X-Slack-Request-Timestamp", ts)
		validReq.Header.Set("X-Slack-Signature", slackSignature(t, tenantA.slackSigningSecret, ts, []byte(body)))
		validResp := httptest.NewRecorder()
		handler.HandleWebhook(validResp, validReq)
		require.Equal(t, http.StatusOK, validResp.Code)
		assert.Contains(t, validResp.Body.String(), "accepted")

		invalidReq := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/"+tenantA.id+"/channels/slack/webhook", strings.NewReader(body))
		invalidReq.SetPathValue("provider", "slack")
		invalidReq.SetPathValue("tenantID", tenantA.id)
		invalidReq.Header.Set("X-Slack-Request-Timestamp", ts)
		invalidReq.Header.Set("X-Slack-Signature", slackSignature(t, tenantB.slackSigningSecret, ts, []byte(body)))
		invalidResp := httptest.NewRecorder()
		handler.HandleWebhook(invalidResp, invalidReq)
		require.Equal(t, http.StatusUnauthorized, invalidResp.Code)
		assert.Contains(t, invalidResp.Body.String(), "rejected_signature")
	})

	t.Run("whatsapp verifies per tenant secret", func(t *testing.T) {
		body := fmt.Sprintf(`{"entry":[{"changes":[{"value":{"messages":[{"from":"+15550000001","id":"wamid-%d","timestamp":"%d","text":{"body":"hello"}}]}}]}]}`, now.UnixNano(), now.Unix())

		validReq := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/"+tenantA.id+"/channels/whatsapp/webhook", strings.NewReader(body))
		validReq.SetPathValue("provider", "whatsapp")
		validReq.SetPathValue("tenantID", tenantA.id)
		validReq.Header.Set("X-Hub-Signature-256", whatsAppSignature(t, tenantA.whatsAppSigningSecret, []byte(body)))
		validResp := httptest.NewRecorder()
		handler.HandleWebhook(validResp, validReq)
		require.Equal(t, http.StatusOK, validResp.Code)
		assert.Contains(t, validResp.Body.String(), "accepted")

		invalidReq := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/"+tenantA.id+"/channels/whatsapp/webhook", strings.NewReader(body))
		invalidReq.SetPathValue("provider", "whatsapp")
		invalidReq.SetPathValue("tenantID", tenantA.id)
		invalidReq.Header.Set("X-Hub-Signature-256", whatsAppSignature(t, tenantB.whatsAppSigningSecret, []byte(body)))
		invalidResp := httptest.NewRecorder()
		handler.HandleWebhook(invalidResp, invalidReq)
		require.Equal(t, http.StatusUnauthorized, invalidResp.Code)
		assert.Contains(t, invalidResp.Body.String(), "rejected_signature")
	})

	t.Run("telegram verifies per tenant secret", func(t *testing.T) {
		body := fmt.Sprintf(`{"message":{"message_id":%d,"date":%d,"text":"hello","from":{"id":70001}}}`, now.UnixNano()%1_000_000_000, now.Unix())

		validReq := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/"+tenantA.id+"/channels/telegram/webhook", strings.NewReader(body))
		validReq.SetPathValue("provider", "telegram")
		validReq.SetPathValue("tenantID", tenantA.id)
		validReq.Header.Set("X-Telegram-Bot-Api-Secret-Token", tenantA.telegramSecretToken)
		validResp := httptest.NewRecorder()
		handler.HandleWebhook(validResp, validReq)
		require.Equal(t, http.StatusOK, validResp.Code)
		assert.Contains(t, validResp.Body.String(), "accepted")

		invalidReq := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/"+tenantA.id+"/channels/telegram/webhook", strings.NewReader(body))
		invalidReq.SetPathValue("provider", "telegram")
		invalidReq.SetPathValue("tenantID", tenantA.id)
		invalidReq.Header.Set("X-Telegram-Bot-Api-Secret-Token", tenantB.telegramSecretToken)
		invalidResp := httptest.NewRecorder()
		handler.HandleWebhook(invalidResp, invalidReq)
		require.Equal(t, http.StatusUnauthorized, invalidResp.Code)
		assert.Contains(t, invalidResp.Body.String(), "rejected_signature")
	})
}

type seededChannelTenant struct {
	id                    string
	slackSigningSecret    string
	whatsAppSigningSecret string
	telegramSecretToken   string
}

func seedChannelTenant(t *testing.T, ctx context.Context, pool *database.Pool, name, slug, suffix string) seededChannelTenant {
	t.Helper()

	var tenantID string
	err := pool.QueryRow(ctx, `INSERT INTO tenants (name, slug) VALUES ($1, $2) RETURNING id`, name, slug).Scan(&tenantID)
	require.NoError(t, err)

	var userID string
	err = pool.QueryRow(ctx, `INSERT INTO users (tenant_id, email, display_name) VALUES ($1, $2, $3) RETURNING id`, tenantID, "user-"+suffix+"@example.com", "User "+suffix).Scan(&userID)
	require.NoError(t, err)

	_, err = pool.Exec(ctx, `INSERT INTO channel_links (tenant_id, user_id, platform, platform_user_id, state, verified) VALUES ($1, $2, 'slack', 'U-shared', 'verified', true)`, tenantID, userID)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `INSERT INTO channel_links (tenant_id, user_id, platform, platform_user_id, state, verified) VALUES ($1, $2, 'whatsapp', '+15550000001', 'verified', true)`, tenantID, userID)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `INSERT INTO channel_links (tenant_id, user_id, platform, platform_user_id, state, verified) VALUES ($1, $2, 'telegram', '70001', 'verified', true)`, tenantID, userID)
	require.NoError(t, err)

	slackSigningSecret := "slack-signing-" + suffix
	whatsAppSigningSecret := "whatsapp-signing-" + suffix
	telegramSecretToken := "telegram-secret-" + suffix

	_, err = pool.Exec(ctx, `INSERT INTO channel_provider_credentials (tenant_id, provider, access_token, signing_secret) VALUES ($1, 'slack', $2, $3)`, tenantID, "xoxb-"+suffix, slackSigningSecret)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `INSERT INTO channel_provider_credentials (tenant_id, provider, access_token, signing_secret, phone_number_id) VALUES ($1, 'whatsapp', $2, $3, $4)`, tenantID, "wa-"+suffix, whatsAppSigningSecret, "100000000"+suffix)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `INSERT INTO channel_provider_credentials (tenant_id, provider, access_token, secret_token) VALUES ($1, 'telegram', $2, $3)`, tenantID, "tg-"+suffix, telegramSecretToken)
	require.NoError(t, err)

	return seededChannelTenant{
		id:                    tenantID,
		slackSigningSecret:    slackSigningSecret,
		whatsAppSigningSecret: whatsAppSigningSecret,
		telegramSecretToken:   telegramSecretToken,
	}
}

func slackSignature(t *testing.T, signingSecret, timestamp string, body []byte) string {
	t.Helper()
	base := "v0:" + timestamp + ":" + string(body)
	mac := hmac.New(sha256.New, []byte(signingSecret))
	_, err := mac.Write([]byte(base))
	require.NoError(t, err)
	return "v0=" + hex.EncodeToString(mac.Sum(nil))
}

func whatsAppSignature(t *testing.T, signingSecret string, body []byte) string {
	t.Helper()
	mac := hmac.New(sha256.New, []byte(signingSecret))
	_, err := mac.Write(body)
	require.NoError(t, err)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}
