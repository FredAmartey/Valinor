package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valinor-ai/valinor/internal/channels"
	"github.com/valinor-ai/valinor/internal/platform/config"
)

func TestBuildChannelOutboxSender(t *testing.T) {
	t.Run("whatsapp enabled missing access token fails", func(t *testing.T) {
		_, err := buildChannelOutboxSender(config.ChannelsConfig{
			Providers: config.ChannelsProvidersConfig{
				WhatsApp: config.ChannelProviderConfig{
					Enabled:       true,
					SigningSecret: "wa-signing-secret",
					PhoneNumberID: "1234567890",
				},
			},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "access token")
	})

	t.Run("whatsapp enabled missing phone number id fails", func(t *testing.T) {
		_, err := buildChannelOutboxSender(config.ChannelsConfig{
			Providers: config.ChannelsProvidersConfig{
				WhatsApp: config.ChannelProviderConfig{
					Enabled:     true,
					AccessToken: "token-123",
				},
			},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "phone number id")
	})

	t.Run("whatsapp enabled with outbound config returns sender", func(t *testing.T) {
		sender, err := buildChannelOutboxSender(config.ChannelsConfig{
			Providers: config.ChannelsProvidersConfig{
				WhatsApp: config.ChannelProviderConfig{
					Enabled:       true,
					SigningSecret: "wa-signing-secret",
					APIBaseURL:    "https://graph.example.com",
					APIVersion:    "v22.0",
					AccessToken:   "test-token",
					PhoneNumberID: "1234567890",
				},
			},
		})
		require.NoError(t, err)
		require.NotNil(t, sender)

		err = sender.Send(context.Background(), channels.ChannelOutbox{
			Provider:    "slack",
			RecipientID: "U12345",
			Payload:     json.RawMessage(`{"content":"hello"}`),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported outbox provider")
	})

	t.Run("no supported provider config fails closed on send", func(t *testing.T) {
		sender, err := buildChannelOutboxSender(config.ChannelsConfig{})
		require.NoError(t, err)
		require.NotNil(t, sender)

		err = sender.Send(context.Background(), channels.ChannelOutbox{
			Provider:    "whatsapp",
			RecipientID: "15550009999",
			Payload:     json.RawMessage(`{"content":"hello"}`),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported outbox provider")
	})
}

func TestWhatsAppOutboxSender_Send(t *testing.T) {
	t.Run("sends whatsapp text message payload", func(t *testing.T) {
		var seenAuth string
		var seenPath string
		var seenBody map[string]any

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			seenAuth = r.Header.Get("Authorization")
			seenPath = r.URL.Path
			defer r.Body.Close()

			decoder := json.NewDecoder(r.Body)
			require.NoError(t, decoder.Decode(&seenBody))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"messages":[{"id":"wamid.outbound.1"}]}`))
		}))
		defer srv.Close()

		sender := newWhatsAppOutboxSender(
			config.ChannelProviderConfig{
				Enabled:       true,
				APIBaseURL:    srv.URL,
				APIVersion:    "v22.0",
				AccessToken:   "token-123",
				PhoneNumberID: "987654321",
			},
			srv.Client(),
		)

		err := sender.Send(context.Background(), channels.ChannelOutbox{
			Provider:    "whatsapp",
			RecipientID: "15550009999",
			Payload:     json.RawMessage(`{"content":"hello from outbox","correlation_id":"corr-123"}`),
		})
		require.NoError(t, err)
		assert.Equal(t, "Bearer token-123", seenAuth)
		assert.Equal(t, "/v22.0/987654321/messages", seenPath)
		assert.Equal(t, "whatsapp", seenBody["messaging_product"])
		assert.Equal(t, "15550009999", seenBody["to"])
		assert.Equal(t, "text", seenBody["type"])

		textPayload, ok := seenBody["text"].(map[string]any)
		require.True(t, ok)
		assert.Equal(t, "hello from outbox", textPayload["body"])
		assert.Equal(t, false, textPayload["preview_url"])
	})

	t.Run("returns error when whatsapp API rejects request", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":{"message":"bad token"}}`))
		}))
		defer srv.Close()

		sender := newWhatsAppOutboxSender(
			config.ChannelProviderConfig{
				Enabled:       true,
				APIBaseURL:    srv.URL,
				APIVersion:    "v22.0",
				AccessToken:   "bad-token",
				PhoneNumberID: "987654321",
			},
			srv.Client(),
		)

		err := sender.Send(context.Background(), channels.ChannelOutbox{
			Provider:    "whatsapp",
			RecipientID: "15550009999",
			Payload:     json.RawMessage(`{"content":"hello from outbox","correlation_id":"corr-123"}`),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "status 401")
		assert.Contains(t, err.Error(), "bad token")
	})

	t.Run("returns error for malformed outbox payload", func(t *testing.T) {
		sender := newWhatsAppOutboxSender(
			config.ChannelProviderConfig{
				Enabled:       true,
				APIBaseURL:    "https://graph.example.com",
				APIVersion:    "v22.0",
				AccessToken:   "token-123",
				PhoneNumberID: "987654321",
			},
			http.DefaultClient,
		)

		err := sender.Send(context.Background(), channels.ChannelOutbox{
			Provider:    "whatsapp",
			RecipientID: "15550009999",
			Payload:     json.RawMessage(`{"content":`),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "decoding outbox payload")
	})

	t.Run("returns error for empty content", func(t *testing.T) {
		sender := newWhatsAppOutboxSender(
			config.ChannelProviderConfig{
				Enabled:       true,
				APIBaseURL:    "https://graph.example.com",
				APIVersion:    "v22.0",
				AccessToken:   "token-123",
				PhoneNumberID: "987654321",
			},
			http.DefaultClient,
		)

		err := sender.Send(context.Background(), channels.ChannelOutbox{
			Provider:    "whatsapp",
			RecipientID: "15550009999",
			Payload:     json.RawMessage(`{"content":"  ","correlation_id":"corr-123"}`),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "content is required")
	})

	t.Run("returns error for empty recipient id", func(t *testing.T) {
		sender := newWhatsAppOutboxSender(
			config.ChannelProviderConfig{
				Enabled:       true,
				APIBaseURL:    "https://graph.example.com",
				APIVersion:    "v22.0",
				AccessToken:   "token-123",
				PhoneNumberID: "987654321",
			},
			http.DefaultClient,
		)

		err := sender.Send(context.Background(), channels.ChannelOutbox{
			Provider:    "whatsapp",
			RecipientID: " ",
			Payload:     json.RawMessage(`{"content":"hello","correlation_id":"corr-123"}`),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "recipient id is required")
	})
}
