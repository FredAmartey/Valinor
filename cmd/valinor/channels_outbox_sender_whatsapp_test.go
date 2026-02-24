package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valinor-ai/valinor/internal/channels"
	"github.com/valinor-ai/valinor/internal/platform/config"
)

func TestBuildChannelOutboxSender(t *testing.T) {
	t.Run("slack enabled missing access token fails", func(t *testing.T) {
		_, err := buildChannelOutboxSender(config.ChannelsConfig{
			Providers: config.ChannelsProvidersConfig{
				Slack: config.ChannelProviderConfig{
					Enabled: true,
				},
			},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "slack access token")
	})

	t.Run("slack enabled with access token returns sender", func(t *testing.T) {
		sender, err := buildChannelOutboxSender(config.ChannelsConfig{
			Providers: config.ChannelsProvidersConfig{
				Slack: config.ChannelProviderConfig{
					Enabled:     true,
					AccessToken: "xoxb-test-token",
					APIBaseURL:  "https://slack.example.com",
				},
			},
		})
		require.NoError(t, err)
		require.NotNil(t, sender)
	})

	t.Run("telegram enabled missing access token fails", func(t *testing.T) {
		_, err := buildChannelOutboxSender(config.ChannelsConfig{
			Providers: config.ChannelsProvidersConfig{
				Telegram: config.ChannelProviderConfig{
					Enabled: true,
				},
			},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "telegram access token")
	})

	t.Run("telegram enabled with access token returns sender", func(t *testing.T) {
		sender, err := buildChannelOutboxSender(config.ChannelsConfig{
			Providers: config.ChannelsProvidersConfig{
				Telegram: config.ChannelProviderConfig{
					Enabled:     true,
					AccessToken: "123456:ABCDEF",
					APIBaseURL:  "https://telegram.example.com",
				},
			},
		})
		require.NoError(t, err)
		require.NotNil(t, sender)
	})

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

func TestIsPermanentOutboxHTTPStatus(t *testing.T) {
	assert.False(t, isPermanentOutboxHTTPStatus(http.StatusRequestTimeout))
	assert.False(t, isPermanentOutboxHTTPStatus(http.StatusTooManyRequests))
	assert.False(t, isPermanentOutboxHTTPStatus(http.StatusBadGateway))

	assert.True(t, isPermanentOutboxHTTPStatus(http.StatusBadRequest))
	assert.True(t, isPermanentOutboxHTTPStatus(http.StatusUnauthorized))
	assert.True(t, isPermanentOutboxHTTPStatus(http.StatusNotFound))
}

func TestSlackOutboxSender_Send(t *testing.T) {
	t.Run("sends slack chat.postMessage payload", func(t *testing.T) {
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
			_, _ = w.Write([]byte(`{"ok":true}`))
		}))
		defer srv.Close()

		sender := newSlackOutboxSender(
			config.ChannelProviderConfig{
				Enabled:     true,
				APIBaseURL:  srv.URL,
				AccessToken: "xoxb-test-token",
			},
			srv.Client(),
		)

		err := sender.Send(context.Background(), channels.ChannelOutbox{
			Provider:    "slack",
			RecipientID: "C12345678",
			Payload:     json.RawMessage(`{"content":"hello from outbox","correlation_id":"corr-123","thread_ts":"1730000010.000100"}`),
		})
		require.NoError(t, err)
		assert.Equal(t, "Bearer xoxb-test-token", seenAuth)
		assert.Equal(t, "/api/chat.postMessage", seenPath)
		assert.Equal(t, "C12345678", seenBody["channel"])
		assert.Equal(t, "hello from outbox", seenBody["text"])
		assert.Equal(t, false, seenBody["unfurl_links"])
		assert.Equal(t, "1730000010.000100", seenBody["thread_ts"])
	})

	t.Run("returns error when slack API returns non-2xx status", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"ok":false,"error":"invalid_auth"}`))
		}))
		defer srv.Close()

		sender := newSlackOutboxSender(
			config.ChannelProviderConfig{
				Enabled:     true,
				APIBaseURL:  srv.URL,
				AccessToken: "xoxb-test-token",
			},
			srv.Client(),
		)

		err := sender.Send(context.Background(), channels.ChannelOutbox{
			Provider:    "slack",
			RecipientID: "C12345678",
			Payload:     json.RawMessage(`{"content":"hello from outbox","correlation_id":"corr-123"}`),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "status 401")
		assert.True(t, channels.IsOutboxPermanentError(err))
	})

	t.Run("returns transient error when slack API returns 5xx status", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte(`{"ok":false,"error":"gateway_error"}`))
		}))
		defer srv.Close()

		sender := newSlackOutboxSender(
			config.ChannelProviderConfig{
				Enabled:     true,
				APIBaseURL:  srv.URL,
				AccessToken: "xoxb-test-token",
			},
			srv.Client(),
		)

		err := sender.Send(context.Background(), channels.ChannelOutbox{
			Provider:    "slack",
			RecipientID: "C12345678",
			Payload:     json.RawMessage(`{"content":"hello from outbox","correlation_id":"corr-123"}`),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "status 502")
		assert.False(t, channels.IsOutboxPermanentError(err))
	})

	t.Run("returns transient retry-after error on 429 with retry-after header", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Retry-After", "37")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"ok":false,"error":"rate_limited"}`))
		}))
		defer srv.Close()

		sender := newSlackOutboxSender(
			config.ChannelProviderConfig{
				Enabled:     true,
				APIBaseURL:  srv.URL,
				AccessToken: "xoxb-test-token",
			},
			srv.Client(),
		)

		err := sender.Send(context.Background(), channels.ChannelOutbox{
			Provider:    "slack",
			RecipientID: "C12345678",
			Payload:     json.RawMessage(`{"content":"hello from outbox","correlation_id":"corr-123"}`),
		})
		require.Error(t, err)
		assert.False(t, channels.IsOutboxPermanentError(err))
		retryAfter, ok := channels.OutboxRetryAfter(err)
		assert.True(t, ok)
		assert.Equal(t, 37*time.Second, retryAfter)
	})

	t.Run("returns error when slack API rejects request", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"ok":false,"error":"channel_not_found"}`))
		}))
		defer srv.Close()

		sender := newSlackOutboxSender(
			config.ChannelProviderConfig{
				Enabled:     true,
				APIBaseURL:  srv.URL,
				AccessToken: "xoxb-test-token",
			},
			srv.Client(),
		)

		err := sender.Send(context.Background(), channels.ChannelOutbox{
			Provider:    "slack",
			RecipientID: "C12345678",
			Payload:     json.RawMessage(`{"content":"hello from outbox","correlation_id":"corr-123"}`),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "channel_not_found")
		assert.True(t, channels.IsOutboxPermanentError(err))
	})

	t.Run("returns error for malformed outbox payload", func(t *testing.T) {
		sender := newSlackOutboxSender(
			config.ChannelProviderConfig{
				Enabled:     true,
				APIBaseURL:  "https://slack.example.com",
				AccessToken: "xoxb-test-token",
			},
			http.DefaultClient,
		)

		err := sender.Send(context.Background(), channels.ChannelOutbox{
			Provider:    "slack",
			RecipientID: "C12345678",
			Payload:     json.RawMessage(`{"content":`),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "decoding outbox payload")
	})

	t.Run("returns error for empty content", func(t *testing.T) {
		sender := newSlackOutboxSender(
			config.ChannelProviderConfig{
				Enabled:     true,
				APIBaseURL:  "https://slack.example.com",
				AccessToken: "xoxb-test-token",
			},
			http.DefaultClient,
		)

		err := sender.Send(context.Background(), channels.ChannelOutbox{
			Provider:    "slack",
			RecipientID: "C12345678",
			Payload:     json.RawMessage(`{"content":"  ","correlation_id":"corr-123"}`),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "content is required")
	})

	t.Run("returns error for empty recipient id", func(t *testing.T) {
		sender := newSlackOutboxSender(
			config.ChannelProviderConfig{
				Enabled:     true,
				APIBaseURL:  "https://slack.example.com",
				AccessToken: "xoxb-test-token",
			},
			http.DefaultClient,
		)

		err := sender.Send(context.Background(), channels.ChannelOutbox{
			Provider:    "slack",
			RecipientID: " ",
			Payload:     json.RawMessage(`{"content":"hello from outbox","correlation_id":"corr-123"}`),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "recipient id is required")
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
		assert.True(t, channels.IsOutboxPermanentError(err))
	})

	t.Run("returns transient error when whatsapp API returns 5xx status", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"error":{"message":"upstream unavailable"}}`))
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
		assert.Contains(t, err.Error(), "status 503")
		assert.False(t, channels.IsOutboxPermanentError(err))
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

func TestTelegramOutboxSender_Send(t *testing.T) {
	t.Run("sends telegram sendMessage payload", func(t *testing.T) {
		var seenPath string
		var seenBody map[string]any

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			seenPath = r.URL.Path
			defer r.Body.Close()

			decoder := json.NewDecoder(r.Body)
			require.NoError(t, decoder.Decode(&seenBody))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"ok":true,"result":{"message_id":42}}`))
		}))
		defer srv.Close()

		sender := newTelegramOutboxSender(
			config.ChannelProviderConfig{
				Enabled:     true,
				APIBaseURL:  srv.URL,
				AccessToken: "123456:ABCDEF",
			},
			srv.Client(),
		)

		err := sender.Send(context.Background(), channels.ChannelOutbox{
			Provider:    "telegram",
			RecipientID: "987654321",
			Payload:     json.RawMessage(`{"content":"hello from outbox","correlation_id":"corr-123"}`),
		})
		require.NoError(t, err)
		assert.Equal(t, "/bot123456:ABCDEF/sendMessage", seenPath)
		assert.Equal(t, "987654321", seenBody["chat_id"])
		assert.Equal(t, "hello from outbox", seenBody["text"])
		assert.Equal(t, true, seenBody["disable_web_page_preview"])
	})

	t.Run("returns error when telegram API returns non-2xx status", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"ok":false,"description":"Unauthorized"}`))
		}))
		defer srv.Close()

		sender := newTelegramOutboxSender(
			config.ChannelProviderConfig{
				Enabled:     true,
				APIBaseURL:  srv.URL,
				AccessToken: "123456:ABCDEF",
			},
			srv.Client(),
		)

		err := sender.Send(context.Background(), channels.ChannelOutbox{
			Provider:    "telegram",
			RecipientID: "987654321",
			Payload:     json.RawMessage(`{"content":"hello from outbox","correlation_id":"corr-123"}`),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "status 401")
		assert.True(t, channels.IsOutboxPermanentError(err))
	})

	t.Run("returns transient error when telegram API returns 5xx status", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte(`{"ok":false,"description":"gateway error"}`))
		}))
		defer srv.Close()

		sender := newTelegramOutboxSender(
			config.ChannelProviderConfig{
				Enabled:     true,
				APIBaseURL:  srv.URL,
				AccessToken: "123456:ABCDEF",
			},
			srv.Client(),
		)

		err := sender.Send(context.Background(), channels.ChannelOutbox{
			Provider:    "telegram",
			RecipientID: "987654321",
			Payload:     json.RawMessage(`{"content":"hello from outbox","correlation_id":"corr-123"}`),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "status 502")
		assert.False(t, channels.IsOutboxPermanentError(err))
	})

	t.Run("returns error when telegram API rejects request", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"ok":false,"description":"Bad Request: chat not found"}`))
		}))
		defer srv.Close()

		sender := newTelegramOutboxSender(
			config.ChannelProviderConfig{
				Enabled:     true,
				APIBaseURL:  srv.URL,
				AccessToken: "123456:ABCDEF",
			},
			srv.Client(),
		)

		err := sender.Send(context.Background(), channels.ChannelOutbox{
			Provider:    "telegram",
			RecipientID: "987654321",
			Payload:     json.RawMessage(`{"content":"hello from outbox","correlation_id":"corr-123"}`),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "chat not found")
		assert.True(t, channels.IsOutboxPermanentError(err))
	})

	t.Run("returns error for malformed outbox payload", func(t *testing.T) {
		sender := newTelegramOutboxSender(
			config.ChannelProviderConfig{
				Enabled:     true,
				APIBaseURL:  "https://telegram.example.com",
				AccessToken: "123456:ABCDEF",
			},
			http.DefaultClient,
		)

		err := sender.Send(context.Background(), channels.ChannelOutbox{
			Provider:    "telegram",
			RecipientID: "987654321",
			Payload:     json.RawMessage(`{"content":`),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "decoding outbox payload")
	})

	t.Run("returns error for empty content", func(t *testing.T) {
		sender := newTelegramOutboxSender(
			config.ChannelProviderConfig{
				Enabled:     true,
				APIBaseURL:  "https://telegram.example.com",
				AccessToken: "123456:ABCDEF",
			},
			http.DefaultClient,
		)

		err := sender.Send(context.Background(), channels.ChannelOutbox{
			Provider:    "telegram",
			RecipientID: "987654321",
			Payload:     json.RawMessage(`{"content":"  ","correlation_id":"corr-123"}`),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "content is required")
	})

	t.Run("returns error for empty recipient id", func(t *testing.T) {
		sender := newTelegramOutboxSender(
			config.ChannelProviderConfig{
				Enabled:     true,
				APIBaseURL:  "https://telegram.example.com",
				AccessToken: "123456:ABCDEF",
			},
			http.DefaultClient,
		)

		err := sender.Send(context.Background(), channels.ChannelOutbox{
			Provider:    "telegram",
			RecipientID: " ",
			Payload:     json.RawMessage(`{"content":"hello from outbox","correlation_id":"corr-123"}`),
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "recipient id is required")
	})
}
