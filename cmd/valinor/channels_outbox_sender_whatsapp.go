package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/valinor-ai/valinor/internal/channels"
	"github.com/valinor-ai/valinor/internal/platform/config"
)

const (
	defaultWhatsAppAPIBaseURL = "https://graph.facebook.com"
	defaultWhatsAppAPIVersion = "v22.0"
	defaultOutboxHTTPTimeout  = 10 * time.Second
)

type routingOutboxSender struct {
	byProvider map[string]channels.OutboxSender
}

func (s routingOutboxSender) Send(ctx context.Context, job channels.ChannelOutbox) error {
	provider := strings.ToLower(strings.TrimSpace(job.Provider))
	if sender, ok := s.byProvider[provider]; ok {
		return sender.Send(ctx, job)
	}
	return fmt.Errorf("unsupported outbox provider: %s", provider)
}

func buildChannelOutboxSender(cfg config.ChannelsConfig) (channels.OutboxSender, error) {
	providers := make(map[string]channels.OutboxSender)
	if cfg.Providers.Slack.Enabled {
		slackCfg := cfg.Providers.Slack
		if strings.TrimSpace(slackCfg.AccessToken) == "" {
			return nil, fmt.Errorf("slack access token is required for outbox sender")
		}
		providers["slack"] = newSlackOutboxSender(slackCfg, nil)
	}
	if cfg.Providers.Telegram.Enabled {
		telegramCfg := cfg.Providers.Telegram
		if strings.TrimSpace(telegramCfg.AccessToken) == "" {
			return nil, fmt.Errorf("telegram access token is required for outbox sender")
		}
		providers["telegram"] = newTelegramOutboxSender(telegramCfg, nil)
	}
	if cfg.Providers.WhatsApp.Enabled {
		waCfg := cfg.Providers.WhatsApp
		if strings.TrimSpace(waCfg.AccessToken) == "" {
			return nil, fmt.Errorf("whatsapp access token is required for outbox sender")
		}
		if strings.TrimSpace(waCfg.PhoneNumberID) == "" {
			return nil, fmt.Errorf("whatsapp phone number id is required for outbox sender")
		}
		providers["whatsapp"] = newWhatsAppOutboxSender(waCfg, nil)
	}

	return routingOutboxSender{
		byProvider: providers,
	}, nil
}

type whatsAppOutboxSender struct {
	client        *http.Client
	apiBaseURL    string
	apiVersion    string
	accessToken   string
	phoneNumberID string
}

func newWhatsAppOutboxSender(cfg config.ChannelProviderConfig, client *http.Client) *whatsAppOutboxSender {
	httpClient := client
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout: defaultOutboxHTTPTimeout,
		}
	}

	apiBaseURL := strings.TrimSpace(cfg.APIBaseURL)
	if apiBaseURL == "" {
		apiBaseURL = defaultWhatsAppAPIBaseURL
	}

	// Normalize values like "/v22.0/" and "v22.0/" to "v22.0".
	apiVersion := strings.Trim(strings.TrimSpace(cfg.APIVersion), "/")
	if apiVersion == "" {
		apiVersion = defaultWhatsAppAPIVersion
	}

	return &whatsAppOutboxSender{
		client:        httpClient,
		apiBaseURL:    strings.TrimRight(apiBaseURL, "/"),
		apiVersion:    apiVersion,
		accessToken:   strings.TrimSpace(cfg.AccessToken),
		phoneNumberID: strings.TrimSpace(cfg.PhoneNumberID),
	}
}

func (s *whatsAppOutboxSender) Send(ctx context.Context, job channels.ChannelOutbox) error {
	var payload struct {
		Content       string `json:"content"`
		CorrelationID string `json:"correlation_id"`
	}
	if err := json.Unmarshal(job.Payload, &payload); err != nil {
		return fmt.Errorf("decoding outbox payload: %w", err)
	}

	content := strings.TrimSpace(payload.Content)
	if content == "" {
		return fmt.Errorf("outbox payload content is required")
	}

	recipientID := strings.TrimSpace(job.RecipientID)
	if recipientID == "" {
		return fmt.Errorf("outbox recipient id is required")
	}

	type whatsAppTextPayload struct {
		Body       string `json:"body"`
		PreviewURL bool   `json:"preview_url"`
	}
	type whatsAppSendRequest struct {
		MessagingProduct string              `json:"messaging_product"`
		To               string              `json:"to"`
		Type             string              `json:"type"`
		Text             whatsAppTextPayload `json:"text"`
	}

	body, err := json.Marshal(whatsAppSendRequest{
		MessagingProduct: "whatsapp",
		To:               recipientID,
		Type:             "text",
		Text: whatsAppTextPayload{
			Body:       content,
			PreviewURL: false,
		},
	})
	if err != nil {
		return fmt.Errorf("marshaling whatsapp message body: %w", err)
	}

	endpoint := fmt.Sprintf("%s/%s/%s/messages", s.apiBaseURL, s.apiVersion, url.PathEscape(s.phoneNumberID))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("building whatsapp request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+s.accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("sending whatsapp request: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		msg := strings.TrimSpace(string(respBody))
		if msg == "" {
			msg = http.StatusText(resp.StatusCode)
		}
		return classifyOutboxHTTPStatus("whatsapp", resp.StatusCode, msg, resp.Header.Get("Retry-After"), time.Now().UTC())
	}

	// WhatsApp Graph API communicates delivery failures through HTTP status codes,
	// so there is no additional semantic ok:false body check on successful 2xx responses.
	return nil
}

func classifyOutboxHTTPStatus(provider string, status int, message, retryAfterHeader string, now time.Time) error {
	msg := strings.TrimSpace(message)
	if msg == "" {
		msg = http.StatusText(status)
	}

	err := fmt.Errorf("%s send failed: status %d: %s", provider, status, msg)
	if isPermanentOutboxHTTPStatus(status) {
		return channels.NewOutboxPermanentError(err)
	}
	if retryAfter, ok := parseRetryAfterDuration(retryAfterHeader, now); ok {
		return channels.NewOutboxTransientErrorWithRetryAfter(err, retryAfter)
	}
	return err
}

func isPermanentOutboxHTTPStatus(status int) bool {
	if status == http.StatusRequestTimeout || status == http.StatusTooManyRequests {
		return false
	}
	return status >= http.StatusBadRequest && status < http.StatusInternalServerError
}

func parseRetryAfterDuration(headerValue string, now time.Time) (time.Duration, bool) {
	value := strings.TrimSpace(headerValue)
	if value == "" {
		return 0, false
	}

	seconds, err := strconv.Atoi(value)
	if err == nil {
		if seconds > 0 {
			return time.Duration(seconds) * time.Second, true
		}
		return 0, false
	}

	retryAt, err := http.ParseTime(value)
	if err != nil {
		return 0, false
	}
	delay := retryAt.Sub(now)
	if delay <= 0 {
		return 0, false
	}
	return delay, true
}
