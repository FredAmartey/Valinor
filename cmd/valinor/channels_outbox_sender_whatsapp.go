package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
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

	if len(providers) == 0 {
		return noopOutboxSender{}, nil
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

	body, err := json.Marshal(map[string]any{
		"messaging_product": "whatsapp",
		"to":                recipientID,
		"type":              "text",
		"text": map[string]any{
			"body":        content,
			"preview_url": false,
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
		return fmt.Errorf("whatsapp send failed: status %d: %s", resp.StatusCode, msg)
	}

	return nil
}
