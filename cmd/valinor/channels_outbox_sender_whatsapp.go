package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/valinor-ai/valinor/internal/channels"
	"github.com/valinor-ai/valinor/internal/platform/config"
	"github.com/valinor-ai/valinor/internal/platform/database"
)

const (
	defaultWhatsAppAPIBaseURL = "https://graph.facebook.com"
	defaultWhatsAppAPIVersion = "v22.0"
	defaultOutboxHTTPTimeout  = 10 * time.Second
)

type routingOutboxSender struct {
	resolver   outboxProviderCredentialResolver
	byProvider map[string]func(config.ChannelProviderConfig) channels.OutboxSender
}

func (s routingOutboxSender) Send(ctx context.Context, job channels.ChannelOutbox) error {
	provider := strings.ToLower(strings.TrimSpace(job.Provider))
	buildSender, ok := s.byProvider[provider]
	if !ok {
		return fmt.Errorf("unsupported outbox provider: %s", provider)
	}

	tenantID := strings.TrimSpace(job.TenantID.String())
	credentialCfg, err := s.resolver.Resolve(ctx, tenantID, provider)
	if err != nil {
		if isOutboxCredentialResolutionPermanent(err) {
			return channels.NewOutboxPermanentError(fmt.Errorf("resolving provider credential: %w", err))
		}
		return fmt.Errorf("resolving provider credential: %w", err)
	}

	return buildSender(credentialCfg).Send(ctx, job)
}

type outboxProviderCredentialResolver interface {
	Resolve(ctx context.Context, tenantID, provider string) (config.ChannelProviderConfig, error)
}

func buildChannelOutboxSender(cfg config.ChannelsConfig, resolver outboxProviderCredentialResolver) (channels.OutboxSender, error) {
	if resolver == nil {
		return nil, fmt.Errorf("outbox provider credential resolver is required")
	}

	providers := make(map[string]func(config.ChannelProviderConfig) channels.OutboxSender)
	if cfg.Providers.Slack.Enabled {
		providers["slack"] = func(providerCfg config.ChannelProviderConfig) channels.OutboxSender {
			return newSlackOutboxSender(providerCfg, nil)
		}
	}
	if cfg.Providers.Telegram.Enabled {
		providers["telegram"] = func(providerCfg config.ChannelProviderConfig) channels.OutboxSender {
			return newTelegramOutboxSender(providerCfg, nil)
		}
	}
	if cfg.Providers.WhatsApp.Enabled {
		providers["whatsapp"] = func(providerCfg config.ChannelProviderConfig) channels.OutboxSender {
			return newWhatsAppOutboxSender(providerCfg, nil)
		}
	}

	return routingOutboxSender{
		resolver:   resolver,
		byProvider: providers,
	}, nil
}

type dbOutboxProviderCredentialResolver struct {
	pool      *database.Pool
	store     *channels.Store
	providers config.ChannelsProvidersConfig
}

func newDBOutboxProviderCredentialResolver(pool *database.Pool, store *channels.Store, providers config.ChannelsProvidersConfig) *dbOutboxProviderCredentialResolver {
	return &dbOutboxProviderCredentialResolver{
		pool:      pool,
		store:     store,
		providers: providers,
	}
}

func (r *dbOutboxProviderCredentialResolver) Resolve(ctx context.Context, tenantID, provider string) (config.ChannelProviderConfig, error) {
	if r == nil || r.pool == nil || r.store == nil {
		return config.ChannelProviderConfig{}, fmt.Errorf("provider credential resolver is not configured")
	}
	if strings.TrimSpace(tenantID) == "" {
		return config.ChannelProviderConfig{}, fmt.Errorf("outbox tenant id is required")
	}

	normalizedProvider := strings.ToLower(strings.TrimSpace(provider))
	baseCfg, err := r.baseProviderConfig(normalizedProvider)
	if err != nil {
		return config.ChannelProviderConfig{}, err
	}
	if !baseCfg.Enabled {
		return config.ChannelProviderConfig{}, channels.ErrProviderUnsupported
	}

	var credential *channels.ProviderCredential
	err = database.WithTenantConnection(ctx, r.pool, tenantID, func(ctx context.Context, q database.Querier) error {
		var lookupErr error
		credential, lookupErr = r.store.GetProviderCredential(ctx, q, normalizedProvider)
		return lookupErr
	})
	if err != nil {
		return config.ChannelProviderConfig{}, err
	}

	baseCfg.AccessToken = strings.TrimSpace(credential.AccessToken)
	if value := strings.TrimSpace(credential.APIBaseURL); value != "" {
		baseCfg.APIBaseURL = value
	}
	if value := strings.TrimSpace(credential.APIVersion); value != "" {
		baseCfg.APIVersion = value
	}
	if value := strings.TrimSpace(credential.PhoneNumberID); value != "" {
		baseCfg.PhoneNumberID = value
	}

	if strings.TrimSpace(baseCfg.AccessToken) == "" {
		return config.ChannelProviderConfig{}, channels.ErrProviderAccessTokenRequired
	}
	if normalizedProvider == "whatsapp" && strings.TrimSpace(baseCfg.PhoneNumberID) == "" {
		return config.ChannelProviderConfig{}, channels.ErrProviderPhoneNumberIDRequired
	}

	return baseCfg, nil
}

func (r *dbOutboxProviderCredentialResolver) baseProviderConfig(provider string) (config.ChannelProviderConfig, error) {
	switch provider {
	case "slack":
		return r.providers.Slack, nil
	case "telegram":
		return r.providers.Telegram, nil
	case "whatsapp":
		return r.providers.WhatsApp, nil
	default:
		return config.ChannelProviderConfig{}, channels.ErrProviderUnsupported
	}
}

func isOutboxCredentialResolutionPermanent(err error) bool {
	switch {
	case errors.Is(err, channels.ErrProviderCredentialNotFound):
		return true
	case errors.Is(err, channels.ErrProviderUnsupported):
		return true
	case errors.Is(err, channels.ErrProviderAccessTokenRequired):
		return true
	case errors.Is(err, channels.ErrProviderPhoneNumberIDRequired):
		return true
	case errors.Is(err, channels.ErrProviderCredentialCipherRequired):
		return true
	case errors.Is(err, channels.ErrProviderCredentialDecryptFailed):
		return true
	case errors.Is(err, channels.ErrPlatformEmpty):
		return true
	default:
		return false
	}
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
