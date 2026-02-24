package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/valinor-ai/valinor/internal/channels"
	"github.com/valinor-ai/valinor/internal/platform/config"
)

const defaultTelegramAPIBaseURL = "https://api.telegram.org"

type telegramOutboxSender struct {
	client      *http.Client
	apiBaseURL  string
	accessToken string
}

func newTelegramOutboxSender(cfg config.ChannelProviderConfig, client *http.Client) *telegramOutboxSender {
	httpClient := client
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout: defaultOutboxHTTPTimeout,
		}
	}

	apiBaseURL := strings.TrimSpace(cfg.APIBaseURL)
	if apiBaseURL == "" {
		apiBaseURL = defaultTelegramAPIBaseURL
	}

	return &telegramOutboxSender{
		client:      httpClient,
		apiBaseURL:  strings.TrimRight(apiBaseURL, "/"),
		accessToken: strings.TrimSpace(cfg.AccessToken),
	}
}

func (s *telegramOutboxSender) Send(ctx context.Context, job channels.ChannelOutbox) error {
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

	type telegramSendRequest struct {
		ChatID                string `json:"chat_id"`
		Text                  string `json:"text"`
		DisableWebPagePreview bool   `json:"disable_web_page_preview"`
	}

	body, err := json.Marshal(telegramSendRequest{
		ChatID:                recipientID,
		Text:                  content,
		DisableWebPagePreview: true,
	})
	if err != nil {
		return fmt.Errorf("marshaling telegram message body: %w", err)
	}

	endpoint := fmt.Sprintf("%s/bot%s/sendMessage", s.apiBaseURL, s.accessToken)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("building telegram request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("sending telegram request: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		msg := strings.TrimSpace(string(respBody))
		if msg == "" {
			msg = http.StatusText(resp.StatusCode)
		}
		return classifyOutboxHTTPStatus("telegram", resp.StatusCode, msg, resp.Header.Get("Retry-After"), time.Now().UTC())
	}

	var response struct {
		OK          bool   `json:"ok"`
		Description string `json:"description"`
	}
	if err := json.Unmarshal(respBody, &response); err != nil {
		return fmt.Errorf("decoding telegram response: %w", err)
	}
	if !response.OK {
		errMsg := strings.TrimSpace(response.Description)
		if errMsg == "" {
			errMsg = "unknown error"
		}
		// Telegram semantic rejections (ok=false) are treated as non-retryable.
		// Transient throttling is expected via HTTP 429 and is handled above.
		return channels.NewOutboxPermanentError(fmt.Errorf("telegram send failed: %s", errMsg))
	}

	return nil
}
