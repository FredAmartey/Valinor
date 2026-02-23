package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/valinor-ai/valinor/internal/channels"
	"github.com/valinor-ai/valinor/internal/platform/config"
)

const defaultSlackAPIBaseURL = "https://slack.com"

type slackOutboxSender struct {
	client      *http.Client
	apiBaseURL  string
	accessToken string
}

func newSlackOutboxSender(cfg config.ChannelProviderConfig, client *http.Client) *slackOutboxSender {
	httpClient := client
	if httpClient == nil {
		httpClient = &http.Client{
			Timeout: defaultOutboxHTTPTimeout,
		}
	}

	apiBaseURL := strings.TrimSpace(cfg.APIBaseURL)
	if apiBaseURL == "" {
		apiBaseURL = defaultSlackAPIBaseURL
	}

	return &slackOutboxSender{
		client:      httpClient,
		apiBaseURL:  strings.TrimRight(apiBaseURL, "/"),
		accessToken: strings.TrimSpace(cfg.AccessToken),
	}
}

func (s *slackOutboxSender) Send(ctx context.Context, job channels.ChannelOutbox) error {
	var payload struct {
		Content       string `json:"content"`
		CorrelationID string `json:"correlation_id"`
		ThreadTS      string `json:"thread_ts"`
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

	type slackSendRequest struct {
		Channel     string `json:"channel"`
		Text        string `json:"text"`
		UnfurlLinks bool   `json:"unfurl_links"`
		ThreadTS    string `json:"thread_ts,omitempty"`
	}

	threadTS := strings.TrimSpace(payload.ThreadTS)
	body, err := json.Marshal(slackSendRequest{
		Channel:     recipientID,
		Text:        content,
		UnfurlLinks: false,
		ThreadTS:    threadTS,
	})
	if err != nil {
		return fmt.Errorf("marshaling slack message body: %w", err)
	}

	endpoint := fmt.Sprintf("%s/api/chat.postMessage", s.apiBaseURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("building slack request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+s.accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("sending slack request: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		msg := strings.TrimSpace(string(respBody))
		if msg == "" {
			msg = http.StatusText(resp.StatusCode)
		}
		return classifyOutboxHTTPStatus("slack", resp.StatusCode, msg)
	}

	var response struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(respBody, &response); err != nil {
		return fmt.Errorf("decoding slack response: %w", err)
	}
	if !response.OK {
		errMsg := strings.TrimSpace(response.Error)
		if errMsg == "" {
			errMsg = "unknown error"
		}
		return channels.NewOutboxPermanentError(fmt.Errorf("slack send failed: %s", errMsg))
	}

	return nil
}
