package channels

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type ingressMetadata struct {
	PlatformUserID    string
	PlatformMessageID string
	OccurredAt        time.Time
	Control           *ingressControl
}

type ingressControl struct {
	AcknowledgeOnly bool
	SlackChallenge  string
}

func extractIngressMetadata(provider string, headers http.Header, body []byte, now time.Time) (ingressMetadata, error) {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "slack":
		return extractSlackIngressMetadata(headers, body, now)
	case "whatsapp":
		return extractWhatsAppIngressMetadata(body, now)
	case "telegram":
		return extractTelegramIngressMetadata(body, now)
	default:
		return ingressMetadata{}, fmt.Errorf("unsupported provider: %s", provider)
	}
}

func extractSlackIngressMetadata(headers http.Header, body []byte, now time.Time) (ingressMetadata, error) {
	var payload struct {
		Type      string `json:"type"`
		Challenge string `json:"challenge"`
		EventID   string `json:"event_id"`
		Event     struct {
			User string `json:"user"`
		} `json:"event"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return ingressMetadata{}, fmt.Errorf("parsing slack payload: %w", err)
	}
	occurredAt := now
	if ts := strings.TrimSpace(headers.Get(slackTimestampHeader)); ts != "" {
		unixTs, err := strconv.ParseInt(ts, 10, 64)
		if err != nil {
			return ingressMetadata{}, fmt.Errorf("parsing slack timestamp: %w", err)
		}
		occurredAt = time.Unix(unixTs, 0)
	}
	if payload.Type != "" && payload.Type != "event_callback" {
		return ingressMetadata{
			OccurredAt: occurredAt,
			Control: &ingressControl{
				AcknowledgeOnly: true,
				SlackChallenge:  strings.TrimSpace(payload.Challenge),
			},
		}, nil
	}
	if strings.TrimSpace(payload.Event.User) == "" {
		return ingressMetadata{
			OccurredAt: occurredAt,
			Control: &ingressControl{
				AcknowledgeOnly: true,
			},
		}, nil
	}

	return ingressMetadata{
		PlatformUserID:    payload.Event.User,
		PlatformMessageID: strings.TrimSpace(payload.EventID),
		OccurredAt:        occurredAt,
	}, nil
}

func extractWhatsAppIngressMetadata(body []byte, now time.Time) (ingressMetadata, error) {
	var payload struct {
		Entry []struct {
			Changes []struct {
				Value struct {
					Messages []struct {
						From      string `json:"from"`
						ID        string `json:"id"`
						Timestamp string `json:"timestamp"`
					} `json:"messages"`
					Statuses []struct {
						Timestamp string `json:"timestamp"`
					} `json:"statuses"`
				} `json:"value"`
			} `json:"changes"`
		} `json:"entry"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return ingressMetadata{}, fmt.Errorf("parsing whatsapp payload: %w", err)
	}
	if len(payload.Entry) == 0 || len(payload.Entry[0].Changes) == 0 {
		return ingressMetadata{}, fmt.Errorf("parsing whatsapp payload: missing messages")
	}

	value := payload.Entry[0].Changes[0].Value
	if len(value.Messages) == 0 {
		occurredAt := now
		if len(value.Statuses) > 0 {
			if ts := strings.TrimSpace(value.Statuses[0].Timestamp); ts != "" {
				unixTs, err := strconv.ParseInt(ts, 10, 64)
				if err != nil {
					return ingressMetadata{}, fmt.Errorf("parsing whatsapp status timestamp: %w", err)
				}
				occurredAt = time.Unix(unixTs, 0)
			}
		}
		return ingressMetadata{
			OccurredAt: occurredAt,
			Control: &ingressControl{
				AcknowledgeOnly: true,
			},
		}, nil
	}

	message := value.Messages[0]
	if strings.TrimSpace(message.From) == "" {
		return ingressMetadata{}, fmt.Errorf("parsing whatsapp payload: %w", ErrIdentityEmpty)
	}

	occurredAt := now
	if ts := strings.TrimSpace(message.Timestamp); ts != "" {
		unixTs, err := strconv.ParseInt(ts, 10, 64)
		if err != nil {
			return ingressMetadata{}, fmt.Errorf("parsing whatsapp timestamp: %w", err)
		}
		occurredAt = time.Unix(unixTs, 0)
	}

	return ingressMetadata{
		PlatformUserID:    message.From,
		PlatformMessageID: strings.TrimSpace(message.ID),
		OccurredAt:        occurredAt,
	}, nil
}

func extractTelegramIngressMetadata(body []byte, now time.Time) (ingressMetadata, error) {
	var payload struct {
		Message struct {
			MessageID int64 `json:"message_id"`
			Date      int64 `json:"date"`
			From      struct {
				ID int64 `json:"id"`
			} `json:"from"`
		} `json:"message"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return ingressMetadata{}, fmt.Errorf("parsing telegram payload: %w", err)
	}
	if payload.Message.From.ID == 0 {
		return ingressMetadata{}, fmt.Errorf("parsing telegram payload: %w", ErrIdentityEmpty)
	}

	occurredAt := now
	if payload.Message.Date > 0 {
		occurredAt = time.Unix(payload.Message.Date, 0)
	}

	platformMessageID := ""
	if payload.Message.MessageID > 0 {
		platformMessageID = strconv.FormatInt(payload.Message.MessageID, 10)
	}

	return ingressMetadata{
		PlatformUserID:    strconv.FormatInt(payload.Message.From.ID, 10),
		PlatformMessageID: platformMessageID,
		OccurredAt:        occurredAt,
	}, nil
}
