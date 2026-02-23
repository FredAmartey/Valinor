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
	Content           string
	Control           *ingressControl
}

type ingressControl struct {
	AcknowledgeOnly bool
	SlackChallenge  string
}

func extractIngressMetadata(provider string, headers http.Header, body []byte, now time.Time) ([]ingressMetadata, error) {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "slack":
		return extractSlackIngressMetadata(headers, body, now)
	case "whatsapp":
		return extractWhatsAppIngressMetadata(body, now)
	case "telegram":
		return extractTelegramIngressMetadata(body, now)
	default:
		return nil, fmt.Errorf("unsupported provider: %s", provider)
	}
}

func extractSlackIngressMetadata(headers http.Header, body []byte, now time.Time) ([]ingressMetadata, error) {
	var payload struct {
		Type      string `json:"type"`
		Challenge string `json:"challenge"`
		EventID   string `json:"event_id"`
		Event     struct {
			Type  string `json:"type"`
			User  string `json:"user"`
			BotID string `json:"bot_id"`
			Text  string `json:"text"`
		} `json:"event"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("parsing slack payload: %w", err)
	}
	occurredAt := now
	if ts := strings.TrimSpace(headers.Get(slackTimestampHeader)); ts != "" {
		unixTs, err := strconv.ParseInt(ts, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("parsing slack timestamp: %w", err)
		}
		occurredAt = time.Unix(unixTs, 0)
	}
	if payload.Type != "" && payload.Type != "event_callback" {
		return []ingressMetadata{{
			OccurredAt: occurredAt,
			Control: &ingressControl{
				AcknowledgeOnly: true,
				SlackChallenge:  strings.TrimSpace(payload.Challenge),
			},
		}}, nil
	}

	platformIdentity := strings.TrimSpace(payload.Event.User)
	if platformIdentity == "" {
		platformIdentity = strings.TrimSpace(payload.Event.BotID)
	}
	if platformIdentity == "" {
		return []ingressMetadata{{
			OccurredAt: occurredAt,
			Control: &ingressControl{
				AcknowledgeOnly: true,
			},
		}}, nil
	}

	return []ingressMetadata{{
		PlatformUserID:    platformIdentity,
		PlatformMessageID: strings.TrimSpace(payload.EventID),
		OccurredAt:        occurredAt,
		Content:           strings.TrimSpace(payload.Event.Text),
	}}, nil
}

func extractWhatsAppIngressMetadata(body []byte, now time.Time) ([]ingressMetadata, error) {
	var payload struct {
		Entry []struct {
			Changes []struct {
				Value struct {
					Messages []struct {
						From      string `json:"from"`
						ID        string `json:"id"`
						Timestamp string `json:"timestamp"`
						Text      struct {
							Body string `json:"body"`
						} `json:"text"`
					} `json:"messages"`
					Statuses []struct {
						Timestamp string `json:"timestamp"`
					} `json:"statuses"`
				} `json:"value"`
			} `json:"changes"`
		} `json:"entry"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("parsing whatsapp payload: %w", err)
	}
	if len(payload.Entry) == 0 {
		return []ingressMetadata{{
			OccurredAt: now,
			Control: &ingressControl{
				AcknowledgeOnly: true,
			},
		}}, nil
	}

	metas := make([]ingressMetadata, 0)
	for _, entry := range payload.Entry {
		if len(entry.Changes) == 0 {
			continue
		}
		for _, change := range entry.Changes {
			value := change.Value
			if len(value.Messages) == 0 {
				continue
			}
			for _, message := range value.Messages {
				if strings.TrimSpace(message.From) == "" {
					return nil, fmt.Errorf("parsing whatsapp payload: %w", ErrIdentityEmpty)
				}

				occurredAt := now
				if ts := strings.TrimSpace(message.Timestamp); ts != "" {
					unixTs, err := strconv.ParseInt(ts, 10, 64)
					if err != nil {
						return nil, fmt.Errorf("parsing whatsapp timestamp: %w", err)
					}
					occurredAt = time.Unix(unixTs, 0)
				}

				metas = append(metas, ingressMetadata{
					PlatformUserID:    strings.TrimSpace(message.From),
					PlatformMessageID: strings.TrimSpace(message.ID),
					OccurredAt:        occurredAt,
					Content:           strings.TrimSpace(message.Text.Body),
				})
			}
		}
	}
	if len(metas) > 0 {
		return metas, nil
	}

	occurredAt := now
	for _, entry := range payload.Entry {
		for _, change := range entry.Changes {
			value := change.Value
			if len(value.Statuses) == 0 {
				continue
			}
			if ts := strings.TrimSpace(value.Statuses[0].Timestamp); ts != "" {
				unixTs, err := strconv.ParseInt(ts, 10, 64)
				if err != nil {
					return nil, fmt.Errorf("parsing whatsapp status timestamp: %w", err)
				}
				occurredAt = time.Unix(unixTs, 0)
			}
			break
		}
	}
	return []ingressMetadata{{
		OccurredAt: occurredAt,
		Control: &ingressControl{
			AcknowledgeOnly: true,
		},
	}}, nil
}

func extractTelegramIngressMetadata(body []byte, now time.Time) ([]ingressMetadata, error) {
	var payload struct {
		Message struct {
			MessageID int64  `json:"message_id"`
			Date      int64  `json:"date"`
			Text      string `json:"text"`
			From      struct {
				ID int64 `json:"id"`
			} `json:"from"`
		} `json:"message"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("parsing telegram payload: %w", err)
	}
	if payload.Message.From.ID == 0 {
		return nil, fmt.Errorf("parsing telegram payload: %w", ErrIdentityEmpty)
	}

	occurredAt := now
	if payload.Message.Date > 0 {
		occurredAt = time.Unix(payload.Message.Date, 0)
	}

	platformMessageID := ""
	if payload.Message.MessageID > 0 {
		platformMessageID = strconv.FormatInt(payload.Message.MessageID, 10)
	}

	return []ingressMetadata{{
		PlatformUserID:    strconv.FormatInt(payload.Message.From.ID, 10),
		PlatformMessageID: platformMessageID,
		OccurredAt:        occurredAt,
		Content:           strings.TrimSpace(payload.Message.Text),
	}}, nil
}
