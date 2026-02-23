package channels

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractIngressMetadata_Slack(t *testing.T) {
	now := time.Unix(1730000050, 0)
	headers := http.Header{
		"X-Slack-Request-Timestamp": []string{"1730000000"},
	}
	body := []byte(`{
	  "event_id":"Ev123",
	  "event":{"user":"U12345","text":"hello"}
	}`)

	meta, err := extractIngressMetadata("slack", headers, body, now)
	require.NoError(t, err)
	assert.Equal(t, "U12345", meta.PlatformUserID)
	assert.Equal(t, "Ev123", meta.PlatformMessageID)
	assert.Equal(t, int64(1730000000), meta.OccurredAt.Unix())
}

func TestExtractIngressMetadata_WhatsApp(t *testing.T) {
	now := time.Unix(1730000050, 0)
	body := []byte(`{
	  "entry": [{
	    "changes": [{
	      "value": {
	        "messages": [{
	          "from": "+15550001111",
	          "id": "wamid.abc123",
	          "timestamp": "1730000000"
	        }]
	      }
	    }]
	  }]
	}`)

	meta, err := extractIngressMetadata("whatsapp", http.Header{}, body, now)
	require.NoError(t, err)
	assert.Equal(t, "+15550001111", meta.PlatformUserID)
	assert.Equal(t, "wamid.abc123", meta.PlatformMessageID)
	assert.Equal(t, int64(1730000000), meta.OccurredAt.Unix())
}

func TestExtractIngressMetadata_Telegram(t *testing.T) {
	now := time.Unix(1730000050, 0)
	body := []byte(`{
	  "message": {
	    "message_id": 321,
	    "date": 1730000000,
	    "from": {"id": 987654}
	  }
	}`)

	meta, err := extractIngressMetadata("telegram", http.Header{}, body, now)
	require.NoError(t, err)
	assert.Equal(t, "987654", meta.PlatformUserID)
	assert.Equal(t, "321", meta.PlatformMessageID)
	assert.Equal(t, int64(1730000000), meta.OccurredAt.Unix())
}

func TestExtractIngressMetadata_SlackURLVerification(t *testing.T) {
	now := time.Unix(1730000050, 0)
	headers := http.Header{
		"X-Slack-Request-Timestamp": []string{"1730000000"},
	}
	body := []byte(`{
	  "type":"url_verification",
	  "challenge":"slack-challenge-token"
	}`)

	meta, err := extractIngressMetadata("slack", headers, body, now)
	require.NoError(t, err)
	require.NotNil(t, meta.Control)
	assert.True(t, meta.Control.AcknowledgeOnly)
	assert.Equal(t, "slack-challenge-token", meta.Control.SlackChallenge)
	assert.Equal(t, int64(1730000000), meta.OccurredAt.Unix())
}

func TestExtractIngressMetadata_WhatsAppStatusUpdate(t *testing.T) {
	now := time.Unix(1730000050, 0)
	body := []byte(`{
	  "entry": [{
	    "changes": [{
	      "value": {
	        "statuses": [{
	          "id": "wamid.status",
	          "status": "read",
	          "timestamp": "1730000001"
	        }]
	      }
	    }]
	  }]
	}`)

	meta, err := extractIngressMetadata("whatsapp", http.Header{}, body, now)
	require.NoError(t, err)
	require.NotNil(t, meta.Control)
	assert.True(t, meta.Control.AcknowledgeOnly)
	assert.Empty(t, meta.Control.SlackChallenge)
	assert.Equal(t, int64(1730000001), meta.OccurredAt.Unix())
}

func TestExtractIngressMetadata_UnsupportedProvider(t *testing.T) {
	_, err := extractIngressMetadata("discord", http.Header{}, []byte(`{}`), time.Now())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported provider")
}
