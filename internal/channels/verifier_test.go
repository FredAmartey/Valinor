package channels_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valinor-ai/valinor/internal/channels"
)

func TestSlackVerifier_ValidSignature(t *testing.T) {
	now := time.Unix(1730000000, 0)
	body := []byte(`{"type":"event_callback"}`)
	secret := "slack-signing-secret"
	ts := strconv.FormatInt(now.Unix(), 10)

	base := "v0:" + ts + ":" + string(body)
	mac := hmac.New(sha256.New, []byte(secret))
	_, err := mac.Write([]byte(base))
	require.NoError(t, err)
	signature := "v0=" + hex.EncodeToString(mac.Sum(nil))

	headers := make(http.Header)
	headers.Set("X-Slack-Request-Timestamp", ts)
	headers.Set("X-Slack-Signature", signature)

	verifier := channels.NewSlackVerifier(secret, 5*time.Minute)
	err = verifier.Verify(headers, body, now)
	require.NoError(t, err)
}

func TestSlackVerifier_InvalidSignature(t *testing.T) {
	now := time.Unix(1730000000, 0)
	body := []byte(`{"type":"event_callback"}`)
	secret := "slack-signing-secret"
	ts := strconv.FormatInt(now.Unix(), 10)

	headers := make(http.Header)
	headers.Set("X-Slack-Request-Timestamp", ts)
	headers.Set("X-Slack-Signature", "v0=deadbeef")

	verifier := channels.NewSlackVerifier(secret, 5*time.Minute)
	err := verifier.Verify(headers, body, now)
	require.Error(t, err)
	assert.ErrorIs(t, err, channels.ErrInvalidSignature)
}

func TestSlackVerifier_ExpiredTimestamp(t *testing.T) {
	now := time.Unix(1730000000, 0)
	body := []byte(`{"type":"event_callback"}`)
	secret := "slack-signing-secret"
	oldTS := strconv.FormatInt(now.Add(-10*time.Minute).Unix(), 10)

	base := "v0:" + oldTS + ":" + string(body)
	mac := hmac.New(sha256.New, []byte(secret))
	_, err := mac.Write([]byte(base))
	require.NoError(t, err)
	signature := "v0=" + hex.EncodeToString(mac.Sum(nil))

	headers := make(http.Header)
	headers.Set("X-Slack-Request-Timestamp", oldTS)
	headers.Set("X-Slack-Signature", signature)

	verifier := channels.NewSlackVerifier(secret, 5*time.Minute)
	err = verifier.Verify(headers, body, now)
	require.Error(t, err)
	assert.ErrorIs(t, err, channels.ErrTimestampExpired)
}

func TestWhatsAppVerifier_ValidSignature(t *testing.T) {
	body := []byte(`{"entry":[{"id":"123"}]}`)
	secret := "whatsapp-app-secret"

	mac := hmac.New(sha256.New, []byte(secret))
	_, err := mac.Write(body)
	require.NoError(t, err)
	signature := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	headers := make(http.Header)
	headers.Set("X-Hub-Signature-256", signature)

	verifier := channels.NewWhatsAppVerifier(secret)
	err = verifier.Verify(headers, body, time.Now())
	require.NoError(t, err)
}

func TestWhatsAppVerifier_InvalidSignature(t *testing.T) {
	body := []byte(`{"entry":[{"id":"123"}]}`)
	secret := "whatsapp-app-secret"

	headers := make(http.Header)
	headers.Set("X-Hub-Signature-256", "sha256=deadbeef")

	verifier := channels.NewWhatsAppVerifier(secret)
	err := verifier.Verify(headers, body, time.Now())
	require.Error(t, err)
	assert.ErrorIs(t, err, channels.ErrInvalidSignature)
}

func TestTelegramVerifier_ValidSecretToken(t *testing.T) {
	secretToken := "telegram-secret-token"
	headers := make(http.Header)
	headers.Set("X-Telegram-Bot-Api-Secret-Token", secretToken)

	verifier := channels.NewTelegramVerifier(secretToken)
	err := verifier.Verify(headers, []byte(`{"ok":true}`), time.Now())
	require.NoError(t, err)
}

func TestTelegramVerifier_InvalidSecretToken(t *testing.T) {
	secretToken := "telegram-secret-token"
	headers := make(http.Header)
	headers.Set("X-Telegram-Bot-Api-Secret-Token", "wrong-token")

	verifier := channels.NewTelegramVerifier(secretToken)
	err := verifier.Verify(headers, []byte(`{"ok":true}`), time.Now())
	require.Error(t, err)
	assert.ErrorIs(t, err, channels.ErrInvalidSignature)
}
