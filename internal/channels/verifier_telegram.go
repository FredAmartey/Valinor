package channels

import (
	"crypto/hmac"
	"net/http"
	"time"
)

const telegramSecretHeader = "X-Telegram-Bot-Api-Secret-Token"

// TelegramVerifier validates Telegram webhook secret tokens.
type TelegramVerifier struct {
	secretToken string
}

// NewTelegramVerifier creates a Telegram webhook verifier.
func NewTelegramVerifier(secretToken string) *TelegramVerifier {
	return &TelegramVerifier{secretToken: secretToken}
}

// Verify checks Telegram secret token header equality.
func (v *TelegramVerifier) Verify(headers http.Header, _ []byte, _ time.Time) error {
	got := headers.Get(telegramSecretHeader)
	if got == "" {
		return ErrMissingSignature
	}
	if !hmac.Equal([]byte(got), []byte(v.secretToken)) {
		return ErrInvalidSignature
	}
	return nil
}
