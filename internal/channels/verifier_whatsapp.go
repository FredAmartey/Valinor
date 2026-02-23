package channels

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"
)

const whatsappSignatureHeader = "X-Hub-Signature-256"

// WhatsAppVerifier verifies WhatsApp Cloud API signatures.
type WhatsAppVerifier struct {
	appSecret []byte
}

// NewWhatsAppVerifier creates a WhatsApp webhook signature verifier.
func NewWhatsAppVerifier(appSecret string) *WhatsAppVerifier {
	return &WhatsAppVerifier{appSecret: []byte(appSecret)}
}

// Verify validates X-Hub-Signature-256 against request body.
func (v *WhatsAppVerifier) Verify(headers http.Header, body []byte, _ time.Time) error {
	signature := headers.Get(whatsappSignatureHeader)
	if signature == "" {
		return ErrMissingSignature
	}

	mac := hmac.New(sha256.New, v.appSecret)
	if _, err := mac.Write(body); err != nil {
		return fmt.Errorf("writing whatsapp signature payload: %w", err)
	}
	expected := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(expected), []byte(signature)) {
		return ErrInvalidSignature
	}
	return nil
}
