package channels

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

const (
	slackSignatureHeader = "X-Slack-Signature"
	slackTimestampHeader = "X-Slack-Request-Timestamp"
)

// SlackVerifier verifies Slack webhook signatures.
type SlackVerifier struct {
	signingSecret []byte
	maxSkew       time.Duration
}

// NewSlackVerifier creates a Slack signature verifier.
func NewSlackVerifier(signingSecret string, maxSkew time.Duration) *SlackVerifier {
	if maxSkew <= 0 {
		maxSkew = 5 * time.Minute
	}
	return &SlackVerifier{
		signingSecret: []byte(signingSecret),
		maxSkew:       maxSkew,
	}
}

// Verify validates Slack request timestamp and signature.
func (v *SlackVerifier) Verify(headers http.Header, body []byte, now time.Time) error {
	signature := headers.Get(slackSignatureHeader)
	if signature == "" {
		return ErrMissingSignature
	}
	timestamp := headers.Get(slackTimestampHeader)
	if timestamp == "" {
		return ErrInvalidTimestamp
	}

	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidTimestamp, err)
	}
	msgTime := time.Unix(ts, 0)
	if now.Sub(msgTime) > v.maxSkew || msgTime.Sub(now) > v.maxSkew {
		return ErrTimestampExpired
	}

	base := "v0:" + timestamp + ":" + string(body)
	mac := hmac.New(sha256.New, v.signingSecret)
	if _, err := mac.Write([]byte(base)); err != nil {
		return fmt.Errorf("writing slack signature base: %w", err)
	}
	expected := "v0=" + hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(expected), []byte(signature)) {
		return ErrInvalidSignature
	}
	return nil
}
