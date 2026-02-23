package channels

import (
	"errors"
	"net/http"
	"time"
)

// Verifier validates incoming webhook authenticity for a provider.
type Verifier interface {
	Verify(headers http.Header, body []byte, now time.Time) error
}

var (
	ErrMissingSignature = errors.New("signature header is required")
	ErrInvalidSignature = errors.New("invalid signature")
	ErrInvalidTimestamp = errors.New("invalid signature timestamp")
	ErrTimestampExpired = errors.New("signature timestamp outside allowed skew")
)
