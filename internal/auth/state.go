package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"time"
)

const (
	stateNonceLen = 16
	stateTimeLen  = 8
	stateMACLen   = 32
	stateRawLen   = stateNonceLen + stateTimeLen + stateMACLen // 56
	statePrefix   = "oidc-state:"
)

// StateStore produces and validates HMAC-signed OIDC state tokens.
// Tokens are stateless — no server-side storage or background goroutines.
// This allows state validation to work across multiple replicas.
type StateStore struct {
	signingKey []byte
	ttl        time.Duration
}

// NewStateStore creates a state store that signs tokens with the given key.
func NewStateStore(signingKey []byte, ttl time.Duration) *StateStore {
	return &StateStore{
		signingKey: signingKey,
		ttl:        ttl,
	}
}

// Generate creates a new HMAC-signed state token containing a random
// nonce and the current timestamp.
func (s *StateStore) Generate() (string, error) {
	nonce := make([]byte, stateNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("generating state nonce: %w", err)
	}

	ts := make([]byte, stateTimeLen)
	binary.BigEndian.PutUint64(ts, uint64(time.Now().Unix()))

	sig := s.sign(nonce, ts)

	raw := make([]byte, 0, stateRawLen)
	raw = append(raw, nonce...)
	raw = append(raw, ts...)
	raw = append(raw, sig...)

	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// Validate checks the HMAC signature and TTL of a state token.
func (s *StateStore) Validate(state string) bool {
	raw, err := base64.RawURLEncoding.DecodeString(state)
	if err != nil || len(raw) != stateRawLen {
		return false
	}

	nonce := raw[:stateNonceLen]
	ts := raw[stateNonceLen : stateNonceLen+stateTimeLen]
	providedMAC := raw[stateNonceLen+stateTimeLen:]

	if !hmac.Equal(providedMAC, s.sign(nonce, ts)) {
		return false
	}

	issuedAt := time.Unix(int64(binary.BigEndian.Uint64(ts)), 0)
	return time.Since(issuedAt) <= s.ttl
}

func (s *StateStore) sign(nonce, ts []byte) []byte {
	mac := hmac.New(sha256.New, s.signingKey)
	mac.Write([]byte(statePrefix))
	mac.Write(nonce)
	mac.Write(ts)
	return mac.Sum(nil)
}
