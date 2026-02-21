package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math"
	"time"
)

const (
	stateNonceLen = 16
	stateTimeLen  = 8
	stateMACLen   = 32
	stateRawLen   = stateNonceLen + stateTimeLen + stateMACLen // 56
	statePrefix   = "oidc-state:"
	stateMaxSkew  = 30 * time.Second // tolerate small clock drift between replicas
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

	now := time.Now().Unix()
	if now < 0 {
		return "", fmt.Errorf("system clock before Unix epoch")
	}
	ts := make([]byte, stateTimeLen)
	binary.BigEndian.PutUint64(ts, uint64(now))

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

	rawTS := binary.BigEndian.Uint64(ts)
	if rawTS > math.MaxInt64 {
		return false
	}
	issuedAt := time.Unix(int64(rawTS), 0)
	age := time.Since(issuedAt)
	if age < -stateMaxSkew {
		return false // issued too far in the future (clock skew)
	}
	return age <= s.ttl
}

func (s *StateStore) sign(nonce, ts []byte) []byte {
	mac := hmac.New(sha256.New, s.signingKey)
	mac.Write([]byte(statePrefix))
	mac.Write(nonce)
	mac.Write(ts)
	return mac.Sum(nil)
}
