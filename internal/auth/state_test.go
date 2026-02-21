package auth_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valinor-ai/valinor/internal/auth"
)

// buildStateToken creates a validly-signed state token with an arbitrary timestamp.
// Used to test clock skew rejection without needing to manipulate time.
func buildStateToken(key []byte, unixSec int64) string {
	nonce := make([]byte, 16)
	ts := make([]byte, 8)
	binary.BigEndian.PutUint64(ts, uint64(unixSec))

	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("oidc-state:"))
	mac.Write(nonce)
	mac.Write(ts)
	sig := mac.Sum(nil)

	raw := make([]byte, 0, 56)
	raw = append(raw, nonce...)
	raw = append(raw, ts...)
	raw = append(raw, sig...)
	return base64.RawURLEncoding.EncodeToString(raw)
}

var testKey = []byte("test-signing-key-must-be-32-chars!!")

func TestStateStore_GenerateAndValidate(t *testing.T) {
	store := auth.NewStateStore(testKey, 10*time.Minute)

	state, err := store.Generate()
	require.NoError(t, err)
	assert.NotEmpty(t, state)

	// First validation succeeds
	assert.True(t, store.Validate(state))

	// Stateless: second validation also succeeds (not single-use)
	assert.True(t, store.Validate(state))
}

func TestStateStore_ExpiredState(t *testing.T) {
	store := auth.NewStateStore(testKey, 50*time.Millisecond)

	state, err := store.Generate()
	require.NoError(t, err)

	time.Sleep(100 * time.Millisecond)

	assert.False(t, store.Validate(state))
}

func TestStateStore_UnknownState(t *testing.T) {
	store := auth.NewStateStore(testKey, 10*time.Minute)

	assert.False(t, store.Validate("unknown-state-value"))
}

func TestStateStore_TamperedState(t *testing.T) {
	store := auth.NewStateStore(testKey, 10*time.Minute)

	state, err := store.Generate()
	require.NoError(t, err)

	// Flip one character in the encoded token
	tampered := []byte(state)
	if tampered[0] == 'A' {
		tampered[0] = 'B'
	} else {
		tampered[0] = 'A'
	}
	assert.False(t, store.Validate(string(tampered)))
}

func TestStateStore_WrongKey(t *testing.T) {
	storeA := auth.NewStateStore([]byte("key-aaaaaaaaaaaaaaaaaaaaaaaaaaaa"), 10*time.Minute)
	storeB := auth.NewStateStore([]byte("key-bbbbbbbbbbbbbbbbbbbbbbbbbbbb"), 10*time.Minute)

	state, err := storeA.Generate()
	require.NoError(t, err)

	assert.False(t, storeB.Validate(state))
}

func TestStateStore_TokenFormat(t *testing.T) {
	store := auth.NewStateStore(testKey, 10*time.Minute)

	state, err := store.Generate()
	require.NoError(t, err)

	raw, err := base64.RawURLEncoding.DecodeString(state)
	require.NoError(t, err)
	assert.Len(t, raw, 56) // 16 nonce + 8 timestamp + 32 HMAC
}

func TestStateStore_EmptyState(t *testing.T) {
	store := auth.NewStateStore(testKey, 10*time.Minute)

	assert.False(t, store.Validate(""))
}

func TestStateStore_TruncatedToken(t *testing.T) {
	store := auth.NewStateStore(testKey, 10*time.Minute)

	state, err := store.Generate()
	require.NoError(t, err)

	truncated := state[:len(state)/2]
	assert.False(t, store.Validate(truncated))
}

func TestStateStore_FutureTimestamp(t *testing.T) {
	store := auth.NewStateStore(testKey, 10*time.Minute)

	// Token issued 5 minutes in the future — exceeds 30s skew tolerance
	futureToken := buildStateToken(testKey, time.Now().Unix()+300)
	assert.False(t, store.Validate(futureToken), "token from 5min in the future should be rejected")

	// Token issued 10 seconds in the future — within 30s skew tolerance
	nearFutureToken := buildStateToken(testKey, time.Now().Unix()+10)
	assert.True(t, store.Validate(nearFutureToken), "token from 10s in the future should be accepted")
}
