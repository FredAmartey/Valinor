package auth_test

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valinor-ai/valinor/internal/auth"
)

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
