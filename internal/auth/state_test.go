package auth_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valinor-ai/valinor/internal/auth"
)

func TestStateStore_GenerateAndValidate(t *testing.T) {
	store := auth.NewStateStore(10 * time.Minute)
	defer store.Stop()

	state, err := store.Generate()
	require.NoError(t, err)
	assert.NotEmpty(t, state)
	assert.Len(t, state, 32) // 16 bytes = 32 hex chars

	// First validation succeeds
	assert.True(t, store.Validate(state))

	// Second validation fails (single-use)
	assert.False(t, store.Validate(state))
}

func TestStateStore_ExpiredState(t *testing.T) {
	store := auth.NewStateStore(50 * time.Millisecond)
	defer store.Stop()

	state, err := store.Generate()
	require.NoError(t, err)

	time.Sleep(100 * time.Millisecond)

	assert.False(t, store.Validate(state))
}

func TestStateStore_UnknownState(t *testing.T) {
	store := auth.NewStateStore(10 * time.Minute)
	defer store.Stop()

	assert.False(t, store.Validate("unknown-state-value"))
}
