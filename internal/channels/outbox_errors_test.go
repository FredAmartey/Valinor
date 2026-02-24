package channels

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestOutboxPermanentError_WrapAndDetect(t *testing.T) {
	baseErr := errors.New("invalid provider token")

	err := NewOutboxPermanentError(baseErr)
	assert.Error(t, err)
	assert.True(t, IsOutboxPermanentError(err))
	assert.ErrorIs(t, err, baseErr)
}

func TestOutboxPermanentError_DetectsNilAndUnrelatedErrors(t *testing.T) {
	assert.False(t, IsOutboxPermanentError(nil))
	assert.False(t, IsOutboxPermanentError(errors.New("temporary network failure")))
}

func TestOutboxPermanentError_DetectsWrappedPermanentErrors(t *testing.T) {
	baseErr := errors.New("invalid provider token")
	permanentErr := NewOutboxPermanentError(baseErr)
	wrappedErr := fmt.Errorf("sender failed: %w", permanentErr)

	assert.True(t, IsOutboxPermanentError(wrappedErr))
	assert.ErrorIs(t, wrappedErr, baseErr)
}

func TestOutboxTransientErrorWithRetryAfter_DetectsDelay(t *testing.T) {
	baseErr := errors.New("provider rate limited")
	err := NewOutboxTransientErrorWithRetryAfter(baseErr, 42*time.Second)

	assert.False(t, IsOutboxPermanentError(err))
	retryAfter, ok := OutboxRetryAfter(err)
	assert.True(t, ok)
	assert.Equal(t, 42*time.Second, retryAfter)
	assert.ErrorIs(t, err, baseErr)
}

func TestOutboxTransientErrorWithRetryAfter_IgnoresNonPositiveDelay(t *testing.T) {
	baseErr := errors.New("provider rate limited")
	err := NewOutboxTransientErrorWithRetryAfter(baseErr, 0)

	retryAfter, ok := OutboxRetryAfter(err)
	assert.False(t, ok)
	assert.Equal(t, 0*time.Second, retryAfter)
}
