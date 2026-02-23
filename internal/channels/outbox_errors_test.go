package channels

import (
	"errors"
	"testing"

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
