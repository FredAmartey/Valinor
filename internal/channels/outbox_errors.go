package channels

import (
	"errors"
	"time"
)

// OutboxSendError marks provider send failures with retry classification metadata.
type OutboxSendError struct {
	err        error
	permanent  bool
	retryAfter time.Duration
}

func (e *OutboxSendError) Error() string {
	if e == nil || e.err == nil {
		return ""
	}
	return e.err.Error()
}

func (e *OutboxSendError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.err
}

// NewOutboxPermanentError wraps a send failure that should be dead-lettered immediately.
func NewOutboxPermanentError(err error) error {
	if err == nil {
		return nil
	}
	return &OutboxSendError{
		err:       err,
		permanent: true,
	}
}

// NewOutboxTransientErrorWithRetryAfter wraps a retryable send failure with a suggested delay.
func NewOutboxTransientErrorWithRetryAfter(err error, retryAfter time.Duration) error {
	if err == nil {
		return nil
	}
	return &OutboxSendError{
		err:        err,
		permanent:  false,
		retryAfter: retryAfter,
	}
}

// IsOutboxPermanentError reports whether err represents a non-retryable send failure.
func IsOutboxPermanentError(err error) bool {
	if err == nil {
		return false
	}

	var sendErr *OutboxSendError
	if !errors.As(err, &sendErr) {
		return false
	}
	return sendErr.permanent
}

// OutboxRetryAfter extracts retry-after delay hints from send errors.
func OutboxRetryAfter(err error) (time.Duration, bool) {
	if err == nil {
		return 0, false
	}

	var sendErr *OutboxSendError
	if !errors.As(err, &sendErr) {
		return 0, false
	}
	if sendErr.retryAfter <= 0 {
		return 0, false
	}
	return sendErr.retryAfter, true
}
