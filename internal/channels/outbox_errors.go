package channels

import "errors"

// OutboxSendError marks provider send failures with retry classification metadata.
type OutboxSendError struct {
	err       error
	permanent bool
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
