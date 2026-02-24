package main

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/valinor-ai/valinor/internal/channels"
)

func classifyOutboxHTTPStatus(provider string, status int, message, retryAfterHeader string, now time.Time) error {
	msg := strings.TrimSpace(message)
	if msg == "" {
		msg = http.StatusText(status)
	}

	err := fmt.Errorf("%s send failed: status %d: %s", provider, status, msg)
	if isPermanentOutboxHTTPStatus(status) {
		return channels.NewOutboxPermanentError(err)
	}
	if retryAfter, ok := parseRetryAfterDuration(retryAfterHeader, now); ok {
		return channels.NewOutboxTransientErrorWithRetryAfter(err, retryAfter)
	}
	return err
}

func isPermanentOutboxHTTPStatus(status int) bool {
	if status == http.StatusRequestTimeout || status == http.StatusTooManyRequests {
		return false
	}
	return status >= http.StatusBadRequest && status < http.StatusInternalServerError
}

func parseRetryAfterDuration(headerValue string, now time.Time) (time.Duration, bool) {
	value := strings.TrimSpace(headerValue)
	if value == "" {
		return 0, false
	}

	seconds, err := strconv.Atoi(value)
	if err == nil {
		if seconds > 0 {
			return time.Duration(seconds) * time.Second, true
		}
		return 0, false
	}

	retryAt, err := http.ParseTime(value)
	if err != nil {
		return 0, false
	}
	delay := retryAt.Sub(now)
	if delay <= 0 {
		return 0, false
	}
	return delay, true
}
