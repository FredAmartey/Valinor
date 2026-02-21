package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/valinor-ai/valinor/internal/platform/middleware"
)

func TestRequestID_GeneratesID(t *testing.T) {
	handler := middleware.RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetRequestID(r.Context())
		assert.NotEmpty(t, reqID)
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.NotEmpty(t, w.Header().Get("X-Request-ID"))
}

func TestRequestID_UsesExisting(t *testing.T) {
	handler := middleware.RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqID := middleware.GetRequestID(r.Context())
		assert.Equal(t, "existing-id-123", reqID)
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Request-ID", "existing-id-123")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	assert.Equal(t, "existing-id-123", w.Header().Get("X-Request-ID"))
}
