package middleware_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valinor-ai/valinor/internal/platform/middleware"
	"github.com/valinor-ai/valinor/internal/platform/telemetry"
)

func TestLogging_CapturesRequest(t *testing.T) {
	var buf bytes.Buffer
	logger := telemetry.NewLogger("info", "json", &buf)

	handler := middleware.Logging(logger)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	var entry map[string]interface{}
	err := json.Unmarshal(buf.Bytes(), &entry)
	require.NoError(t, err)

	assert.Equal(t, "http request", entry["msg"])
	assert.Equal(t, "GET", entry["method"])
	assert.Equal(t, "/api/v1/tenants", entry["path"])
	assert.Equal(t, float64(200), entry["status"])
	assert.Contains(t, entry, "duration_ms")
}
