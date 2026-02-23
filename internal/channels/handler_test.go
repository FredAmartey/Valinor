package channels

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleWebhook_RejectsInvalidSignature(t *testing.T) {
	guard := NewIngressGuard(
		stubVerifier{verifyErr: ErrInvalidSignature},
		24*time.Hour,
		func(_ context.Context, _, _ string) (*ChannelLink, error) { return nil, nil },
		func(_ context.Context, _ IngressMessage) (bool, error) { return true, nil },
	)

	h := NewHandler(map[string]*IngressGuard{
		"whatsapp": guard,
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/channels/whatsapp/webhook", strings.NewReader(`{}`))
	req.SetPathValue("provider", "whatsapp")
	w := httptest.NewRecorder()

	h.HandleWebhook(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestHandleWebhook_AcceptsVerifiedMessage(t *testing.T) {
	guard := NewIngressGuard(
		stubVerifier{},
		24*time.Hour,
		func(_ context.Context, _, _ string) (*ChannelLink, error) {
			return &ChannelLink{State: LinkStateVerified}, nil
		},
		func(_ context.Context, _ IngressMessage) (bool, error) {
			return true, nil
		},
	)

	h := NewHandler(map[string]*IngressGuard{
		"whatsapp": guard,
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/channels/whatsapp/webhook", strings.NewReader(`{}`))
	req.SetPathValue("provider", "whatsapp")
	req.Header.Set("X-Request-ID", "req-123")
	w := httptest.NewRecorder()

	h.HandleWebhook(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "accepted")
}

func TestHandleListLinks_RequiresTenantContext(t *testing.T) {
	h := NewHandler(nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/channels/links", nil)
	w := httptest.NewRecorder()

	h.HandleListLinks(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}
