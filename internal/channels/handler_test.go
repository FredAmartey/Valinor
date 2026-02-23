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

func TestHandleWebhook_IdempotencyFallbackDeterministic(t *testing.T) {
	var seenKeys []string
	guard := NewIngressGuard(
		stubVerifier{},
		24*time.Hour,
		func(_ context.Context, _, _ string) (*ChannelLink, error) {
			return &ChannelLink{State: LinkStateVerified}, nil
		},
		func(_ context.Context, msg IngressMessage) (bool, error) {
			seenKeys = append(seenKeys, msg.IdempotencyKey)
			return true, nil
		},
	)

	h := NewHandler(map[string]*IngressGuard{
		"whatsapp": guard,
	})

	makeReq := func() (*http.Request, *httptest.ResponseRecorder) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/channels/whatsapp/webhook", strings.NewReader(`{"text":"hello"}`))
		req.SetPathValue("provider", "whatsapp")
		req.Header.Set("X-Platform-User-ID", "+15550001111")
		w := httptest.NewRecorder()
		return req, w
	}

	req1, w1 := makeReq()
	h.HandleWebhook(w1, req1)
	require.Equal(t, http.StatusOK, w1.Code)

	req2, w2 := makeReq()
	h.HandleWebhook(w2, req2)
	require.Equal(t, http.StatusOK, w2.Code)

	require.Len(t, seenKeys, 2)
	assert.Equal(t, seenKeys[0], seenKeys[1])
	assert.Contains(t, seenKeys[0], "whatsapp:+15550001111:")
}
