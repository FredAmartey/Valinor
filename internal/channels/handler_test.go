package channels

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testWhatsAppWebhookBody() string {
	return fmt.Sprintf(`{
  "entry": [{
    "changes": [{
      "value": {
        "messages": [{
          "from": "+15550001111",
          "id": "wamid.123",
          "timestamp": "%d"
        }]
      }
    }]
  }]
}`, time.Now().Unix())
}

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

	req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/190f3a21-3b2c-42ce-b26e-2f448a58ec14/channels/whatsapp/webhook", strings.NewReader(testWhatsAppWebhookBody()))
	req.SetPathValue("provider", "whatsapp")
	req.SetPathValue("tenantID", "190f3a21-3b2c-42ce-b26e-2f448a58ec14")
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

	req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/190f3a21-3b2c-42ce-b26e-2f448a58ec14/channels/whatsapp/webhook", strings.NewReader(testWhatsAppWebhookBody()))
	req.SetPathValue("provider", "whatsapp")
	req.SetPathValue("tenantID", "190f3a21-3b2c-42ce-b26e-2f448a58ec14")
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

func TestHandleWebhook_RequiresTenantPath(t *testing.T) {
	guard := NewIngressGuard(
		stubVerifier{},
		24*time.Hour,
		func(_ context.Context, _, _ string) (*ChannelLink, error) {
			return &ChannelLink{State: LinkStateVerified}, nil
		},
		func(_ context.Context, _ IngressMessage) (bool, error) { return true, nil },
	)
	h := NewHandler(map[string]*IngressGuard{"whatsapp": guard})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants//channels/whatsapp/webhook", strings.NewReader(testWhatsAppWebhookBody()))
	req.SetPathValue("provider", "whatsapp")
	w := httptest.NewRecorder()

	h.HandleWebhook(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleWebhook_RejectsInvalidTenantPath(t *testing.T) {
	guard := NewIngressGuard(
		stubVerifier{},
		24*time.Hour,
		func(_ context.Context, _, _ string) (*ChannelLink, error) {
			return &ChannelLink{State: LinkStateVerified}, nil
		},
		func(_ context.Context, _ IngressMessage) (bool, error) { return true, nil },
	)
	h := NewHandler(map[string]*IngressGuard{"whatsapp": guard})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/not-a-uuid/channels/whatsapp/webhook", strings.NewReader(testWhatsAppWebhookBody()))
	req.SetPathValue("provider", "whatsapp")
	req.SetPathValue("tenantID", "not-a-uuid")
	w := httptest.NewRecorder()

	h.HandleWebhook(w, req)
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
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/190f3a21-3b2c-42ce-b26e-2f448a58ec14/channels/whatsapp/webhook", strings.NewReader(fmt.Sprintf(`{
  "entry": [{
    "changes": [{
      "value": {
        "messages": [{
          "from": "+15550001111",
          "timestamp": "%d"
        }]
      }
    }]
  }]
}`, time.Now().Unix())))
		req.SetPathValue("provider", "whatsapp")
		req.SetPathValue("tenantID", "190f3a21-3b2c-42ce-b26e-2f448a58ec14")
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

func TestHandleWebhook_UsesPayloadIdentityOverHeader(t *testing.T) {
	var seenUserIDs []string
	guard := NewIngressGuard(
		stubVerifier{},
		24*time.Hour,
		func(_ context.Context, _, platformUserID string) (*ChannelLink, error) {
			seenUserIDs = append(seenUserIDs, platformUserID)
			return &ChannelLink{State: LinkStateVerified}, nil
		},
		func(_ context.Context, _ IngressMessage) (bool, error) { return true, nil },
	)
	h := NewHandler(map[string]*IngressGuard{"whatsapp": guard})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/190f3a21-3b2c-42ce-b26e-2f448a58ec14/channels/whatsapp/webhook", strings.NewReader(testWhatsAppWebhookBody()))
	req.SetPathValue("provider", "whatsapp")
	req.SetPathValue("tenantID", "190f3a21-3b2c-42ce-b26e-2f448a58ec14")
	req.Header.Set("X-Platform-User-ID", "attacker-header-user")
	w := httptest.NewRecorder()

	h.HandleWebhook(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	require.Len(t, seenUserIDs, 1)
	assert.Equal(t, "+15550001111", seenUserIDs[0])
}
