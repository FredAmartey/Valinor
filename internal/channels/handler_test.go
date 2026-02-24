package channels

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valinor-ai/valinor/internal/platform/middleware"
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

func testWhatsAppWebhookBodyWithText(text string) string {
	return fmt.Sprintf(`{
  "entry": [{
    "changes": [{
      "value": {
        "messages": [{
          "from": "+15550001111",
          "id": "wamid.123",
          "timestamp": "%d",
          "text": {"body": %q}
        }]
      }
    }]
  }]
}`, time.Now().Unix(), text)
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

func TestHandleWebhook_AcceptedMessageInvokesExecutor(t *testing.T) {
	guard := NewIngressGuard(
		stubVerifier{},
		24*time.Hour,
		func(_ context.Context, _, _ string) (*ChannelLink, error) {
			return &ChannelLink{
				TenantID: uuid.MustParse("190f3a21-3b2c-42ce-b26e-2f448a58ec14"),
				UserID:   uuid.MustParse("2f6a9b58-c56f-49d5-a06f-45b0145b9e1f"),
				State:    LinkStateVerified,
			}, nil
		},
		func(_ context.Context, _ IngressMessage) (bool, error) {
			return true, nil
		},
	)

	executed := false
	var executedMsg ExecutionMessage
	h := NewHandler(map[string]*IngressGuard{
		"whatsapp": guard,
	}).WithExecutor(func(_ context.Context, msg ExecutionMessage) ExecutionResult {
		executed = true
		executedMsg = msg
		return ExecutionResult{
			Decision: IngressExecuted,
			AgentID:  "agent-123",
		}
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/190f3a21-3b2c-42ce-b26e-2f448a58ec14/channels/whatsapp/webhook", strings.NewReader(testWhatsAppWebhookBodyWithText("hello from field")))
	req.SetPathValue("provider", "whatsapp")
	req.SetPathValue("tenantID", "190f3a21-3b2c-42ce-b26e-2f448a58ec14")
	req.Header.Set("X-Request-ID", "req-exec")
	w := httptest.NewRecorder()

	h.HandleWebhook(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.True(t, executed)
	assert.Equal(t, "hello from field", executedMsg.Content)
	assert.Equal(t, "req-exec", executedMsg.CorrelationID)
	assert.Contains(t, w.Body.String(), string(IngressExecuted))
	assert.Contains(t, w.Body.String(), "agent-123")
}

func TestHandleWebhook_DuplicateMessageSkipsExecutor(t *testing.T) {
	guard := NewIngressGuard(
		stubVerifier{},
		24*time.Hour,
		func(_ context.Context, _, _ string) (*ChannelLink, error) {
			return &ChannelLink{State: LinkStateVerified}, nil
		},
		func(_ context.Context, _ IngressMessage) (bool, error) {
			return false, nil
		},
	)

	executed := false
	h := NewHandler(map[string]*IngressGuard{
		"whatsapp": guard,
	}).WithExecutor(func(_ context.Context, _ ExecutionMessage) ExecutionResult {
		executed = true
		return ExecutionResult{Decision: IngressExecuted}
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/190f3a21-3b2c-42ce-b26e-2f448a58ec14/channels/whatsapp/webhook", strings.NewReader(testWhatsAppWebhookBodyWithText("hello duplicate")))
	req.SetPathValue("provider", "whatsapp")
	req.SetPathValue("tenantID", "190f3a21-3b2c-42ce-b26e-2f448a58ec14")
	w := httptest.NewRecorder()

	h.HandleWebhook(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.False(t, executed)
	assert.Contains(t, w.Body.String(), string(IngressDuplicate))
}

func TestHandleWebhook_ExecutionPersistsMessageStatus(t *testing.T) {
	guard := NewIngressGuard(
		stubVerifier{},
		24*time.Hour,
		func(_ context.Context, _, _ string) (*ChannelLink, error) {
			return &ChannelLink{
				TenantID: uuid.MustParse("190f3a21-3b2c-42ce-b26e-2f448a58ec14"),
				UserID:   uuid.MustParse("2f6a9b58-c56f-49d5-a06f-45b0145b9e1f"),
				State:    LinkStateVerified,
			}, nil
		},
		func(_ context.Context, _ IngressMessage) (bool, error) { return true, nil },
	)

	var persisted struct {
		tenantID       string
		platform       string
		idempotencyKey string
		status         string
		metadata       json.RawMessage
	}

	h := NewHandler(map[string]*IngressGuard{"whatsapp": guard}).WithExecutor(
		func(_ context.Context, _ ExecutionMessage) ExecutionResult {
			return ExecutionResult{Decision: IngressExecuted, AgentID: "agent-123"}
		},
	)
	h.updateMessageStatus = func(_ context.Context, tenantID, platform, idempotencyKey, status string, metadata json.RawMessage) error {
		persisted.tenantID = tenantID
		persisted.platform = platform
		persisted.idempotencyKey = idempotencyKey
		persisted.status = status
		persisted.metadata = metadata
		return nil
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/190f3a21-3b2c-42ce-b26e-2f448a58ec14/channels/whatsapp/webhook", strings.NewReader(testWhatsAppWebhookBodyWithText("persist me")))
	req.SetPathValue("provider", "whatsapp")
	req.SetPathValue("tenantID", "190f3a21-3b2c-42ce-b26e-2f448a58ec14")
	w := httptest.NewRecorder()

	h.HandleWebhook(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "190f3a21-3b2c-42ce-b26e-2f448a58ec14", persisted.tenantID)
	assert.Equal(t, "whatsapp", persisted.platform)
	assert.Equal(t, "wamid.123", persisted.idempotencyKey)
	assert.Equal(t, MessageStatusExecuted, persisted.status)
	assert.JSONEq(t, `{"decision":"executed","agent_id":"agent-123"}`, string(persisted.metadata))
}

func TestHandleWebhook_ExecutedEnqueuesOutbox(t *testing.T) {
	guard := NewIngressGuard(
		stubVerifier{},
		24*time.Hour,
		func(_ context.Context, _, _ string) (*ChannelLink, error) {
			return &ChannelLink{
				TenantID: uuid.MustParse("190f3a21-3b2c-42ce-b26e-2f448a58ec14"),
				UserID:   uuid.MustParse("2f6a9b58-c56f-49d5-a06f-45b0145b9e1f"),
				State:    LinkStateVerified,
			}, nil
		},
		func(_ context.Context, _ IngressMessage) (bool, error) { return true, nil },
	)

	var enqueued struct {
		tenantID       string
		platform       string
		idempotencyKey string
		recipientID    string
		outboxThreadTS string
		correlationID  string
		content        string
	}
	enqueuedCalled := false

	h := NewHandler(map[string]*IngressGuard{"whatsapp": guard}).WithExecutor(
		func(_ context.Context, _ ExecutionMessage) ExecutionResult {
			return ExecutionResult{
				Decision:        IngressExecuted,
				AgentID:         "agent-123",
				ResponseContent: "agent response body",
			}
		},
	)
	h.enqueueOutbound = func(_ context.Context, tenantID, platform, idempotencyKey, recipientID, outboxThreadTS, correlationID, responseContent string) error {
		enqueuedCalled = true
		enqueued.tenantID = tenantID
		enqueued.platform = platform
		enqueued.idempotencyKey = idempotencyKey
		enqueued.recipientID = recipientID
		enqueued.outboxThreadTS = outboxThreadTS
		enqueued.correlationID = correlationID
		enqueued.content = responseContent
		return nil
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/190f3a21-3b2c-42ce-b26e-2f448a58ec14/channels/whatsapp/webhook", strings.NewReader(testWhatsAppWebhookBodyWithText("outbox me")))
	req.SetPathValue("provider", "whatsapp")
	req.SetPathValue("tenantID", "190f3a21-3b2c-42ce-b26e-2f448a58ec14")
	req.Header.Set("X-Request-ID", "req-outbox")
	w := httptest.NewRecorder()

	h.HandleWebhook(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.True(t, enqueuedCalled)
	assert.Equal(t, "190f3a21-3b2c-42ce-b26e-2f448a58ec14", enqueued.tenantID)
	assert.Equal(t, "whatsapp", enqueued.platform)
	assert.Equal(t, "wamid.123", enqueued.idempotencyKey)
	assert.Equal(t, "+15550001111", enqueued.recipientID)
	assert.Equal(t, "req-outbox", enqueued.correlationID)
	assert.Equal(t, "agent response body", enqueued.content)
}

func TestHandleWebhook_EnqueueFailureReturns500AndDispatchFailed(t *testing.T) {
	guard := NewIngressGuard(
		stubVerifier{},
		24*time.Hour,
		func(_ context.Context, _, _ string) (*ChannelLink, error) {
			return &ChannelLink{
				TenantID: uuid.MustParse("190f3a21-3b2c-42ce-b26e-2f448a58ec14"),
				UserID:   uuid.MustParse("2f6a9b58-c56f-49d5-a06f-45b0145b9e1f"),
				State:    LinkStateVerified,
			}, nil
		},
		func(_ context.Context, _ IngressMessage) (bool, error) { return true, nil },
	)

	var persistedStatus string
	var persistedMetadata json.RawMessage

	h := NewHandler(map[string]*IngressGuard{"whatsapp": guard}).WithExecutor(
		func(_ context.Context, _ ExecutionMessage) ExecutionResult {
			return ExecutionResult{
				Decision:        IngressExecuted,
				AgentID:         "agent-123",
				ResponseContent: "agent response body",
			}
		},
	)
	h.enqueueOutbound = func(_ context.Context, _, _, _, _, _, _, _ string) error {
		return errors.New("enqueue failed")
	}
	h.updateMessageStatus = func(_ context.Context, _, _, _, status string, metadata json.RawMessage) error {
		persistedStatus = status
		persistedMetadata = metadata
		return nil
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/190f3a21-3b2c-42ce-b26e-2f448a58ec14/channels/whatsapp/webhook", strings.NewReader(testWhatsAppWebhookBodyWithText("outbox me")))
	req.SetPathValue("provider", "whatsapp")
	req.SetPathValue("tenantID", "190f3a21-3b2c-42ce-b26e-2f448a58ec14")
	w := httptest.NewRecorder()

	h.HandleWebhook(w, req)

	require.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "processing webhook failed")
	assert.Equal(t, MessageStatusDispatchFailed, persistedStatus)
	assert.JSONEq(t, `{"decision":"dispatch_failed","agent_id":"agent-123","outbox_enqueue_failed":true,"outbox_recipient_id":"+15550001111","response_content":"agent response body"}`, string(persistedMetadata))
}

func TestHandleWebhook_DuplicateDispatchFailedRequeuesWithoutReexecution(t *testing.T) {
	insertCalls := 0
	guard := NewIngressGuard(
		stubVerifier{},
		24*time.Hour,
		func(_ context.Context, _, _ string) (*ChannelLink, error) {
			return &ChannelLink{
				TenantID: uuid.MustParse("190f3a21-3b2c-42ce-b26e-2f448a58ec14"),
				UserID:   uuid.MustParse("2f6a9b58-c56f-49d5-a06f-45b0145b9e1f"),
				State:    LinkStateVerified,
			}, nil
		},
		func(_ context.Context, _ IngressMessage) (bool, error) {
			insertCalls++
			return insertCalls == 1, nil
		},
	)

	executeCalls := 0
	enqueueCalls := 0
	var persistedStatus string
	var persistedMetadata json.RawMessage

	h := NewHandler(map[string]*IngressGuard{"whatsapp": guard}).WithExecutor(
		func(_ context.Context, _ ExecutionMessage) ExecutionResult {
			executeCalls++
			return ExecutionResult{
				Decision:        IngressExecuted,
				AgentID:         "agent-123",
				ResponseContent: "agent response body",
			}
		},
	)
	h.enqueueOutbound = func(_ context.Context, _, _, _, _, _, _, _ string) error {
		enqueueCalls++
		if enqueueCalls == 1 {
			return errors.New("enqueue failed")
		}
		return nil
	}
	h.updateMessageStatus = func(_ context.Context, _, _, _, status string, metadata json.RawMessage) error {
		persistedStatus = status
		persistedMetadata = append([]byte(nil), metadata...)
		return nil
	}
	h.getMessageByIdempotencyKey = func(_ context.Context, _, _, _ string) (*ChannelMessageRecord, error) {
		return &ChannelMessageRecord{
			PlatformUserID: "+15550001111",
			CorrelationID:  "corr-initial",
			Status:         persistedStatus,
			Metadata:       append([]byte(nil), persistedMetadata...),
		}, nil
	}

	reqOne := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/190f3a21-3b2c-42ce-b26e-2f448a58ec14/channels/whatsapp/webhook", strings.NewReader(testWhatsAppWebhookBodyWithText("outbox me")))
	reqOne.SetPathValue("provider", "whatsapp")
	reqOne.SetPathValue("tenantID", "190f3a21-3b2c-42ce-b26e-2f448a58ec14")
	wOne := httptest.NewRecorder()

	h.HandleWebhook(wOne, reqOne)

	require.Equal(t, http.StatusInternalServerError, wOne.Code)
	assert.Equal(t, 1, executeCalls)
	assert.Equal(t, 1, enqueueCalls)
	assert.Equal(t, MessageStatusDispatchFailed, persistedStatus)
	assert.JSONEq(t, `{"decision":"dispatch_failed","agent_id":"agent-123","outbox_enqueue_failed":true,"outbox_recipient_id":"+15550001111","response_content":"agent response body"}`, string(persistedMetadata))

	reqTwo := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/190f3a21-3b2c-42ce-b26e-2f448a58ec14/channels/whatsapp/webhook", strings.NewReader(testWhatsAppWebhookBodyWithText("outbox me")))
	reqTwo.SetPathValue("provider", "whatsapp")
	reqTwo.SetPathValue("tenantID", "190f3a21-3b2c-42ce-b26e-2f448a58ec14")
	reqTwo.Header.Set("X-Request-ID", "req-retry")
	wTwo := httptest.NewRecorder()

	h.HandleWebhook(wTwo, reqTwo)

	require.Equal(t, http.StatusOK, wTwo.Code)
	assert.Equal(t, 1, executeCalls)
	assert.Equal(t, 2, enqueueCalls)
	assert.Equal(t, MessageStatusExecuted, persistedStatus)
	assert.Contains(t, wTwo.Body.String(), string(IngressExecuted))
	assert.JSONEq(t, `{"decision":"executed","agent_id":"agent-123","outbox_enqueue_failed":false,"outbox_recovered":true,"outbox_recipient_id":"+15550001111","response_content":"agent response body"}`, string(persistedMetadata))
}

func TestHandleWebhook_StatusPersistenceFailureReturns500(t *testing.T) {
	guard := NewIngressGuard(
		stubVerifier{},
		24*time.Hour,
		func(_ context.Context, _, _ string) (*ChannelLink, error) {
			return &ChannelLink{State: LinkStateVerified}, nil
		},
		func(_ context.Context, _ IngressMessage) (bool, error) { return true, nil },
	)

	h := NewHandler(map[string]*IngressGuard{"whatsapp": guard}).WithExecutor(
		func(_ context.Context, _ ExecutionMessage) ExecutionResult {
			return ExecutionResult{Decision: IngressExecuted, AgentID: "agent-123"}
		},
	)
	h.updateMessageStatus = func(_ context.Context, _, _, _, _ string, _ json.RawMessage) error {
		return errors.New("write failed")
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/190f3a21-3b2c-42ce-b26e-2f448a58ec14/channels/whatsapp/webhook", strings.NewReader(testWhatsAppWebhookBodyWithText("persist fail")))
	req.SetPathValue("provider", "whatsapp")
	req.SetPathValue("tenantID", "190f3a21-3b2c-42ce-b26e-2f448a58ec14")
	w := httptest.NewRecorder()

	h.HandleWebhook(w, req)

	require.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "processing webhook failed")
}

func TestHandleWebhook_AcceptedWithoutContentSkipsStatusUpdate(t *testing.T) {
	guard := NewIngressGuard(
		stubVerifier{},
		24*time.Hour,
		func(_ context.Context, _, _ string) (*ChannelLink, error) {
			return &ChannelLink{State: LinkStateVerified}, nil
		},
		func(_ context.Context, _ IngressMessage) (bool, error) { return true, nil },
	)

	executed := false
	statusUpdated := false

	h := NewHandler(map[string]*IngressGuard{"whatsapp": guard}).WithExecutor(
		func(_ context.Context, _ ExecutionMessage) ExecutionResult {
			executed = true
			return ExecutionResult{Decision: IngressExecuted, AgentID: "agent-should-not-run"}
		},
	)
	h.updateMessageStatus = func(_ context.Context, _, _, _, _ string, _ json.RawMessage) error {
		statusUpdated = true
		return nil
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/190f3a21-3b2c-42ce-b26e-2f448a58ec14/channels/whatsapp/webhook", strings.NewReader(testWhatsAppWebhookBodyWithText("   ")))
	req.SetPathValue("provider", "whatsapp")
	req.SetPathValue("tenantID", "190f3a21-3b2c-42ce-b26e-2f448a58ec14")
	w := httptest.NewRecorder()

	h.HandleWebhook(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), string(IngressAccepted))
	assert.False(t, executed)
	assert.False(t, statusUpdated)
}

func TestMessageStatusForDecision(t *testing.T) {
	tests := []struct {
		decision IngressDecision
		expected string
		ok       bool
	}{
		{decision: IngressAccepted, expected: "", ok: false},
		{decision: IngressExecuted, expected: MessageStatusExecuted, ok: true},
		{decision: IngressDeniedRBAC, expected: MessageStatusDeniedRBAC, ok: true},
		{decision: IngressDeniedNoAgent, expected: MessageStatusDeniedNoAgent, ok: true},
		{decision: IngressDeniedSentinel, expected: MessageStatusDeniedSentinel, ok: true},
		{decision: IngressDispatchFailed, expected: MessageStatusDispatchFailed, ok: true},
		{decision: IngressDuplicate, expected: "", ok: false},
		{decision: IngressReplayBlocked, expected: "", ok: false},
		{decision: IngressDeniedUnverified, expected: "", ok: false},
		{decision: IngressRejectedSignature, expected: "", ok: false},
	}

	for _, tc := range tests {
		status, ok := messageStatusForDecision(tc.decision)
		assert.Equal(t, tc.expected, status)
		assert.Equal(t, tc.ok, ok)
	}
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
	fixedTs := time.Now().Unix()
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
}`, fixedTs)))
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

func TestHandleWebhook_SlackURLVerificationRespondsChallenge(t *testing.T) {
	linkLookupCalled := false
	insertCalled := false
	guard := NewIngressGuard(
		stubVerifier{},
		24*time.Hour,
		func(_ context.Context, _, _ string) (*ChannelLink, error) {
			linkLookupCalled = true
			return &ChannelLink{State: LinkStateVerified}, nil
		},
		func(_ context.Context, _ IngressMessage) (bool, error) {
			insertCalled = true
			return true, nil
		},
	)
	h := NewHandler(map[string]*IngressGuard{"slack": guard})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/190f3a21-3b2c-42ce-b26e-2f448a58ec14/channels/slack/webhook", strings.NewReader(`{
  "type":"url_verification",
  "challenge":"slack-challenge-token"
}`))
	req.SetPathValue("provider", "slack")
	req.SetPathValue("tenantID", "190f3a21-3b2c-42ce-b26e-2f448a58ec14")
	w := httptest.NewRecorder()

	h.HandleWebhook(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
	assert.Contains(t, w.Body.String(), "\"challenge\":\"slack-challenge-token\"")
	assert.False(t, linkLookupCalled)
	assert.False(t, insertCalled)
}

func TestHandleWebhook_SlackBotEventUsesBotID(t *testing.T) {
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
	h := NewHandler(map[string]*IngressGuard{"slack": guard})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/190f3a21-3b2c-42ce-b26e-2f448a58ec14/channels/slack/webhook", strings.NewReader(`{
  "event_id":"Ev456",
  "event":{"bot_id":"B12345","text":"hello"}
}`))
	req.SetPathValue("provider", "slack")
	req.SetPathValue("tenantID", "190f3a21-3b2c-42ce-b26e-2f448a58ec14")
	req.Header.Set("X-Slack-Request-Timestamp", strconv.FormatInt(time.Now().Unix(), 10))
	w := httptest.NewRecorder()

	h.HandleWebhook(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "accepted")
	require.Len(t, seenUserIDs, 1)
	assert.Equal(t, "B12345", seenUserIDs[0])
}

func TestHandleWebhook_SlackExecutedEnqueuesOutboxChannelAndThread(t *testing.T) {
	guard := NewIngressGuard(
		stubVerifier{},
		24*time.Hour,
		func(_ context.Context, _, _ string) (*ChannelLink, error) {
			return &ChannelLink{
				TenantID: uuid.MustParse("190f3a21-3b2c-42ce-b26e-2f448a58ec14"),
				UserID:   uuid.MustParse("2f6a9b58-c56f-49d5-a06f-45b0145b9e1f"),
				State:    LinkStateVerified,
			}, nil
		},
		func(_ context.Context, _ IngressMessage) (bool, error) { return true, nil },
	)

	var enqueuedRecipientID string
	var enqueuedThreadTS string
	h := NewHandler(map[string]*IngressGuard{"slack": guard}).WithExecutor(
		func(_ context.Context, _ ExecutionMessage) ExecutionResult {
			return ExecutionResult{
				Decision:        IngressExecuted,
				AgentID:         "agent-123",
				ResponseContent: "agent response body",
			}
		},
	)
	h.enqueueOutbound = func(_ context.Context, _, _, _, recipientID, outboxThreadTS, _, _ string) error {
		enqueuedRecipientID = recipientID
		enqueuedThreadTS = outboxThreadTS
		return nil
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/190f3a21-3b2c-42ce-b26e-2f448a58ec14/channels/slack/webhook", strings.NewReader(`{
  "event_id":"Ev901",
  "event":{"user":"U12345","text":"hello","channel":"C12345","thread_ts":"1730000010.000100"}
}`))
	req.SetPathValue("provider", "slack")
	req.SetPathValue("tenantID", "190f3a21-3b2c-42ce-b26e-2f448a58ec14")
	req.Header.Set("X-Slack-Request-Timestamp", strconv.FormatInt(time.Now().Unix(), 10))
	w := httptest.NewRecorder()

	h.HandleWebhook(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), string(IngressExecuted))
	assert.Equal(t, "C12345", enqueuedRecipientID)
	assert.Equal(t, "1730000010.000100", enqueuedThreadTS)
}

func TestHandleWebhook_SlackExecutedWithoutChannelReturnsDispatchFailed(t *testing.T) {
	guard := NewIngressGuard(
		stubVerifier{},
		24*time.Hour,
		func(_ context.Context, _, _ string) (*ChannelLink, error) {
			return &ChannelLink{
				TenantID: uuid.MustParse("190f3a21-3b2c-42ce-b26e-2f448a58ec14"),
				UserID:   uuid.MustParse("2f6a9b58-c56f-49d5-a06f-45b0145b9e1f"),
				State:    LinkStateVerified,
			}, nil
		},
		func(_ context.Context, _ IngressMessage) (bool, error) { return true, nil },
	)

	enqueueCalled := false
	var persistedStatus string
	var persistedMetadata json.RawMessage

	h := NewHandler(map[string]*IngressGuard{"slack": guard}).WithExecutor(
		func(_ context.Context, _ ExecutionMessage) ExecutionResult {
			return ExecutionResult{
				Decision:        IngressExecuted,
				AgentID:         "agent-123",
				ResponseContent: "agent response body",
			}
		},
	)
	h.enqueueOutbound = func(_ context.Context, _, _, _, _, _, _, _ string) error {
		enqueueCalled = true
		return nil
	}
	h.updateMessageStatus = func(_ context.Context, _, _, _, status string, metadata json.RawMessage) error {
		persistedStatus = status
		persistedMetadata = append([]byte(nil), metadata...)
		return nil
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/190f3a21-3b2c-42ce-b26e-2f448a58ec14/channels/slack/webhook", strings.NewReader(`{
  "event_id":"Ev902",
  "event":{"user":"U12345","text":"hello"}
}`))
	req.SetPathValue("provider", "slack")
	req.SetPathValue("tenantID", "190f3a21-3b2c-42ce-b26e-2f448a58ec14")
	req.Header.Set("X-Slack-Request-Timestamp", strconv.FormatInt(time.Now().Unix(), 10))
	w := httptest.NewRecorder()

	h.HandleWebhook(w, req)

	require.Equal(t, http.StatusInternalServerError, w.Code)
	assert.False(t, enqueueCalled)
	assert.Equal(t, MessageStatusDispatchFailed, persistedStatus)
	assert.JSONEq(t, `{"decision":"dispatch_failed","agent_id":"agent-123","outbox_enqueue_failed":true,"response_content":"agent response body"}`, string(persistedMetadata))
}

func TestHandleWebhook_ControlPayloadStillVerifiesSignature(t *testing.T) {
	linkLookupCalled := false
	insertCalled := false
	guard := NewIngressGuard(
		stubVerifier{verifyErr: ErrInvalidSignature},
		24*time.Hour,
		func(_ context.Context, _, _ string) (*ChannelLink, error) {
			linkLookupCalled = true
			return &ChannelLink{State: LinkStateVerified}, nil
		},
		func(_ context.Context, _ IngressMessage) (bool, error) {
			insertCalled = true
			return true, nil
		},
	)
	h := NewHandler(map[string]*IngressGuard{"slack": guard})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/190f3a21-3b2c-42ce-b26e-2f448a58ec14/channels/slack/webhook", strings.NewReader(`{
  "type":"url_verification",
  "challenge":"slack-challenge-token"
}`))
	req.SetPathValue("provider", "slack")
	req.SetPathValue("tenantID", "190f3a21-3b2c-42ce-b26e-2f448a58ec14")
	w := httptest.NewRecorder()

	h.HandleWebhook(w, req)

	require.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), string(IngressRejectedSignature))
	assert.False(t, linkLookupCalled)
	assert.False(t, insertCalled)
}

func TestHandleWebhook_WhatsAppStatusPayloadIgnored(t *testing.T) {
	linkLookupCalled := false
	insertCalled := false
	guard := NewIngressGuard(
		stubVerifier{},
		24*time.Hour,
		func(_ context.Context, _, _ string) (*ChannelLink, error) {
			linkLookupCalled = true
			return &ChannelLink{State: LinkStateVerified}, nil
		},
		func(_ context.Context, _ IngressMessage) (bool, error) {
			insertCalled = true
			return true, nil
		},
	)
	h := NewHandler(map[string]*IngressGuard{"whatsapp": guard})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/190f3a21-3b2c-42ce-b26e-2f448a58ec14/channels/whatsapp/webhook", strings.NewReader(`{
  "entry": [{
    "changes": [{
      "value": {
        "statuses": [{"id":"wamid.status","status":"read"}]
      }
    }]
  }]
}`))
	req.SetPathValue("provider", "whatsapp")
	req.SetPathValue("tenantID", "190f3a21-3b2c-42ce-b26e-2f448a58ec14")
	w := httptest.NewRecorder()

	h.HandleWebhook(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "ignored")
	assert.False(t, linkLookupCalled)
	assert.False(t, insertCalled)
}

func TestHandleWebhook_WhatsAppBatchedMessagesProcessedIndividually(t *testing.T) {
	var seenUserIDs []string
	var seenMessageIDs []string
	now := time.Now().Unix()
	guard := NewIngressGuard(
		stubVerifier{},
		24*time.Hour,
		func(_ context.Context, _, platformUserID string) (*ChannelLink, error) {
			seenUserIDs = append(seenUserIDs, platformUserID)
			return &ChannelLink{State: LinkStateVerified}, nil
		},
		func(_ context.Context, msg IngressMessage) (bool, error) {
			seenMessageIDs = append(seenMessageIDs, msg.PlatformMessageID)
			return true, nil
		},
	)
	h := NewHandler(map[string]*IngressGuard{"whatsapp": guard})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/190f3a21-3b2c-42ce-b26e-2f448a58ec14/channels/whatsapp/webhook", strings.NewReader(fmt.Sprintf(`{
  "entry": [{
    "changes": [{
      "value": {
        "messages": [{
          "from": "+15550001111",
          "id": "wamid.111",
          "timestamp": "%d"
        }, {
          "from": "+15550002222",
          "id": "wamid.222",
          "timestamp": "%d"
        }]
      }
    }]
  }]
}`, now, now+1)))
	req.SetPathValue("provider", "whatsapp")
	req.SetPathValue("tenantID", "190f3a21-3b2c-42ce-b26e-2f448a58ec14")
	w := httptest.NewRecorder()

	h.HandleWebhook(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "accepted")
	assert.Equal(t, []string{"+15550001111", "+15550002222"}, seenUserIDs)
	assert.Equal(t, []string{"wamid.111", "wamid.222"}, seenMessageIDs)
}

func TestHandleWebhook_RejectsMalformedJSON(t *testing.T) {
	guard := NewIngressGuard(
		stubVerifier{},
		24*time.Hour,
		func(_ context.Context, _, _ string) (*ChannelLink, error) {
			return &ChannelLink{State: LinkStateVerified}, nil
		},
		func(_ context.Context, _ IngressMessage) (bool, error) { return true, nil },
	)
	h := NewHandler(map[string]*IngressGuard{"whatsapp": guard})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants/190f3a21-3b2c-42ce-b26e-2f448a58ec14/channels/whatsapp/webhook", strings.NewReader(`not-json`))
	req.SetPathValue("provider", "whatsapp")
	req.SetPathValue("tenantID", "190f3a21-3b2c-42ce-b26e-2f448a58ec14")
	w := httptest.NewRecorder()

	h.HandleWebhook(w, req)

	require.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "invalid webhook payload")
}

func TestHandleListLinks_ReturnsLinks(t *testing.T) {
	expectedID := uuid.New()
	h := NewHandler(nil)
	h.listLinks = func(_ context.Context, tenantID string) ([]ChannelLink, error) {
		assert.Equal(t, "tenant-abc", tenantID)
		return []ChannelLink{{
			ID:             expectedID,
			Platform:       "slack",
			PlatformUserID: "U12345",
			State:          LinkStateVerified,
		}}, nil
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/channels/links", nil)
	req = req.WithContext(middleware.WithTenantID(req.Context(), "tenant-abc"))
	w := httptest.NewRecorder()

	h.HandleListLinks(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var out []ChannelLink
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &out))
	require.Len(t, out, 1)
	assert.Equal(t, expectedID, out[0].ID)
}

func TestHandleCreateLink_ValidRequest(t *testing.T) {
	expectedID := uuid.New()
	seenState := LinkState("")
	seenMethod := ""
	seenMetadata := ""

	h := NewHandler(nil)
	h.upsertLink = func(_ context.Context, tenantID, userID, platform, platformUserID string, state LinkState, verificationMethod string, verificationMetadata json.RawMessage) (*ChannelLink, error) {
		assert.Equal(t, "tenant-create", tenantID)
		assert.Equal(t, "190f3a21-3b2c-42ce-b26e-2f448a58ec14", userID)
		assert.Equal(t, "whatsapp", platform)
		assert.Equal(t, "+15550009999", platformUserID)
		seenState = state
		seenMethod = verificationMethod
		seenMetadata = string(verificationMetadata)
		return &ChannelLink{
			ID:             expectedID,
			Platform:       platform,
			PlatformUserID: platformUserID,
			State:          state,
		}, nil
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/channels/links", strings.NewReader(`{
  "user_id": "190f3a21-3b2c-42ce-b26e-2f448a58ec14",
  "platform": "whatsapp",
  "platform_user_id": "+15550009999",
  "state": "verified",
  "verification_method": "admin_override",
  "verification_metadata": {"source":"manual"}
}`))
	req = req.WithContext(middleware.WithTenantID(req.Context(), "tenant-create"))
	w := httptest.NewRecorder()

	h.HandleCreateLink(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, LinkStateVerified, seenState)
	assert.Equal(t, "admin_override", seenMethod)
	assert.JSONEq(t, `{"source":"manual"}`, seenMetadata)
}

func TestHandleCreateLink_RejectsInvalidUserID(t *testing.T) {
	h := NewHandler(nil)
	h.upsertLink = func(_ context.Context, _, _, _, _ string, _ LinkState, _ string, _ json.RawMessage) (*ChannelLink, error) {
		t.Fatalf("upsert should not be called for invalid user_id")
		return nil, nil
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/channels/links", strings.NewReader(`{
  "user_id": "not-a-uuid",
  "platform": "telegram",
  "platform_user_id": "tg-123"
}`))
	req = req.WithContext(middleware.WithTenantID(req.Context(), "tenant-create"))
	w := httptest.NewRecorder()

	h.HandleCreateLink(w, req)

	require.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "user_id")
}

func TestHandleDeleteLink_NotFound(t *testing.T) {
	h := NewHandler(nil)
	h.deleteLink = func(_ context.Context, tenantID, id string) error {
		assert.Equal(t, "tenant-delete", tenantID)
		assert.Equal(t, "190f3a21-3b2c-42ce-b26e-2f448a58ec14", id)
		return ErrLinkNotFound
	}

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/channels/links/190f3a21-3b2c-42ce-b26e-2f448a58ec14", nil)
	req.SetPathValue("id", "190f3a21-3b2c-42ce-b26e-2f448a58ec14")
	req = req.WithContext(middleware.WithTenantID(req.Context(), "tenant-delete"))
	w := httptest.NewRecorder()

	h.HandleDeleteLink(w, req)

	require.Equal(t, http.StatusNotFound, w.Code)
}

func TestHandleDeleteLink_PropagatesUnexpectedError(t *testing.T) {
	h := NewHandler(nil)
	h.deleteLink = func(_ context.Context, _, _ string) error {
		return errors.New("boom")
	}

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/channels/links/190f3a21-3b2c-42ce-b26e-2f448a58ec14", nil)
	req.SetPathValue("id", "190f3a21-3b2c-42ce-b26e-2f448a58ec14")
	req = req.WithContext(middleware.WithTenantID(req.Context(), "tenant-delete"))
	w := httptest.NewRecorder()

	h.HandleDeleteLink(w, req)

	require.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestHandleGetProviderCredential_ReturnsSanitizedCredential(t *testing.T) {
	h := NewHandler(nil)
	h.getProviderCredential = func(_ context.Context, tenantID, provider string) (*ProviderCredential, error) {
		assert.Equal(t, "tenant-provider", tenantID)
		assert.Equal(t, "slack", provider)
		return &ProviderCredential{
			ID:            uuid.New(),
			Provider:      "slack",
			AccessToken:   "xoxb-secret",
			SigningSecret: "slack-signing-secret",
			APIBaseURL:    "https://slack.example.com",
		}, nil
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/channels/providers/slack/credentials", nil)
	req.SetPathValue("provider", "slack")
	req = req.WithContext(middleware.WithTenantID(req.Context(), "tenant-provider"))
	w := httptest.NewRecorder()

	h.HandleGetProviderCredential(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var out map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &out))
	assert.Equal(t, "slack", out["provider"])
	assert.Equal(t, true, out["has_access_token"])
	assert.Equal(t, true, out["has_signing_secret"])
	assert.Equal(t, false, out["has_secret_token"])
	_, hasToken := out["access_token"]
	assert.False(t, hasToken, "response must not include raw access_token")
	_, hasSigning := out["signing_secret"]
	assert.False(t, hasSigning, "response must not include raw signing_secret")
}

func TestHandleUpsertProviderCredential_ValidRequest(t *testing.T) {
	h := NewHandler(nil)
	h.upsertProviderCredential = func(_ context.Context, tenantID string, params UpsertProviderCredentialParams) (*ProviderCredential, error) {
		assert.Equal(t, "tenant-provider", tenantID)
		assert.Equal(t, "whatsapp", params.Provider)
		assert.Equal(t, "wa-token", params.AccessToken)
		assert.Equal(t, "wa-signing-secret", params.SigningSecret)
		assert.Equal(t, "15550001111", params.PhoneNumberID)
		return &ProviderCredential{
			ID:            uuid.New(),
			Provider:      params.Provider,
			AccessToken:   params.AccessToken,
			SigningSecret: params.SigningSecret,
			PhoneNumberID: params.PhoneNumberID,
		}, nil
	}

	req := httptest.NewRequest(http.MethodPut, "/api/v1/channels/providers/whatsapp/credentials", strings.NewReader(`{
  "access_token": "wa-token",
  "signing_secret": "wa-signing-secret",
  "phone_number_id": "15550001111"
}`))
	req.SetPathValue("provider", "whatsapp")
	req = req.WithContext(middleware.WithTenantID(req.Context(), "tenant-provider"))
	w := httptest.NewRecorder()

	h.HandleUpsertProviderCredential(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var out map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &out))
	assert.Equal(t, "whatsapp", out["provider"])
	assert.Equal(t, true, out["has_access_token"])
	assert.Equal(t, true, out["has_signing_secret"])
	assert.Equal(t, false, out["has_secret_token"])
}

func TestHandleUpsertProviderCredential_ValidationError(t *testing.T) {
	h := NewHandler(nil)
	h.upsertProviderCredential = func(_ context.Context, _ string, _ UpsertProviderCredentialParams) (*ProviderCredential, error) {
		return nil, ErrProviderAccessTokenRequired
	}

	req := httptest.NewRequest(http.MethodPut, "/api/v1/channels/providers/slack/credentials", strings.NewReader(`{}`))
	req.SetPathValue("provider", "slack")
	req = req.WithContext(middleware.WithTenantID(req.Context(), "tenant-provider"))
	w := httptest.NewRecorder()

	h.HandleUpsertProviderCredential(w, req)

	require.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "access token")
}

func TestHandleDeleteProviderCredential_NotFound(t *testing.T) {
	h := NewHandler(nil)
	h.deleteProviderCredential = func(_ context.Context, tenantID, provider string) error {
		assert.Equal(t, "tenant-provider", tenantID)
		assert.Equal(t, "telegram", provider)
		return ErrProviderCredentialNotFound
	}

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/channels/providers/telegram/credentials", nil)
	req.SetPathValue("provider", "telegram")
	req = req.WithContext(middleware.WithTenantID(req.Context(), "tenant-provider"))
	w := httptest.NewRecorder()

	h.HandleDeleteProviderCredential(w, req)

	require.Equal(t, http.StatusNotFound, w.Code)
}

func TestHandleUpsertProviderCredential_TelegramSecretToken(t *testing.T) {
	h := NewHandler(nil)
	h.upsertProviderCredential = func(_ context.Context, tenantID string, params UpsertProviderCredentialParams) (*ProviderCredential, error) {
		assert.Equal(t, "tenant-provider", tenantID)
		assert.Equal(t, "telegram", params.Provider)
		assert.Equal(t, "123456:ABC", params.AccessToken)
		assert.Equal(t, "telegram-secret", params.SecretToken)
		return &ProviderCredential{
			ID:          uuid.New(),
			Provider:    params.Provider,
			AccessToken: params.AccessToken,
			SecretToken: params.SecretToken,
		}, nil
	}

	req := httptest.NewRequest(http.MethodPut, "/api/v1/channels/providers/telegram/credentials", strings.NewReader(`{
  "access_token": "123456:ABC",
  "secret_token": "telegram-secret"
}`))
	req.SetPathValue("provider", "telegram")
	req = req.WithContext(middleware.WithTenantID(req.Context(), "tenant-provider"))
	w := httptest.NewRecorder()

	h.HandleUpsertProviderCredential(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var out map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &out))
	assert.Equal(t, true, out["has_access_token"])
	assert.Equal(t, true, out["has_secret_token"])
	assert.Equal(t, false, out["has_signing_secret"])
}
