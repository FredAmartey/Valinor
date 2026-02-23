package connectors_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/valinor-ai/valinor/internal/connectors"
	"github.com/valinor-ai/valinor/internal/platform/middleware"
)

func TestHandleCreate_MissingName(t *testing.T) {
	handler := connectors.NewHandler(nil, connectors.NewStore())
	body := `{"endpoint": "https://example.com"}`
	req := httptest.NewRequest("POST", "/api/v1/tenants/test-tenant/connectors", strings.NewReader(body))
	req = req.WithContext(middleware.WithTenantID(req.Context(), "test-tenant"))
	req.SetPathValue("tenantID", "test-tenant")
	w := httptest.NewRecorder()

	handler.HandleCreate(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestHandleDelete_MissingID(t *testing.T) {
	handler := connectors.NewHandler(nil, connectors.NewStore())
	req := httptest.NewRequest("DELETE", "/api/v1/connectors/", nil)
	w := httptest.NewRecorder()

	handler.HandleDelete(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestHandleCreate_TenantPathMismatch(t *testing.T) {
	handler := connectors.NewHandler(nil, connectors.NewStore())
	req := httptest.NewRequest("POST", "/api/v1/connectors", strings.NewReader("{"))
	req = req.WithContext(middleware.WithTenantID(req.Context(), "tenant-a"))
	req.SetPathValue("tenantID", "tenant-b")
	w := httptest.NewRecorder()

	handler.HandleCreate(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
}

func TestHandleList_TenantPathMismatch(t *testing.T) {
	handler := connectors.NewHandler(nil, connectors.NewStore())
	req := httptest.NewRequest("GET", "/api/v1/connectors", nil)
	req = req.WithContext(middleware.WithTenantID(req.Context(), "tenant-a"))
	req.SetPathValue("tenantID", "tenant-b")
	w := httptest.NewRecorder()

	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("handler panicked: %v", recovered)
		}
	}()

	handler.HandleList(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
}
