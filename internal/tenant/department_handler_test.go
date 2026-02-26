package tenant_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valinor-ai/valinor/internal/auth"
	"github.com/valinor-ai/valinor/internal/platform/middleware"
	"github.com/valinor-ai/valinor/internal/tenant"
)

// withTenantIdentity sets auth identity and tenant context for handler tests.
func withTenantIdentity(req *http.Request, tenantID string) *http.Request {
	identity := &auth.Identity{
		UserID:   "test-user",
		TenantID: tenantID,
		Roles:    []string{"org_admin"},
	}
	return req.WithContext(auth.WithIdentity(req.Context(), identity))
}

// wrapWithTenantCtx wraps a handler with TenantContext middleware so
// middleware.GetTenantID works in tests.
func wrapWithTenantCtx(h http.HandlerFunc) http.Handler {
	return middleware.TenantContext(h)
}

func TestDepartmentHandler(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ownerPool, rlsPool, cleanup := setupTestDBWithRLS(t)
	defer cleanup()

	ctx := context.Background()
	tenantStore := tenant.NewStore(ownerPool)
	ten, err := tenantStore.Create(ctx, "Handler Org", "handler-org")
	require.NoError(t, err)

	handler := tenant.NewDepartmentHandler(rlsPool, tenant.NewDepartmentStore(), nil)

	t.Run("Create", func(t *testing.T) {
		body := `{"name": "Engineering"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/departments", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req = withTenantIdentity(req, ten.ID)
		w := httptest.NewRecorder()

		wrapWithTenantCtx(handler.HandleCreate).ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)
		var dept tenant.Department
		err := json.Unmarshal(w.Body.Bytes(), &dept)
		require.NoError(t, err)
		assert.Equal(t, "Engineering", dept.Name)
		assert.NotEmpty(t, dept.ID)
	})

	t.Run("Create_EmptyName", func(t *testing.T) {
		body := `{"name": ""}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/departments", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req = withTenantIdentity(req, ten.ID)
		w := httptest.NewRecorder()

		wrapWithTenantCtx(handler.HandleCreate).ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("Create_WithParent", func(t *testing.T) {
		// First create the parent
		body := `{"name": "Product"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/departments", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req = withTenantIdentity(req, ten.ID)
		w := httptest.NewRecorder()
		wrapWithTenantCtx(handler.HandleCreate).ServeHTTP(w, req)
		require.Equal(t, http.StatusCreated, w.Code)
		var parent tenant.Department
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &parent))

		// Now create child
		body = `{"name": "Backend", "parent_id": "` + parent.ID + `"}`
		req = httptest.NewRequest(http.MethodPost, "/api/v1/departments", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req = withTenantIdentity(req, ten.ID)
		w = httptest.NewRecorder()
		wrapWithTenantCtx(handler.HandleCreate).ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)
		var child tenant.Department
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &child))
		assert.Equal(t, &parent.ID, child.ParentID)
	})

	t.Run("Get", func(t *testing.T) {
		// Create a department first
		body := `{"name": "Scouting"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/departments", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req = withTenantIdentity(req, ten.ID)
		w := httptest.NewRecorder()
		wrapWithTenantCtx(handler.HandleCreate).ServeHTTP(w, req)
		require.Equal(t, http.StatusCreated, w.Code)
		var created tenant.Department
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &created))

		// Now get it
		req = httptest.NewRequest(http.MethodGet, "/api/v1/departments/"+created.ID, nil)
		req.SetPathValue("id", created.ID)
		req = withTenantIdentity(req, ten.ID)
		w = httptest.NewRecorder()
		wrapWithTenantCtx(handler.HandleGet).ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var got tenant.Department
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
		assert.Equal(t, "Scouting", got.Name)
	})

	t.Run("List", func(t *testing.T) {
		// Create a fresh tenant for clean list
		ten2, err := tenantStore.Create(ctx, "List Org 2", "list-org-2")
		require.NoError(t, err)

		// Create two departments
		for _, name := range []string{"Dept A", "Dept B"} {
			body := `{"name": "` + name + `"}`
			req := httptest.NewRequest(http.MethodPost, "/api/v1/departments", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req = withTenantIdentity(req, ten2.ID)
			w := httptest.NewRecorder()
			wrapWithTenantCtx(handler.HandleCreate).ServeHTTP(w, req)
			require.Equal(t, http.StatusCreated, w.Code)
		}

		req := httptest.NewRequest(http.MethodGet, "/api/v1/departments", nil)
		req = withTenantIdentity(req, ten2.ID)
		w := httptest.NewRecorder()
		wrapWithTenantCtx(handler.HandleList).ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var departments []tenant.Department
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &departments))
		assert.Len(t, departments, 2)
	})
}
