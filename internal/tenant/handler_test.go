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
	"github.com/valinor-ai/valinor/internal/tenant"
)

func withPlatformAdmin(req *http.Request) *http.Request {
	identity := &auth.Identity{
		UserID:          "admin-1",
		IsPlatformAdmin: true,
	}
	return req.WithContext(auth.WithIdentity(req.Context(), identity))
}

func TestHandler_CreateTenant(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	store := tenant.NewStore(pool)
	handler := tenant.NewHandler(store, nil)

	body := `{"name": "Chelsea FC", "slug": "chelsea-fc"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = withPlatformAdmin(req)
	w := httptest.NewRecorder()

	handler.HandleCreate(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)

	var resp tenant.Tenant
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "Chelsea FC", resp.Name)
	assert.Equal(t, "chelsea-fc", resp.Slug)
	assert.NotEmpty(t, resp.ID)
}

func TestHandler_CreateTenant_InvalidSlug(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	store := tenant.NewStore(pool)
	handler := tenant.NewHandler(store, nil)

	body := `{"name": "Bad", "slug": "api"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/tenants", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req = withPlatformAdmin(req)
	w := httptest.NewRecorder()

	handler.HandleCreate(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandler_GetTenant(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	store := tenant.NewStore(pool)
	handler := tenant.NewHandler(store, nil)

	created, err := store.Create(context.Background(), "Chelsea FC", "chelsea-fc")
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/"+created.ID, nil)
	req.SetPathValue("id", created.ID)
	req = withPlatformAdmin(req)
	w := httptest.NewRecorder()

	handler.HandleGet(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp tenant.Tenant
	err = json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "Chelsea FC", resp.Name)
}

func TestHandler_ListTenants(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	pool, cleanup := setupTestDB(t)
	defer cleanup()

	store := tenant.NewStore(pool)
	handler := tenant.NewHandler(store, nil)

	_, err := store.Create(context.Background(), "Tenant A", "tenant-a")
	require.NoError(t, err)
	_, err = store.Create(context.Background(), "Tenant B", "tenant-b")
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants", nil)
	req = withPlatformAdmin(req)
	w := httptest.NewRecorder()

	handler.HandleList(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp []tenant.Tenant
	err = json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Len(t, resp, 2)
}
