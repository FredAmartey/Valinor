# Hierarchical Memory Volume Mounts Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Wire all four memory layers (personal, department, tenant, shared) as Docker bind mounts so OpenClaw agents can read hierarchical knowledge via the filesystem.

**Architecture:** Expand VMSpec with UserID/DepartmentID/KnowledgeBaseIDs. Add a KnowledgeBaseStore to resolve granted KBs. DockerDriver builds mounts for all four layers. Manager wires it together during provisioning.

**Tech Stack:** Go, Docker Engine API, PostgreSQL (pgx), testify

---

### Task 1: Add UserID, DepartmentID, KnowledgeBaseIDs to VMSpec

**Files:**
- Modify: `internal/orchestrator/orchestrator.go:38-51`

**Step 1: Add the three new fields to VMSpec**

Add after the `TenantID` field (line 40):

```go
type VMSpec struct {
	VMID             string
	TenantID         string   // tenant owning this VM (empty for warm pool)
	UserID           string   // user owning this VM (empty for warm pool)
	DepartmentID     string   // department of the user (empty for warm pool)
	KnowledgeBases   []KBMount // granted knowledge bases for /memory/shared mounts
	RootDrive        string
	DataDrive        string
	DataDriveQuotaMB int
	KernelPath       string
	KernelArgs       string
	VCPUs            int
	MemoryMB         int
	VsockCID         uint32
	UseJailer        bool
	JailerPath       string
}

// KBMount identifies a knowledge base to mount as a shared volume.
type KBMount struct {
	ID   string // knowledge_bases.id
	Name string // knowledge_bases.name (used as subdirectory under /memory/shared/)
}
```

**Step 2: Verify it compiles**

Run: `CGO_ENABLED=0 go build ./internal/orchestrator/`
Expected: Success (new fields are zero-valued, no callers break)

**Step 3: Commit**

```bash
git add internal/orchestrator/orchestrator.go
git commit -m "feat: add UserID, DepartmentID, KnowledgeBases to VMSpec"
```

---

### Task 2: Create KnowledgeBaseStore with GrantsForUser query

**Files:**
- Create: `internal/orchestrator/kb_store.go`
- Create: `internal/orchestrator/kb_store_test.go`

**Step 1: Write the failing test**

Create `internal/orchestrator/kb_store_test.go`:

```go
package orchestrator_test

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/valinor-ai/valinor/internal/orchestrator"
	"github.com/valinor-ai/valinor/internal/platform/database"
)

func requireTestDB(t *testing.T) *database.Pool {
	t.Helper()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		dsn = "postgres://valinor:valinor@localhost:5432/valinor?sslmode=disable"
	}
	pool, err := database.Connect(context.Background(), dsn)
	if err != nil {
		t.Skip("database not available, skipping integration test")
	}
	t.Cleanup(func() { pool.Close() })
	return pool
}

func TestKBStore_GrantsForUser(t *testing.T) {
	pool := requireTestDB(t)
	ctx := context.Background()
	kbStore := orchestrator.NewKBStore()

	// Use known test tenant from seed data
	tenantID := "a1b2c3d4-0001-4000-8000-000000000001" // gondolin-fc

	// With no grants configured, should return empty slice
	grants, err := kbStore.GrantsForUser(ctx, pool, tenantID, "00000000-0000-0000-0000-000000000099", "00000000-0000-0000-0000-000000000099")
	require.NoError(t, err)
	require.Empty(t, grants)
}
```

**Step 2: Run test to verify it fails**

Run: `CGO_ENABLED=0 go test ./internal/orchestrator/ -run TestKBStore_GrantsForUser -v -short`
Expected: FAIL — `NewKBStore` undefined

**Step 3: Write the KnowledgeBaseStore implementation**

Create `internal/orchestrator/kb_store.go`:

```go
package orchestrator

import (
	"context"
	"fmt"

	"github.com/valinor-ai/valinor/internal/platform/database"
)

// KBStore queries knowledge_bases and knowledge_base_grants.
type KBStore struct{}

// NewKBStore creates a KBStore.
func NewKBStore() *KBStore {
	return &KBStore{}
}

// GrantsForUser returns all knowledge bases granted to a user, either directly,
// via their department, or via their roles. Uses the owner pool (no RLS).
func (s *KBStore) GrantsForUser(ctx context.Context, q database.Querier, tenantID, userID, departmentID string) ([]KBMount, error) {
	rows, err := q.Query(ctx,
		`SELECT DISTINCT kb.id, kb.name
		 FROM knowledge_bases kb
		 JOIN knowledge_base_grants g ON g.knowledge_base_id = kb.id
		 WHERE kb.tenant_id = $1
		   AND (
		       (g.grant_type = 'user' AND g.grant_target_id = $2::UUID)
		    OR (g.grant_type = 'department' AND g.grant_target_id = $3::UUID)
		    OR (g.grant_type = 'role' AND g.grant_target_id IN (
		            SELECT role_id FROM user_roles WHERE user_id = $2::UUID
		        ))
		   )
		 ORDER BY kb.name`,
		tenantID, userID, departmentID,
	)
	if err != nil {
		return nil, fmt.Errorf("querying knowledge base grants: %w", err)
	}
	defer rows.Close()

	var grants []KBMount
	for rows.Next() {
		var g KBMount
		if err := rows.Scan(&g.ID, &g.Name); err != nil {
			return nil, fmt.Errorf("scanning knowledge base grant: %w", err)
		}
		grants = append(grants, g)
	}
	return grants, rows.Err()
}
```

**Step 4: Run test to verify it passes**

Run: `CGO_ENABLED=0 go test ./internal/orchestrator/ -run TestKBStore_GrantsForUser -v -short`
Expected: PASS (or SKIP if no DB)

**Step 5: Run all tests to verify no regressions**

Run: `CGO_ENABLED=0 go test -short ./...`
Expected: All 16 packages pass

**Step 6: Commit**

```bash
git add internal/orchestrator/kb_store.go internal/orchestrator/kb_store_test.go
git commit -m "feat: add KnowledgeBaseStore with GrantsForUser query"
```

---

### Task 3: Wire KBStore into Manager and populate VMSpec

**Files:**
- Modify: `internal/orchestrator/manager.go:28-34,52,111-131`
- Modify: `cmd/valinor/main.go:239`

**Step 1: Add kbStore field to Manager and update NewManager**

In `internal/orchestrator/manager.go`, add `kbStore` to the Manager struct:

```go
type Manager struct {
	driver  VMDriver
	store   *Store
	kbStore *KBStore
	pool    *database.Pool
	cfg     ManagerConfig
	mu      sync.Mutex
}

func NewManager(pool *database.Pool, driver VMDriver, store *Store, kbStore *KBStore, cfg ManagerConfig) *Manager {
```

Set `kbStore: kbStore` in the return value.

**Step 2: Populate VMSpec in coldStart**

In `coldStart()` (around line 126), after building the spec, resolve grants and set identity fields:

```go
	spec := VMSpec{
		VMID:             vmID,
		TenantID:         tenantID,
		VsockCID:         cid,
		DataDriveQuotaMB: m.cfg.WorkspaceDataQuotaMB,
	}

	// Pass identity for memory volume mounts.
	if opts.UserID != nil {
		spec.UserID = *opts.UserID
	}
	if opts.DepartmentID != nil {
		spec.DepartmentID = *opts.DepartmentID
	}

	// Resolve granted knowledge bases for shared memory mounts.
	if spec.UserID != "" && spec.DepartmentID != "" {
		kbs, kbErr := m.kbStore.GrantsForUser(ctx, m.pool, tenantID, spec.UserID, spec.DepartmentID)
		if kbErr != nil {
			slog.Warn("failed to resolve knowledge base grants, skipping shared mounts", "error", kbErr)
		} else {
			spec.KnowledgeBases = kbs
		}
	}
```

**Step 3: Update main.go to pass kbStore**

In `cmd/valinor/main.go`, around line 239:

```go
	orchKBStore := orchestrator.NewKBStore()
	orchManager = orchestrator.NewManager(pool, orchDriver, orchStore, orchKBStore, orchCfg)
```

**Step 4: Verify it compiles**

Run: `CGO_ENABLED=0 go build ./...`
Expected: Success

**Step 5: Run all tests**

Run: `CGO_ENABLED=0 go test -short ./...`
Expected: All 16 packages pass

**Step 6: Commit**

```bash
git add internal/orchestrator/manager.go cmd/valinor/main.go
git commit -m "feat: wire KBStore into Manager and populate VMSpec with identity"
```

---

### Task 4: Expand DockerDriver mount logic for all four layers

**Files:**
- Modify: `internal/orchestrator/docker_driver.go:96-113`

**Step 1: Replace the personal-only mount block with all four layers**

Replace the mount block in `Start()` (lines 96-113) with:

```go
	// Memory volume mounts: personal (rw), department (ro), tenant (ro), shared (ro per KB).
	var mounts []mount.Mount
	if d.cfg.MemoryBasePath != "" {
		cleanBase := filepath.Clean(d.cfg.MemoryBasePath)

		addMount := func(subpath, target string, readOnly bool) error {
			hostDir := filepath.Join(d.cfg.MemoryBasePath, subpath)
			if !strings.HasPrefix(filepath.Clean(hostDir), cleanBase+string(filepath.Separator)) {
				return fmt.Errorf("memory path %q escapes base %q", hostDir, cleanBase)
			}
			if err := os.MkdirAll(hostDir, 0o750); err != nil {
				return fmt.Errorf("creating memory dir %s: %w", target, err)
			}
			mounts = append(mounts, mount.Mount{
				Type:     mount.TypeBind,
				Source:   hostDir,
				Target:   target,
				ReadOnly: readOnly,
			})
			return nil
		}

		// Personal: per-VM, read-write
		if err := addMount(filepath.Join(spec.VMID, "personal"), "/memory/personal", false); err != nil {
			return VMHandle{}, err
		}

		// Department: shared across dept agents, read-only
		if spec.DepartmentID != "" {
			if err := addMount(filepath.Join("departments", spec.DepartmentID), "/memory/department", true); err != nil {
				return VMHandle{}, err
			}
		}

		// Tenant: shared across tenant agents, read-only
		if spec.TenantID != "" {
			if err := addMount(filepath.Join("tenants", spec.TenantID), "/memory/tenant", true); err != nil {
				return VMHandle{}, err
			}
		}

		// Shared: one read-only mount per granted knowledge base
		for _, kb := range spec.KnowledgeBases {
			target := fmt.Sprintf("/memory/shared/%s", kb.Name)
			if err := addMount(filepath.Join("kbs", kb.ID), target, true); err != nil {
				return VMHandle{}, err
			}
		}
	}
```

**Step 2: Verify it compiles**

Run: `CGO_ENABLED=0 go build ./internal/orchestrator/`
Expected: Success

**Step 3: Commit**

```bash
git add internal/orchestrator/docker_driver.go
git commit -m "feat: expand DockerDriver mount logic for all four memory layers"
```

---

### Task 5: Add unit test for memory mount construction

**Files:**
- Modify: `internal/orchestrator/docker_driver_test.go`

**Step 1: Write the test**

Add to `internal/orchestrator/docker_driver_test.go`:

```go
func TestDockerDriver_MemoryMounts(t *testing.T) {
	requireDocker(t)

	tmpDir := t.TempDir()
	driver := orchestrator.NewDockerDriver(orchestrator.DockerDriverConfig{
		Image:           "alpine:latest",
		NetworkMode:     "none",
		DefaultCPUs:     1,
		DefaultMemoryMB: 64,
		MemoryBasePath:  tmpDir,
		Cmd:             []string{"sleep", "30"},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	spec := orchestrator.VMSpec{
		VMID:         "mount-test",
		TenantID:     "tenant-abc",
		UserID:       "user-123",
		DepartmentID: "dept-456",
		VsockCID:     600,
		KnowledgeBases: []orchestrator.KBMount{
			{ID: "kb-001", Name: "transfer-targets"},
			{ID: "kb-002", Name: "playbook"},
		},
	}

	handle, err := driver.Start(ctx, spec)
	require.NoError(t, err)
	defer func() {
		_ = driver.Stop(ctx, spec.VMID)
		_ = driver.Cleanup(ctx, spec.VMID)
	}()
	require.Equal(t, "mount-test", handle.ID)

	// Verify host directories were created
	require.DirExists(t, filepath.Join(tmpDir, "mount-test", "personal"))
	require.DirExists(t, filepath.Join(tmpDir, "departments", "dept-456"))
	require.DirExists(t, filepath.Join(tmpDir, "tenants", "tenant-abc"))
	require.DirExists(t, filepath.Join(tmpDir, "kbs", "kb-001"))
	require.DirExists(t, filepath.Join(tmpDir, "kbs", "kb-002"))
}
```

You will need these imports at the top of the test file (add any that are missing):

```go
import (
	"context"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/valinor-ai/valinor/internal/orchestrator"
)
```

**Step 2: Run the test**

Run: `CGO_ENABLED=0 go test ./internal/orchestrator/ -run TestDockerDriver_MemoryMounts -v -count=1`
Expected: PASS (or SKIP if Docker not available)

**Step 3: Run all tests**

Run: `CGO_ENABLED=0 go test -short ./...`
Expected: All 16 packages pass

**Step 4: Commit**

```bash
git add internal/orchestrator/docker_driver_test.go
git commit -m "test: add unit test for all four memory mount layers"
```

---

### Task 6: Add integration test for KBStore grant resolution

**Files:**
- Modify: `internal/orchestrator/kb_store_test.go`

**Step 1: Add integration test with seeded grant data**

Add to `internal/orchestrator/kb_store_test.go`:

```go
func TestKBStore_GrantsForUser_Integration(t *testing.T) {
	pool := requireTestDB(t)
	ctx := context.Background()
	kbStore := orchestrator.NewKBStore()

	tenantID := "a1b2c3d4-0001-4000-8000-000000000001" // gondolin-fc

	// Seed a knowledge base and grants for this test.
	// Use a transaction so we can roll back after the test.
	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()

	// Create a test knowledge base
	var kbID string
	err = tx.QueryRow(ctx,
		`INSERT INTO knowledge_bases (tenant_id, name, description, layer)
		 VALUES ($1, 'Test KB', 'test', 'tenant')
		 RETURNING id`,
		tenantID,
	).Scan(&kbID)
	require.NoError(t, err)

	// Grant to a specific user
	testUserID := "a1b2c3d4-0002-4000-8000-000000000001" // glorfindel
	_, err = tx.Exec(ctx,
		`INSERT INTO knowledge_base_grants (knowledge_base_id, grant_type, grant_target_id)
		 VALUES ($1, 'user', $2)`,
		kbID, testUserID,
	)
	require.NoError(t, err)

	// Query grants for the user — should find the KB
	grants, err := kbStore.GrantsForUser(ctx, tx, tenantID, testUserID, "00000000-0000-0000-0000-000000000000")
	require.NoError(t, err)
	require.Len(t, grants, 1)
	require.Equal(t, kbID, grants[0].ID)
	require.Equal(t, "Test KB", grants[0].Name)

	// Query for a different user — should find nothing
	grants, err = kbStore.GrantsForUser(ctx, tx, tenantID, "00000000-0000-0000-0000-000000000099", "00000000-0000-0000-0000-000000000000")
	require.NoError(t, err)
	require.Empty(t, grants)
}
```

**Step 2: Run the test**

Run: `CGO_ENABLED=0 go test ./internal/orchestrator/ -run TestKBStore_GrantsForUser_Integration -v`
Expected: PASS (or SKIP if no DB)

**Step 3: Run all tests**

Run: `CGO_ENABLED=0 go test -short ./...`
Expected: All 16 packages pass

**Step 4: Commit**

```bash
git add internal/orchestrator/kb_store_test.go
git commit -m "test: add integration test for KBStore grant resolution"
```
