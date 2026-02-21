# Phase 1: Foundation — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Establish the Go project scaffold with PostgreSQL connectivity, migrations, HTTP server, structured logging, and graceful shutdown — the base everything else builds on.

**Architecture:** Modular monolith in Go 1.26. Single binary entry point at `cmd/valinor/main.go`. Shared platform infrastructure in `internal/platform/`. Configuration via environment variables with YAML fallback (koanf). PostgreSQL via pgx/v5 connection pool. stdlib `net/http` router (Go 1.22+ patterns). Structured JSON logging via slog.

**Tech Stack:** Go 1.26, PostgreSQL 16, pgx/v5, golang-migrate/v4, koanf/v2, slog, testify, testcontainers-go

**Design Doc:** `docs/plans/2026-02-21-valinor-design.md`

---

### Task 1: Initialize Go Module and Directory Structure

**Files:**
- Create: `go.mod`
- Create: `cmd/valinor/main.go`
- Create: `.gitignore`

**Step 1: Initialize module**

```bash
cd /Users/fred/Documents/Valinor
go mod init github.com/valinor-ai/valinor
```

**Step 2: Create directory structure**

```bash
mkdir -p cmd/valinor
mkdir -p internal/platform/{config,database,server,middleware,telemetry,errors,events}
mkdir -p internal/{auth,rbac,tenant,orchestrator,proxy,audit,lifecycle,channels,connectors}
mkdir -p valinor-agent
mkdir -p api/openapi
mkdir -p migrations
mkdir -p deploy/{docker,systemd,terraform}
```

**Step 3: Create .gitignore**

Create `.gitignore`:
```
# Binaries
/bin/
*.exe
*.exe~
*.dll
*.so
*.dylib
valinor
valinor-agent

# Test
*.test
*.out
coverage.html

# Dependency
/vendor/

# IDE
.idea/
.vscode/
*.swp
*.swo

# OS
.DS_Store
Thumbs.db

# Config (secrets)
.env
*.local.yaml
```

**Step 4: Create minimal main.go**

Create `cmd/valinor/main.go`:
```go
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Println("valinor starting...")
	os.Exit(0)
}
```

**Step 5: Verify it builds and runs**

```bash
go build -o bin/valinor ./cmd/valinor
./bin/valinor
```
Expected: prints "valinor starting..." and exits 0.

**Step 6: Commit**

```bash
git add go.mod cmd/ internal/ valinor-agent/ api/ migrations/ deploy/ .gitignore
git commit -m "feat: initialize Go module and project structure"
```

---

### Task 2: Configuration Loading

**Files:**
- Create: `internal/platform/config/config.go`
- Create: `internal/platform/config/config_test.go`
- Create: `config.yaml` (example config)

**Step 1: Write the failing test**

Create `internal/platform/config/config_test.go`:
```go
package config_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valinor-ai/valinor/internal/platform/config"
)

func TestLoad_Defaults(t *testing.T) {
	cfg, err := config.Load()
	require.NoError(t, err)

	assert.Equal(t, 8080, cfg.Server.Port)
	assert.Equal(t, "info", cfg.Log.Level)
	assert.Equal(t, "json", cfg.Log.Format)
}

func TestLoad_EnvOverrides(t *testing.T) {
	os.Setenv("VALINOR_SERVER_PORT", "9090")
	os.Setenv("VALINOR_DATABASE_URL", "postgres://test:test@localhost:5432/valinor_test")
	defer func() {
		os.Unsetenv("VALINOR_SERVER_PORT")
		os.Unsetenv("VALINOR_DATABASE_URL")
	}()

	cfg, err := config.Load()
	require.NoError(t, err)

	assert.Equal(t, 9090, cfg.Server.Port)
	assert.Equal(t, "postgres://test:test@localhost:5432/valinor_test", cfg.Database.URL)
}
```

**Step 2: Install dependencies and run test to verify it fails**

```bash
go get github.com/knadh/koanf/v2
go get github.com/knadh/koanf/providers/env
go get github.com/knadh/koanf/providers/file
go get github.com/knadh/koanf/parsers/yaml
go get github.com/stretchr/testify
```

```bash
go test ./internal/platform/config/ -v
```
Expected: FAIL — package doesn't exist yet.

**Step 3: Implement config loading**

Create `internal/platform/config/config.go`:
```go
package config

import (
	"strings"

	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
)

type Config struct {
	Server   ServerConfig   `koanf:"server"`
	Database DatabaseConfig `koanf:"database"`
	Log      LogConfig      `koanf:"log"`
}

type ServerConfig struct {
	Port int    `koanf:"port"`
	Host string `koanf:"host"`
}

type DatabaseConfig struct {
	URL             string `koanf:"url"`
	MaxConns        int    `koanf:"max_conns"`
	MigrationsPath  string `koanf:"migrations_path"`
}

type LogConfig struct {
	Level  string `koanf:"level"`
	Format string `koanf:"format"`
}

func Load(configPaths ...string) (*Config, error) {
	k := koanf.New(".")

	// Defaults
	k.Load(confmap(map[string]interface{}{
		"server.port":             8080,
		"server.host":             "0.0.0.0",
		"database.max_conns":      25,
		"database.migrations_path": "migrations",
		"log.level":               "info",
		"log.format":              "json",
	}), nil)

	// YAML file (optional)
	for _, path := range configPaths {
		if err := k.Load(file.Provider(path), yaml.Parser()); err != nil {
			// Config file is optional, skip if not found
			continue
		}
	}

	// Environment variables override everything
	// VALINOR_SERVER_PORT -> server.port
	k.Load(env.Provider("VALINOR_", ".", func(s string) string {
		return strings.Replace(
			strings.ToLower(strings.TrimPrefix(s, "VALINOR_")),
			"_", ".", -1,
		)
	}), nil)

	var cfg Config
	if err := k.Unmarshal("", &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// confmap is a simple koanf.Provider that loads from a map.
type confmapProvider struct {
	mp map[string]interface{}
}

func confmap(mp map[string]interface{}) koanf.Provider {
	return &confmapProvider{mp: mp}
}

func (c *confmapProvider) ReadBytes() ([]byte, error) { return nil, nil }
func (c *confmapProvider) Read() (map[string]interface{}, error) {
	return c.mp, nil
}
```

**Step 4: Run tests to verify they pass**

```bash
go test ./internal/platform/config/ -v
```
Expected: PASS (2 tests).

**Step 5: Create example config file**

Create `config.yaml`:
```yaml
server:
  port: 8080
  host: "0.0.0.0"

database:
  url: "postgres://valinor:valinor@localhost:5432/valinor?sslmode=disable"
  max_conns: 25
  migrations_path: "migrations"

log:
  level: "info"
  format: "json"
```

**Step 6: Commit**

```bash
git add internal/platform/config/ config.yaml go.mod go.sum
git commit -m "feat: add configuration loading with env override support"
```

---

### Task 3: Structured Logging

**Files:**
- Create: `internal/platform/telemetry/logger.go`
- Create: `internal/platform/telemetry/logger_test.go`

**Step 1: Write the failing test**

Create `internal/platform/telemetry/logger_test.go`:
```go
package telemetry_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valinor-ai/valinor/internal/platform/telemetry"
)

func TestNewLogger_JSON(t *testing.T) {
	var buf bytes.Buffer
	logger := telemetry.NewLogger("info", "json", &buf)

	logger.Info("test message", "key", "value")

	var entry map[string]interface{}
	err := json.Unmarshal(buf.Bytes(), &entry)
	require.NoError(t, err)

	assert.Equal(t, "test message", entry["msg"])
	assert.Equal(t, "value", entry["key"])
	assert.Equal(t, "INFO", entry["level"])
}

func TestNewLogger_LevelFiltering(t *testing.T) {
	var buf bytes.Buffer
	logger := telemetry.NewLogger("warn", "json", &buf)

	logger.Info("should not appear")

	assert.Empty(t, buf.String())
}
```

**Step 2: Run test to verify it fails**

```bash
go test ./internal/platform/telemetry/ -v
```
Expected: FAIL — package doesn't exist.

**Step 3: Implement logger**

Create `internal/platform/telemetry/logger.go`:
```go
package telemetry

import (
	"io"
	"log/slog"
	"os"
	"strings"
)

func NewLogger(level, format string, w ...io.Writer) *slog.Logger {
	var writer io.Writer = os.Stderr
	if len(w) > 0 {
		writer = w[0]
	}

	lvl := parseLevel(level)
	opts := &slog.HandlerOptions{Level: lvl}

	var handler slog.Handler
	if format == "text" {
		handler = slog.NewTextHandler(writer, opts)
	} else {
		handler = slog.NewJSONHandler(writer, opts)
	}

	return slog.New(handler)
}

func SetDefault(logger *slog.Logger) {
	slog.SetDefault(logger)
}

func parseLevel(level string) slog.Level {
	switch strings.ToLower(level) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
```

**Step 4: Run tests to verify they pass**

```bash
go test ./internal/platform/telemetry/ -v
```
Expected: PASS (2 tests).

**Step 5: Commit**

```bash
git add internal/platform/telemetry/
git commit -m "feat: add structured JSON logging with slog"
```

---

### Task 4: PostgreSQL Connection Pool

**Files:**
- Create: `internal/platform/database/postgres.go`
- Create: `internal/platform/database/postgres_test.go`

**Step 1: Write the failing test**

Create `internal/platform/database/postgres_test.go`:
```go
package database_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
	"github.com/valinor-ai/valinor/internal/platform/database"
)

func setupPostgres(t *testing.T) (string, func()) {
	t.Helper()
	ctx := context.Background()

	container, err := postgres.Run(ctx,
		"postgres:16-alpine",
		postgres.WithDatabase("valinor_test"),
		postgres.WithUsername("test"),
		postgres.WithPassword("test"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2),
		),
	)
	require.NoError(t, err)

	connStr, err := container.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	cleanup := func() {
		container.Terminate(ctx)
	}

	return connStr, cleanup
}

func TestConnect(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	connStr, cleanup := setupPostgres(t)
	defer cleanup()

	pool, err := database.Connect(context.Background(), connStr, 5)
	require.NoError(t, err)
	defer pool.Close()

	// Verify connection works
	var result int
	err = pool.QueryRow(context.Background(), "SELECT 1").Scan(&result)
	require.NoError(t, err)
	assert.Equal(t, 1, result)
}

func TestConnect_BadURL(t *testing.T) {
	_, err := database.Connect(context.Background(), "postgres://bad:bad@localhost:1/nope", 5)
	assert.Error(t, err)
}
```

**Step 2: Install dependencies and run test to verify it fails**

```bash
go get github.com/jackc/pgx/v5
go get github.com/testcontainers/testcontainers-go
go get github.com/testcontainers/testcontainers-go/modules/postgres
```

```bash
go test ./internal/platform/database/ -v
```
Expected: FAIL — package doesn't exist.

**Step 3: Implement connection pool**

Create `internal/platform/database/postgres.go`:
```go
package database

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

func Connect(ctx context.Context, databaseURL string, maxConns int) (*pgxpool.Pool, error) {
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parsing database URL: %w", err)
	}

	if maxConns > 0 {
		config.MaxConns = int32(maxConns)
	}

	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("creating connection pool: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("pinging database: %w", err)
	}

	return pool, nil
}
```

**Step 4: Run tests to verify they pass**

```bash
go test ./internal/platform/database/ -v -count=1
```
Expected: PASS (2 tests). The integration test requires Docker running.

**Step 5: Commit**

```bash
git add internal/platform/database/ go.mod go.sum
git commit -m "feat: add PostgreSQL connection pool with pgx/v5"
```

---

### Task 5: Database Migrations

**Files:**
- Create: `internal/platform/database/migrate.go`
- Create: `internal/platform/database/migrate_test.go`
- Create: `migrations/000001_initial_schema.up.sql`
- Create: `migrations/000001_initial_schema.down.sql`

**Step 1: Create initial migration files**

Create `migrations/000001_initial_schema.up.sql`:
```sql
-- Tenants
CREATE TABLE tenants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    slug TEXT UNIQUE NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    settings JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Departments
CREATE TABLE departments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    parent_id UUID REFERENCES departments(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_departments_tenant_id ON departments(tenant_id);

-- Users
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    display_name TEXT,
    oidc_subject TEXT,
    oidc_issuer TEXT,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(tenant_id, email)
);

CREATE INDEX idx_users_tenant_id ON users(tenant_id);
CREATE INDEX idx_users_oidc ON users(oidc_issuer, oidc_subject);

-- User-Department membership
CREATE TABLE user_departments (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    department_id UUID NOT NULL REFERENCES departments(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, department_id)
);

-- Roles
CREATE TABLE roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    permissions JSONB NOT NULL DEFAULT '[]',
    is_system BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(tenant_id, name)
);

CREATE INDEX idx_roles_tenant_id ON roles(tenant_id);

-- User-Role assignments (scoped)
CREATE TABLE user_roles (
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    scope_type TEXT NOT NULL,
    scope_id UUID NOT NULL,
    PRIMARY KEY (user_id, role_id, scope_type, scope_id)
);

-- Resource policies
CREATE TABLE resource_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    subject_type TEXT NOT NULL,
    subject_id UUID NOT NULL,
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id UUID,
    effect TEXT NOT NULL,
    conditions JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_resource_policies_tenant_id ON resource_policies(tenant_id);
CREATE INDEX idx_resource_policies_subject ON resource_policies(subject_type, subject_id);

-- Agent instances
CREATE TABLE agent_instances (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    department_id UUID REFERENCES departments(id) ON DELETE SET NULL,
    vm_id TEXT,
    status TEXT NOT NULL DEFAULT 'provisioning',
    config JSONB NOT NULL DEFAULT '{}',
    vsock_cid INTEGER,
    tool_allowlist JSONB NOT NULL DEFAULT '[]',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_health_check TIMESTAMPTZ
);

CREATE INDEX idx_agent_instances_tenant_id ON agent_instances(tenant_id);

-- Channel links
CREATE TABLE channel_links (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    platform TEXT NOT NULL,
    platform_user_id TEXT NOT NULL,
    verified BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(platform, platform_user_id)
);

-- Connectors
CREATE TABLE connectors (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    connector_type TEXT NOT NULL DEFAULT 'mcp',
    endpoint TEXT NOT NULL,
    auth_config JSONB NOT NULL DEFAULT '{}',
    resources JSONB NOT NULL DEFAULT '[]',
    tools JSONB NOT NULL DEFAULT '[]',
    status TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_connectors_tenant_id ON connectors(tenant_id);

-- Audit events (partitioned by month)
CREATE TABLE audit_events (
    id UUID NOT NULL DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    user_id UUID,
    action TEXT NOT NULL,
    resource_type TEXT,
    resource_id UUID,
    metadata JSONB,
    source TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
) PARTITION BY RANGE (created_at);

-- Create initial partition for current month
CREATE TABLE audit_events_2026_02 PARTITION OF audit_events
    FOR VALUES FROM ('2026-02-01') TO ('2026-03-01');

CREATE TABLE audit_events_2026_03 PARTITION OF audit_events
    FOR VALUES FROM ('2026-03-01') TO ('2026-04-01');

CREATE INDEX idx_audit_events_tenant_id ON audit_events(tenant_id);
CREATE INDEX idx_audit_events_created_at ON audit_events(created_at);
CREATE INDEX idx_audit_events_user_id ON audit_events(user_id);

-- Row-Level Security
ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE departments ENABLE ROW LEVEL SECURITY;
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE resource_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_instances ENABLE ROW LEVEL SECURITY;
ALTER TABLE channel_links ENABLE ROW LEVEL SECURITY;
ALTER TABLE connectors ENABLE ROW LEVEL SECURITY;

-- RLS policies (tenant isolation)
-- These use a session variable set per-request: SET app.current_tenant_id = '<uuid>'
CREATE POLICY tenant_isolation ON departments
    USING (tenant_id = current_setting('app.current_tenant_id', true)::UUID);
CREATE POLICY tenant_isolation ON users
    USING (tenant_id = current_setting('app.current_tenant_id', true)::UUID);
CREATE POLICY tenant_isolation ON roles
    USING (tenant_id = current_setting('app.current_tenant_id', true)::UUID);
CREATE POLICY tenant_isolation ON resource_policies
    USING (tenant_id = current_setting('app.current_tenant_id', true)::UUID);
CREATE POLICY tenant_isolation ON agent_instances
    USING (tenant_id = current_setting('app.current_tenant_id', true)::UUID);
CREATE POLICY tenant_isolation ON connectors
    USING (tenant_id = current_setting('app.current_tenant_id', true)::UUID);
```

Create `migrations/000001_initial_schema.down.sql`:
```sql
DROP TABLE IF EXISTS audit_events_2026_03;
DROP TABLE IF EXISTS audit_events_2026_02;
DROP TABLE IF EXISTS audit_events;
DROP TABLE IF EXISTS connectors;
DROP TABLE IF EXISTS channel_links;
DROP TABLE IF EXISTS agent_instances;
DROP TABLE IF EXISTS resource_policies;
DROP TABLE IF EXISTS user_roles;
DROP TABLE IF EXISTS roles;
DROP TABLE IF EXISTS user_departments;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS departments;
DROP TABLE IF EXISTS tenants;
```

**Step 2: Write the failing test for migration runner**

Create `internal/platform/database/migrate_test.go`:
```go
package database_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valinor-ai/valinor/internal/platform/database"
)

func TestRunMigrations(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}

	connStr, cleanup := setupPostgres(t)
	defer cleanup()

	err := database.RunMigrations(connStr, "file:///Users/fred/Documents/Valinor/migrations")
	require.NoError(t, err)

	// Verify tables exist by connecting and querying
	pool, err := database.Connect(context.Background(), connStr, 5)
	require.NoError(t, err)
	defer pool.Close()

	// Check that tenants table exists
	var tableName string
	err = pool.QueryRow(context.Background(),
		"SELECT table_name FROM information_schema.tables WHERE table_name = 'tenants'").
		Scan(&tableName)
	require.NoError(t, err)
	assert.Equal(t, "tenants", tableName)

	// Check that RLS is enabled on users table
	var rlsEnabled bool
	err = pool.QueryRow(context.Background(),
		"SELECT relrowsecurity FROM pg_class WHERE relname = 'users'").
		Scan(&rlsEnabled)
	require.NoError(t, err)
	assert.True(t, rlsEnabled)
}
```

**Step 3: Run test to verify it fails**

```bash
go get github.com/golang-migrate/migrate/v4
go get github.com/golang-migrate/migrate/v4/database/postgres
go get github.com/golang-migrate/migrate/v4/source/file
```

```bash
go test ./internal/platform/database/ -v -run TestRunMigrations -count=1
```
Expected: FAIL — RunMigrations doesn't exist.

**Step 4: Implement migration runner**

Create `internal/platform/database/migrate.go`:
```go
package database

import (
	"errors"
	"fmt"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

func RunMigrations(databaseURL, migrationsPath string) error {
	m, err := migrate.New(migrationsPath, databaseURL)
	if err != nil {
		return fmt.Errorf("creating migrator: %w", err)
	}
	defer m.Close()

	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("running migrations: %w", err)
	}

	return nil
}
```

**Step 5: Run tests to verify they pass**

```bash
go test ./internal/platform/database/ -v -count=1
```
Expected: PASS (3 tests — Connect, Connect_BadURL, RunMigrations).

**Step 6: Commit**

```bash
git add internal/platform/database/migrate.go internal/platform/database/migrate_test.go migrations/ go.mod go.sum
git commit -m "feat: add database migrations with initial schema (all tables + RLS)"
```

---

### Task 6: HTTP Server with Health Check

**Files:**
- Create: `internal/platform/server/server.go`
- Create: `internal/platform/server/server_test.go`

**Step 1: Write the failing test**

Create `internal/platform/server/server_test.go`:
```go
package server_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valinor-ai/valinor/internal/platform/server"
)

func TestServer_HealthCheck(t *testing.T) {
	srv := server.New(":0", nil) // nil db pool for unit test

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var body map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &body)
	require.NoError(t, err)
	assert.Equal(t, "ok", body["status"])
}

func TestServer_ReadinessCheck_NoDB(t *testing.T) {
	srv := server.New(":0", nil)

	req := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	w := httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestServer_NotFound(t *testing.T) {
	srv := server.New(":0", nil)

	req := httptest.NewRequest(http.MethodGet, "/nonexistent", nil)
	w := httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestServer_StartStop(t *testing.T) {
	srv := server.New("127.0.0.1:0", nil)

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Start(ctx)
	}()

	// Give server time to start, then cancel
	cancel()

	err := <-errCh
	assert.NoError(t, err)
}
```

**Step 2: Run test to verify it fails**

```bash
go test ./internal/platform/server/ -v
```
Expected: FAIL — package doesn't exist.

**Step 3: Implement server**

Create `internal/platform/server/server.go`:
```go
package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Server struct {
	httpServer *http.Server
	mux        *http.ServeMux
	pool       *pgxpool.Pool
}

func New(addr string, pool *pgxpool.Pool) *Server {
	mux := http.NewServeMux()

	s := &Server{
		httpServer: &http.Server{
			Addr:         addr,
			Handler:      mux,
			ReadTimeout:  15 * time.Second,
			WriteTimeout: 15 * time.Second,
			IdleTimeout:  60 * time.Second,
		},
		mux:  mux,
		pool: pool,
	}

	s.registerRoutes()
	return s
}

func (s *Server) Handler() http.Handler {
	return s.mux
}

func (s *Server) Start(ctx context.Context) error {
	listener, err := net.Listen("tcp", s.httpServer.Addr)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", s.httpServer.Addr, err)
	}

	slog.Info("server starting", "addr", listener.Addr().String())

	errCh := make(chan error, 1)
	go func() {
		if err := s.httpServer.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		slog.Info("server shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return s.httpServer.Shutdown(shutdownCtx)
	}
}

func (s *Server) registerRoutes() {
	s.mux.HandleFunc("GET /healthz", s.handleHealth)
	s.mux.HandleFunc("GET /readyz", s.handleReadiness)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleReadiness(w http.ResponseWriter, r *http.Request) {
	if s.pool == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"status": "not ready",
			"reason": "database not connected",
		})
		return
	}

	if err := s.pool.Ping(r.Context()); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"status": "not ready",
			"reason": "database ping failed",
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
```

**Step 4: Run tests to verify they pass**

```bash
go test ./internal/platform/server/ -v
```
Expected: PASS (4 tests).

**Step 5: Commit**

```bash
git add internal/platform/server/
git commit -m "feat: add HTTP server with health and readiness checks"
```

---

### Task 7: Request ID Middleware

**Files:**
- Create: `internal/platform/middleware/request_id.go`
- Create: `internal/platform/middleware/request_id_test.go`

**Step 1: Write the failing test**

Create `internal/platform/middleware/request_id_test.go`:
```go
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
```

**Step 2: Run test to verify it fails**

```bash
go test ./internal/platform/middleware/ -v
```
Expected: FAIL.

**Step 3: Implement middleware**

Create `internal/platform/middleware/request_id.go`:
```go
package middleware

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
)

type contextKey string

const requestIDKey contextKey = "request_id"

func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		if id == "" {
			id = generateID()
		}

		ctx := context.WithValue(r.Context(), requestIDKey, id)
		w.Header().Set("X-Request-ID", id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func GetRequestID(ctx context.Context) string {
	if id, ok := ctx.Value(requestIDKey).(string); ok {
		return id
	}
	return ""
}

func generateID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}
```

**Step 4: Run tests to verify they pass**

```bash
go test ./internal/platform/middleware/ -v
```
Expected: PASS (2 tests).

**Step 5: Commit**

```bash
git add internal/platform/middleware/
git commit -m "feat: add request ID middleware"
```

---

### Task 8: Logging Middleware

**Files:**
- Create: `internal/platform/middleware/logging.go`
- Create: `internal/platform/middleware/logging_test.go`

**Step 1: Write the failing test**

Create `internal/platform/middleware/logging_test.go`:
```go
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
```

**Step 2: Run test to verify it fails**

```bash
go test ./internal/platform/middleware/ -v -run TestLogging
```
Expected: FAIL.

**Step 3: Implement logging middleware**

Create `internal/platform/middleware/logging.go`:
```go
package middleware

import (
	"log/slog"
	"net/http"
	"time"
)

type wrappedWriter struct {
	http.ResponseWriter
	statusCode int
}

func (w *wrappedWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

func Logging(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			wrapped := &wrappedWriter{ResponseWriter: w, statusCode: http.StatusOK}
			next.ServeHTTP(wrapped, r)

			duration := time.Since(start)

			logger.Info("http request",
				"method", r.Method,
				"path", r.URL.Path,
				"status", wrapped.statusCode,
				"duration_ms", duration.Milliseconds(),
				"request_id", GetRequestID(r.Context()),
			)
		})
	}
}
```

**Step 4: Run tests to verify they pass**

```bash
go test ./internal/platform/middleware/ -v
```
Expected: PASS (3 tests — RequestID x2, Logging x1).

**Step 5: Commit**

```bash
git add internal/platform/middleware/logging.go internal/platform/middleware/logging_test.go
git commit -m "feat: add HTTP request logging middleware"
```

---

### Task 9: Wire Everything in main.go

**Files:**
- Modify: `cmd/valinor/main.go`

**Step 1: Update main.go to wire all components**

Replace `cmd/valinor/main.go` with:
```go
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/valinor-ai/valinor/internal/platform/config"
	"github.com/valinor-ai/valinor/internal/platform/database"
	"github.com/valinor-ai/valinor/internal/platform/server"
	"github.com/valinor-ai/valinor/internal/platform/telemetry"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	// Load configuration
	cfg, err := config.Load("config.yaml")
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	// Setup logging
	logger := telemetry.NewLogger(cfg.Log.Level, cfg.Log.Format)
	telemetry.SetDefault(logger)

	slog.Info("valinor starting",
		"version", "0.1.0",
		"port", cfg.Server.Port,
	)

	// Connect to database (optional for startup — will retry)
	ctx := context.Background()
	var pool = (*database.Pool)(nil)

	if cfg.Database.URL != "" {
		slog.Info("connecting to database")
		p, err := database.Connect(ctx, cfg.Database.URL, cfg.Database.MaxConns)
		if err != nil {
			slog.Warn("database connection failed, starting without DB", "error", err)
		} else {
			pool = p
			defer pool.Close()

			// Run migrations
			migrationsURL := fmt.Sprintf("file://%s", cfg.Database.MigrationsPath)
			if err := database.RunMigrations(cfg.Database.URL, migrationsURL); err != nil {
				return fmt.Errorf("running migrations: %w", err)
			}
			slog.Info("migrations complete")
		}
	}

	// Create and start server
	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	srv := server.New(addr, pool)

	// Graceful shutdown on SIGINT/SIGTERM
	ctx, cancel := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	slog.Info("server ready", "addr", addr)
	return srv.Start(ctx)
}
```

**Step 2: Fix the type alias for pool**

The `database.Pool` type doesn't exist yet. Update `internal/platform/database/postgres.go` to add a type alias:

Add at the top of `internal/platform/database/postgres.go`:
```go
// Pool is a type alias for pgxpool.Pool for use in other packages.
type Pool = pgxpool.Pool
```

**Step 3: Build and verify**

```bash
go build ./cmd/valinor
```
Expected: builds successfully.

**Step 4: Run without database to test graceful startup**

```bash
timeout 3 ./bin/valinor 2>&1 || true
```
Expected: starts, logs "valinor starting", logs "server ready", shuts down on timeout.

**Step 5: Run all tests**

```bash
go test ./... -short -v
```
Expected: all unit tests pass (skips integration tests with `-short`).

**Step 6: Commit**

```bash
git add cmd/valinor/main.go internal/platform/database/postgres.go
git commit -m "feat: wire foundation components in main.go with graceful shutdown"
```

---

### Task 10: Verify End-to-End with Docker PostgreSQL

**Step 1: Start PostgreSQL locally**

```bash
docker run -d --name valinor-postgres \
  -e POSTGRES_USER=valinor \
  -e POSTGRES_PASSWORD=valinor \
  -e POSTGRES_DB=valinor \
  -p 5432:5432 \
  postgres:16-alpine
```

**Step 2: Run Valinor with database**

```bash
VALINOR_DATABASE_URL="postgres://valinor:valinor@localhost:5432/valinor?sslmode=disable" \
  go run ./cmd/valinor
```
Expected output (JSON logs):
- "valinor starting"
- "connecting to database"
- "migrations complete"
- "server ready"

**Step 3: Test health endpoint**

```bash
curl -s http://localhost:8080/healthz | jq .
```
Expected: `{"status": "ok"}`

**Step 4: Test readiness endpoint**

```bash
curl -s http://localhost:8080/readyz | jq .
```
Expected: `{"status": "ready"}`

**Step 5: Run full test suite (including integration)**

```bash
go test ./... -v -count=1
```
Expected: all tests pass (integration tests use testcontainers).

**Step 6: Stop PostgreSQL**

```bash
docker stop valinor-postgres && docker rm valinor-postgres
```

**Step 7: Final commit**

```bash
git add -A
git commit -m "feat: Phase 1 Foundation complete — Go scaffold, PostgreSQL, migrations, HTTP server, logging, middleware"
```

---

## Summary

After completing all 10 tasks, Phase 1 delivers:

| Component | Status |
|-----------|--------|
| Go module (`github.com/valinor-ai/valinor`) | Initialized |
| Full directory structure (9 modules) | Created |
| Configuration loading (env + YAML) | Working + tested |
| Structured JSON logging (slog) | Working + tested |
| PostgreSQL connection pool (pgx/v5) | Working + integration tested |
| Database migrations (full schema + RLS) | Working + integration tested |
| HTTP server with health/readiness | Working + tested |
| Request ID middleware | Working + tested |
| Logging middleware | Working + tested |
| Graceful shutdown (SIGINT/SIGTERM) | Working |
| 10 commits | Clean history |

**Next:** Phase 2 — Auth + RBAC (OIDC login, JWT validation, role definitions, policy evaluation middleware)
