# Valinor — Agent Instructions

## Cursor Cloud specific instructions

### Architecture

Valinor is a Go modular monolith (API server at `cmd/valinor/`) with a Next.js admin dashboard (`dashboard/`). PostgreSQL 16 is the primary database. See `CLAUDE.md` for coding rules.

### Services

| Service | Port | Start command |
|---------|------|---------------|
| PostgreSQL 16 | 5432 | `sudo pg_ctlcluster 16 main start` |
| Valinor API | 8080 | `go run ./cmd/valinor/` (from repo root) |
| Dashboard | 3000 | `npm run dev` (from `dashboard/`) |

Docker must be running for Go integration tests (testcontainers): `sudo dockerd &>/tmp/dockerd.log &`

### Dev mode

The API server runs in dev mode by default (`auth.devmode: true` in `config.yaml`). This bypasses OIDC authentication — use `Authorization: Bearer dev` for API calls. The dev identity has `TenantID: "dev-tenant"` and `Roles: ["org_admin"]`.

**Important**: After starting PostgreSQL and running the server (which auto-runs migrations), you must seed a dev tenant and roles so the dev identity's RBAC resolves correctly:

```sql
-- Create dev tenant (needed for RBAC role lookup by dev identity)
INSERT INTO tenants (id, name, slug) VALUES ('00000000-0000-0000-0000-000000000001', 'Dev Tenant', 'dev-tenant')
ON CONFLICT (slug) DO NOTHING;

-- Seed RBAC roles for that tenant
INSERT INTO roles (tenant_id, name, permissions, is_system)
VALUES
    ('00000000-0000-0000-0000-000000000001', 'org_admin', '["*"]'::jsonb, true),
    ('00000000-0000-0000-0000-000000000001', 'dept_head', '["agents:read","agents:write","agents:message","users:read","users:write","departments:read","connectors:read","connectors:write","channels:links:read","channels:links:write","channels:messages:write","channels:outbox:read","channels:outbox:write","channels:providers:read","channels:providers:write","audit:read"]'::jsonb, true),
    ('00000000-0000-0000-0000-000000000001', 'standard_user', '["agents:read","agents:message","channels:messages:write"]'::jsonb, true),
    ('00000000-0000-0000-0000-000000000001', 'read_only', '["agents:read"]'::jsonb, true)
ON CONFLICT (tenant_id, name) DO NOTHING;
```

**Caveat**: The dev identity's `TenantID` is the string `"dev-tenant"`, not a UUID. The RBAC engine loads roles keyed by the `tenant_id` column (UUID). This means the dev identity will not match DB-loaded roles unless you also register roles in-memory (the server does this automatically when `pool == nil`, but not when the DB is connected). The workaround is to run `scripts/seed_dev_roles.sql` after the dev tenant exists, or use the SQL above.

### Dashboard login (dev mode)

The dashboard uses next-auth with dev mode. Copy `dashboard/.env.example` to `dashboard/.env`. To log in:
1. Navigate to `http://localhost:3000/login`
2. A dev user must exist in the database — create one if needed:
   ```sql
   INSERT INTO users (tenant_id, email, display_name, oidc_subject, oidc_issuer, is_platform_admin)
   VALUES (
       (SELECT id FROM tenants WHERE slug = 'dev-tenant'),
       'dev@example.com', 'Dev User',
       'dev-oidc-sub', 'dev-issuer', false
   ) ON CONFLICT (oidc_issuer, oidc_subject) DO UPDATE SET email = EXCLUDED.email;
   ```
3. Enter the email on the login page and click "Sign In (Dev Mode)"

### Lint, test, build

- **Go lint**: `golangci-lint run ./...` (golangci-lint v2 must be on PATH; installed at `~/go/bin/`)
- **Go tests (unit, short)**: `go test ./... -short -count=1`
- **Go tests (integration)**: `go test ./... -count=1` (requires Docker for testcontainers)
- **Dashboard lint**: `npx eslint .` (from `dashboard/`; pre-existing lint warnings exist)
- **Dashboard tests**: `npx vitest run` (from `dashboard/`)
- **Dashboard build**: `npm run build` (from `dashboard/`)

### Gotchas

- The server auto-runs DB migrations on startup from the `migrations/` directory.
- `golangci-lint` is installed at `~/go/bin/golangci-lint` — add `~/go/bin` to PATH if needed.
- The pre-commit config (`.pre-commit-config.yaml`) runs gitleaks, golangci-lint, go-mod-tidy, and whitespace checks.
- ESLint in the dashboard has pre-existing errors in `use-agent-websocket.ts` (react-hooks/immutability).
