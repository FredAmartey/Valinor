# Connectors UI Design

## Goal

Add a dashboard page at `/connectors` that lets org_admins and dept_heads register, view, and delete MCP connectors for their tenant. The backend API is already complete — this is frontend-only work.

## Scope

### In scope

- Single page at `/connectors` with server-side permission gate
- Inline collapsible create form (name, endpoint, tools, auth config JSON)
- Connector list with name, type badge, status pill, endpoint, tools, created date
- Delete with confirmation dialog
- Query hooks following existing factory-key pattern
- `CreateConnectorRequest` type addition
- Audit label entries for `connector.created` / `connector.deleted`

### Out of scope

- No edit/update (backend is immutable — delete + recreate)
- No detail page `/connectors/[id]` (no GET-by-ID route wired)
- No endpoint health check or connection test
- No resources field in create form (unused, defaults to `[]`)
- No auth_config display in list (secrets) — show "[configured]" or "[none]"

## Architecture

### Files to create

| File | Role |
|------|------|
| `dashboard/src/app/(dashboard)/connectors/page.tsx` | Server component — auth gate, passes `canWrite` to view |
| `dashboard/src/lib/queries/connectors.ts` | Key factory, fetch functions, TanStack Query hooks |
| `dashboard/src/components/connectors/connectors-view.tsx` | Client component — list + inline create + delete |

### Files to modify

| File | Change |
|------|--------|
| `dashboard/src/lib/types.ts` | Add `CreateConnectorRequest` interface |
| `dashboard/src/components/audit/audit-labels.ts` | Add `connector.created` / `connector.deleted` entries |

### Patterns followed

- Server component permission check via `hasPermission()` (same as channels, agents)
- Client view with `useSession()` for token, TanStack Query for data
- `apiClient<T>()` for client-side fetches
- `connectorKeys` factory (same pattern as `channelKeys`, `agentKeys`)
- Inline form pattern from channels `CreateLinkForm`
- Status pills, empty states, error+retry from existing component conventions

### Permissions

- `connectors:read` — view list (org_admin, dept_head)
- `connectors:write` — create/delete (org_admin, dept_head)
- Sidebar link already gated on `connectors:read`

## Acceptance criteria

- Page renders at `/connectors` for users with `connectors:read`
- Users with `connectors:write` can register a new connector via inline form
- Users with `connectors:write` can delete a connector with confirmation
- Auth config is accepted in create form but not displayed in list
- Loading, empty, and error states all handled
- Matches visual style of existing dashboard pages
