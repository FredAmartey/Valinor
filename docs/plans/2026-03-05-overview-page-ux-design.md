# Overview Page UX — Role-Adaptive Design

## Problem

The overview page (`/`) shows "Platform Overview — System health and recent activity across all tenants" to all users, including standard users who have no access to tenant data or audit events. This creates a confusing, broken experience for non-admin users.

## Design Decisions

- Unified layout for all roles — same structure, role-adaptive content
- Warm heading: "Welcome back, {firstName}" with role-appropriate subtitle
- Summary stat cards link to detail pages (e.g. "1 Unhealthy" links to `/agents`)
- Personal activity feed for users without audit access via new backend endpoint
- Quick Stats panel only shown for platform admins (tenant breakdown)
- Follow-up design planned: platform admin tenant drill-down navigation

## Heading

All users see: **"Welcome back, {firstName}"**

Subtitle by role:
- Platform admin: "Platform health and activity across all tenants."
- org_admin / dept_head: "Here's what's happening in your organization."
- standard_user / read_only: "Here's what's happening with your agents."

## Layout

```
+---------------------------------------------+
| Welcome back, Fred                          |
| Here's what's happening with your agents.   |
+--------+--------+--------+--------+         |
| Card 1 | Card 2 | Card 3 | Card 4 |        |
+--------+--------+--------+--------+         |
|                                             |
| +--- Recent Activity (2fr) ---+ +- Quick -+ |
| | activity feed                | | Stats   | |
| | (audit OR personal)         | |         | |
| +------------------------------+ +---------+ |
+---------------------------------------------+
```

When Quick Stats is hidden, the activity feed goes full width.

## Stat Cards by Role

| Role           | Cards                                                    |
|----------------|----------------------------------------------------------|
| platform_admin | Total Tenants, Active Tenants, Running Agents, Unhealthy |
| org_admin      | Running Agents, Unhealthy Agents, Total Users, Channels  |
| dept_head      | Running Agents, Unhealthy Agents, Total Users, Channels  |
| standard_user  | Running Agents, Agents Online                            |
| read_only      | Running Agents, Agents Online                            |

Cards with fewer than 4 items naturally collapse the grid (2 cards instead of 4).

## Activity Feed

- Users with `audit:read` -> org-wide audit events (existing `/api/v1/audit/events`)
- Users without `audit:read` -> personal activity via new `GET /api/v1/me/activity`

## Quick Stats Panel

- Platform admin: Suspended/Archived tenant counts (existing behavior)
- All other roles: panel hidden, activity feed goes full width

## Backend: GET /api/v1/me/activity

- No permission gate — scoped to authenticated user's own actions
- Filters `audit_events` table by `user_id = JWT.sub`
- Query param: `limit` (default 10)
- Response shape matches `/api/v1/audit/events` for frontend reuse:
  ```json
  { "count": 5, "events": [...] }
  ```

## Files to Change

| File | Change |
|------|--------|
| `dashboard/src/app/(dashboard)/page.tsx` | Pass session/role info to overview component |
| `dashboard/src/components/overview/platform-overview.tsx` | Rename to `overview.tsx`, make role-adaptive |
| `dashboard/src/components/overview/recent-events.tsx` | Switch data source based on `audit:read` permission |
| `internal/` (new handler) | Add `GET /api/v1/me/activity` endpoint |

## Out of Scope (follow-up design)

- Platform admin tenant drill-down / tenant switcher navigation
- Personal activity feed content beyond audit events (e.g. message history)
