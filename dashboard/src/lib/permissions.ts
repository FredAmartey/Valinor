// Mirrors cmd/valinor/main.go rbacEngine.RegisterRole() calls.
// IMPORTANT: Keep in sync with the backend when roles or permissions change.
// There is no automated enforcement — a backend-only permission addition will
// cause the UI to incorrectly hide controls. A future improvement would be to
// include resolved permissions in the JWT or fetch them from the API.
const ROLE_PERMISSIONS: Record<string, string[]> = {
  org_admin: ["*"],
  dept_head: [
    "agents:read", "agents:write", "agents:message",
    "users:read", "users:write",
    "departments:read",
    "connectors:read", "connectors:write",
    "channels:links:read", "channels:links:write",
    "channels:messages:write",
    "channels:outbox:read", "channels:outbox:write",
    "channels:providers:read", "channels:providers:write",
    "audit:read",
  ],
  standard_user: [
    "agents:read", "agents:message",
    "channels:messages:write",
  ],
  read_only: [
    "agents:read",
  ],
}

/**
 * Pure permission check. Safe to call in server components,
 * tests, and anywhere you already have the roles array.
 *
 * @param isPlatformAdmin - full bypass when true
 * @param roles - array of role names from the session
 * @param permission - exact permission string, e.g. "agents:write"
 */
export function hasPermission(
  isPlatformAdmin: boolean,
  roles: string[],
  permission: string,
): boolean {
  if (isPlatformAdmin) return true
  for (const role of roles) {
    const perms = ROLE_PERMISSIONS[role]
    if (!perms) continue
    if (perms.includes("*") || perms.includes(permission)) return true
  }
  return false
}
