"use client"

export const PERMISSION_GRID = [
  { resource: "Agents", permissions: ["agents:read", "agents:write", "agents:message"] },
  { resource: "Users", permissions: ["users:read", "users:write", "users:manage"] },
  { resource: "Departments", permissions: ["departments:read", "departments:write"] },
  { resource: "Connectors", permissions: ["connectors:read", "connectors:write"] },
  { resource: "Channels: Links", permissions: ["channels:links:read", "channels:links:write"] },
  { resource: "Channels: Messages", permissions: ["channels:messages:write"] },
  { resource: "Channels: Outbox", permissions: ["channels:outbox:read", "channels:outbox:write"] },
  { resource: "Channels: Providers", permissions: ["channels:providers:read", "channels:providers:write"] },
] as const

const ALL_ACTIONS = ["read", "write", "message", "manage"] as const

function extractAction(permission: string): string {
  const parts = permission.split(":")
  return parts[parts.length - 1]
}

interface PermissionMatrixProps {
  permissions: string[]
  readonly: boolean
  onChange: (permissions: string[]) => void
}

export function PermissionMatrix({ permissions, readonly, onChange }: PermissionMatrixProps) {
  const permSet = new Set(permissions)

  function handleToggle(perm: string) {
    if (readonly) return
    const next = new Set(permSet)
    if (next.has(perm)) {
      next.delete(perm)
    } else {
      next.add(perm)
    }
    onChange(Array.from(next))
  }

  const actionColumns = ALL_ACTIONS

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-zinc-200">
            <th className="py-2 pr-4 text-left font-medium text-zinc-600">Resource</th>
            {actionColumns.map((action) => (
              <th key={action} className="px-3 py-2 text-center font-medium text-zinc-600 capitalize">
                {action}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {PERMISSION_GRID.map((row) => {
            const rowActions = new Map(
              row.permissions.map((p) => [extractAction(p), p])
            )
            return (
              <tr key={row.resource} className="border-b border-zinc-100">
                <td className="py-2.5 pr-4 font-medium text-zinc-800">{row.resource}</td>
                {actionColumns.map((action) => {
                  const perm = rowActions.get(action)
                  if (!perm) {
                    return <td key={action} className="px-3 py-2.5 text-center" />
                  }
                  return (
                    <td key={action} className="px-3 py-2.5 text-center">
                      <input
                        type="checkbox"
                        data-testid={`perm-${perm}`}
                        checked={permSet.has(perm)}
                        disabled={readonly}
                        onChange={() => handleToggle(perm)}
                        className="h-4 w-4 rounded border-zinc-300 text-zinc-900 focus:ring-zinc-500 disabled:opacity-50"
                      />
                    </td>
                  )
                })}
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}
