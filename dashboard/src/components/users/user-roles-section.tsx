"use client"

import { useState } from "react"
import {
  useRolesQuery,
  useUserRolesQuery,
  useAssignRoleMutation,
  useRemoveRoleMutation,
} from "@/lib/queries/roles"
import { useDepartmentsQuery } from "@/lib/queries/departments"
import { Skeleton } from "@/components/ui/skeleton"
import { Badge } from "@/components/ui/badge"
import { X, Plus } from "@phosphor-icons/react"
import type { AssignRoleRequest } from "@/lib/types"

interface UserRolesSectionProps {
  userId: string
  tenantId: string
}

export function UserRolesSection({ userId, tenantId }: UserRolesSectionProps) {
  const { data: userRoles, isLoading: rolesLoading } = useUserRolesQuery(userId)
  const { data: allRoles } = useRolesQuery()
  const { data: departments } = useDepartmentsQuery()
  const assignMutation = useAssignRoleMutation(userId)
  const removeMutation = useRemoveRoleMutation(userId)

  const [assigning, setAssigning] = useState(false)
  const [selectedRoleId, setSelectedRoleId] = useState("")
  const [scopeType, setScopeType] = useState<"org" | "department">("org")
  const [scopeId, setScopeId] = useState("")

  if (rolesLoading) {
    return <Skeleton className="h-24 w-full" />
  }

  function handleAssign() {
    if (!selectedRoleId || !scopeId) return
    assignMutation.mutate(
      { role_id: selectedRoleId, scope_type: scopeType, scope_id: scopeId },
      {
        onSuccess: () => {
          setAssigning(false)
          setSelectedRoleId("")
          setScopeType("org")
          setScopeId("")
        },
      },
    )
  }

  function handleRemove(role: AssignRoleRequest) {
    removeMutation.mutate(role)
  }

  function getDepartmentName(id: string): string {
    return departments?.find((d) => d.id === id)?.name ?? id
  }

  return (
    <div>
      <h2 className="mb-3 text-sm font-medium text-zinc-900">Roles</h2>
      {(!userRoles || userRoles.length === 0) ? (
        <p className="text-sm text-zinc-500">No roles assigned.</p>
      ) : (
        <div className="space-y-2">
          {userRoles.map((ur) => (
            <div
              key={`${ur.role_id}-${ur.scope_type}-${ur.scope_id}`}
              className="flex items-center justify-between rounded-lg border border-zinc-200 bg-white px-3 py-2"
            >
              <div className="flex items-center gap-2">
                <span className="text-sm font-medium text-zinc-900">{ur.role_name}</span>
                <Badge variant="outline" className="text-xs">
                  {ur.scope_type === "org" ? "Org-wide" : getDepartmentName(ur.scope_id)}
                </Badge>
              </div>
              <button
                onClick={() => handleRemove({
                  role_id: ur.role_id,
                  scope_type: ur.scope_type,
                  scope_id: ur.scope_id,
                })}
                disabled={removeMutation.isPending}
                className="rounded p-1 text-zinc-400 hover:bg-zinc-100 hover:text-zinc-600 transition-colors"
                aria-label={`Remove ${ur.role_name}`}
              >
                <X size={14} />
              </button>
            </div>
          ))}
        </div>
      )}
      {assigning ? (
        <div className="mt-3 space-y-3 rounded-lg border border-zinc-200 bg-zinc-50 p-3">
          <select
            className="w-full rounded-lg border border-zinc-200 bg-white px-3 py-2 text-sm"
            value={selectedRoleId}
            onChange={(e) => setSelectedRoleId(e.target.value)}
          >
            <option value="">Select role...</option>
            {allRoles?.map((r) => (
              <option key={r.id} value={r.id}>{r.name}</option>
            ))}
          </select>
          <div className="flex gap-2">
            <select
              className="flex-1 rounded-lg border border-zinc-200 bg-white px-3 py-2 text-sm"
              value={scopeType}
              onChange={(e) => {
                const newType = e.target.value as "org" | "department"
                setScopeType(newType)
                setScopeId(newType === "org" ? tenantId : "")
              }}
            >
              <option value="org">Org-wide</option>
              <option value="department">Department</option>
            </select>
            {scopeType === "department" && (
              <select
                className="flex-1 rounded-lg border border-zinc-200 bg-white px-3 py-2 text-sm"
                value={scopeId}
                onChange={(e) => setScopeId(e.target.value)}
              >
                <option value="">Select department...</option>
                {departments?.map((d) => (
                  <option key={d.id} value={d.id}>{d.name}</option>
                ))}
              </select>
            )}
          </div>
          <div className="flex gap-2">
            <button
              onClick={handleAssign}
              disabled={!selectedRoleId || !scopeId || assignMutation.isPending}
              className="rounded-lg bg-zinc-900 px-3 py-1.5 text-sm font-medium text-white hover:bg-zinc-800 active:scale-[0.98] disabled:opacity-50"
            >
              {assignMutation.isPending ? "Assigning..." : "Assign"}
            </button>
            <button
              onClick={() => setAssigning(false)}
              className="rounded-lg px-3 py-1.5 text-sm text-zinc-500 hover:text-zinc-700"
            >
              Cancel
            </button>
          </div>
        </div>
      ) : (
        <button
          onClick={() => {
            setScopeId(tenantId)
            setAssigning(true)
          }}
          className="mt-3 flex items-center gap-1.5 text-sm font-medium text-zinc-500 hover:text-zinc-700 transition-colors"
        >
          <Plus size={14} />
          Assign role
        </button>
      )}
    </div>
  )
}
