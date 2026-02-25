"use client"

import { useState } from "react"
import { useRouter } from "next/navigation"
import { useProvisionAgentMutation } from "@/lib/queries/agents"
import { useUsersQuery } from "@/lib/queries/users"
import { useDepartmentsQuery } from "@/lib/queries/departments"
import { useSession } from "next-auth/react"
import { Label } from "@/components/ui/label"

export function ProvisionAgentForm() {
  const router = useRouter()
  const { data: session } = useSession()
  const mutation = useProvisionAgentMutation()
  const { data: users } = useUsersQuery()
  const { data: departments } = useDepartmentsQuery()

  const isPlatformAdmin = session?.user?.isPlatformAdmin ?? false
  const [userId, setUserId] = useState(isPlatformAdmin ? "" : session?.user?.id ?? "")
  const [departmentId, setDepartmentId] = useState("")
  const [configJson, setConfigJson] = useState("{}")
  const [jsonError, setJsonError] = useState("")

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setJsonError("")

    let parsedConfig: Record<string, unknown> | undefined
    if (configJson.trim() && configJson.trim() !== "{}") {
      try {
        parsedConfig = JSON.parse(configJson)
      } catch {
        setJsonError("Invalid JSON")
        return
      }
    }

    mutation.mutate(
      {
        user_id: userId || undefined,
        department_id: departmentId || undefined,
        config: parsedConfig,
      },
      { onSuccess: (agent) => router.push(`/agents/${agent.id}`) },
    )
  }

  return (
    <form onSubmit={handleSubmit} className="max-w-lg space-y-6">
      <div className="space-y-2">
        <Label htmlFor="userId">User</Label>
        {isPlatformAdmin ? (
          <select
            id="userId"
            className="w-full rounded-lg border border-zinc-200 bg-white px-3 py-2 text-sm text-zinc-900"
            value={userId}
            onChange={(e) => setUserId(e.target.value)}
          >
            <option value="">Auto-assign</option>
            {users?.map((u) => (
              <option key={u.id} value={u.id}>
                {u.display_name || u.email}
              </option>
            ))}
          </select>
        ) : (
          <p className="text-sm text-zinc-500">Assigned to you ({session?.user?.email})</p>
        )}
      </div>

      <div className="space-y-2">
        <Label htmlFor="departmentId">Department</Label>
        <select
          id="departmentId"
          className="w-full rounded-lg border border-zinc-200 bg-white px-3 py-2 text-sm text-zinc-900"
          value={departmentId}
          onChange={(e) => setDepartmentId(e.target.value)}
        >
          <option value="">None</option>
          {departments?.map((d) => (
            <option key={d.id} value={d.id}>{d.name}</option>
          ))}
        </select>
        <p className="text-xs text-zinc-400">Optional. Scope this agent to a department.</p>
      </div>

      <div className="space-y-2">
        <Label htmlFor="config">Initial Config (JSON)</Label>
        <textarea
          id="config"
          value={configJson}
          onChange={(e) => setConfigJson(e.target.value)}
          rows={4}
          className="w-full rounded-lg border border-zinc-200 bg-white px-3 py-2 font-mono text-xs text-zinc-900 focus:border-zinc-400 focus:outline-none focus:ring-1 focus:ring-zinc-400"
        />
        {jsonError && <p className="text-xs text-rose-600">{jsonError}</p>}
        <p className="text-xs text-zinc-400">Optional. Provide initial agent configuration.</p>
      </div>

      {mutation.isError && (
        <div className="rounded-lg border border-rose-200 bg-rose-50 px-3 py-2">
          <p className="text-sm text-rose-700">Failed to provision agent.</p>
        </div>
      )}

      <button
        type="submit"
        disabled={mutation.isPending}
        className="rounded-lg bg-zinc-900 px-4 py-2.5 text-sm font-medium text-white transition-colors hover:bg-zinc-800 active:scale-[0.98] disabled:opacity-50 disabled:cursor-not-allowed"
      >
        {mutation.isPending ? "Provisioning..." : "Provision agent"}
      </button>
    </form>
  )
}
