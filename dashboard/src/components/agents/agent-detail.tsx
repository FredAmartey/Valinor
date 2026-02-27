"use client"

import { useState } from "react"
import { useRouter } from "next/navigation"
import { useAgentQuery, useDestroyAgentMutation } from "@/lib/queries/agents"
import { AgentStatusBadge } from "./agent-status-badge"
import { AgentConfigEditor } from "./agent-config-editor"
import { Skeleton } from "@/components/ui/skeleton"
import { Badge } from "@/components/ui/badge"
import { formatDate, formatTimeAgo, truncateId } from "@/lib/format"
import { Wrench, Trash, Gear } from "@phosphor-icons/react"
import Link from "next/link"
import { useCan } from "@/components/providers/permission-provider"
import { AgentChat } from "./agent-chat"

function parseJsonField(val: string | Record<string, unknown> | null): Record<string, unknown> {
  if (!val) return {}
  if (typeof val === "object") return val
  try { return JSON.parse(val) } catch { return {} }
}

function parseArrayField(val: string | string[] | null): string[] {
  if (!val) return []
  if (Array.isArray(val)) return val
  try { return JSON.parse(val) } catch { return [] }
}

export function AgentDetail({ id }: { id: string }) {
  const router = useRouter()
  const { data: agent, isLoading, isError } = useAgentQuery(id)
  const destroyMutation = useDestroyAgentMutation()
  const [editing, setEditing] = useState(false)
  const [confirmDestroy, setConfirmDestroy] = useState(false)
  const canWrite = useCan("agents:write")

  if (isLoading) {
    return (
      <div className="space-y-6">
        <Skeleton className="h-12 w-72" />
        <Skeleton className="h-24 w-full rounded-xl" />
        <Skeleton className="h-48 w-full rounded-xl" />
      </div>
    )
  }

  if (isError || !agent) {
    return (
      <div className="rounded-xl border border-rose-200 bg-rose-50 p-4">
        <p className="text-sm text-rose-700">Failed to load agent details.</p>
      </div>
    )
  }

  const config = parseJsonField(agent.config)
  const tools = parseArrayField(agent.tool_allowlist)

  function handleDestroy() {
    destroyMutation.mutate(id, {
      onSuccess: () => router.push("/agents"),
    })
  }

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-semibold tracking-tight text-zinc-900">Agent</h1>
            <AgentStatusBadge status={agent.status} />
          </div>
          <div className="mt-2 flex items-center gap-4 text-sm text-zinc-500">
            <span className="font-mono" title={agent.id}>{truncateId(agent.id, 12)}</span>
            <span>Created {formatDate(agent.created_at, "long")}</span>
          </div>
        </div>
        <div className="flex gap-2">
          <span
            title={!canWrite ? "You don't have permission to do this." : undefined}
            className={!canWrite ? "cursor-not-allowed" : undefined}
          >
            <button
              onClick={() => setEditing(!editing)}
              disabled={!canWrite}
              className="flex items-center gap-1.5 rounded-lg border border-zinc-200 px-3 py-1.5 text-sm font-medium text-zinc-700 hover:bg-zinc-50 transition-colors active:scale-[0.98] disabled:opacity-40 disabled:cursor-not-allowed disabled:pointer-events-none"
            >
              <Gear size={14} />
              Configure
            </button>
          </span>
          {!confirmDestroy ? (
            <span
              title={!canWrite ? "You don't have permission to do this." : undefined}
              className={!canWrite ? "cursor-not-allowed" : undefined}
            >
              <button
                onClick={() => setConfirmDestroy(true)}
                disabled={!canWrite}
                className="flex items-center gap-1.5 rounded-lg border border-rose-200 px-3 py-1.5 text-sm font-medium text-rose-600 hover:bg-rose-50 transition-colors active:scale-[0.98] disabled:opacity-40 disabled:cursor-not-allowed disabled:pointer-events-none"
              >
                <Trash size={14} />
                Destroy
              </button>
            </span>
          ) : (
            <div className="flex items-center gap-2">
              <button
                onClick={handleDestroy}
                disabled={destroyMutation.isPending}
                className="rounded-lg bg-rose-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-rose-700 active:scale-[0.98] disabled:opacity-50"
              >
                {destroyMutation.isPending ? "Destroying..." : "Confirm destroy"}
              </button>
              <button
                onClick={() => setConfirmDestroy(false)}
                className="text-sm text-zinc-500 hover:text-zinc-700"
              >
                Cancel
              </button>
            </div>
          )}
        </div>
      </div>

      {/* Health strip */}
      <div className="flex flex-wrap gap-6 border-t border-zinc-200 pt-4 text-sm">
        <div>
          <span className="text-zinc-500">Last Health Check</span>
          <p className="font-mono text-zinc-900">{formatTimeAgo(agent.last_health_check)}</p>
        </div>
        <div>
          <span className="text-zinc-500">Consecutive Failures</span>
          <p className="font-mono text-zinc-900">{agent.consecutive_failures ?? 0}</p>
        </div>
        <div>
          <span className="text-zinc-500">VM Driver</span>
          <p className="text-zinc-900">{agent.vm_driver || "unknown"}</p>
        </div>
        {agent.vsock_cid && (
          <div>
            <span className="text-zinc-500">vsock CID</span>
            <p className="font-mono text-zinc-900">{agent.vsock_cid}</p>
          </div>
        )}
        {agent.vm_id && (
          <div>
            <span className="text-zinc-500">VM ID</span>
            <p className="font-mono text-zinc-900">{truncateId(agent.vm_id)}</p>
          </div>
        )}
      </div>

      {/* Info */}
      <div className="flex flex-wrap gap-6 text-sm">
        {agent.user_id && (
          <div>
            <span className="text-zinc-500">Assigned User</span>
            <p>
              <Link href={`/users/${agent.user_id}`} className="font-mono text-zinc-900 hover:underline">
                {truncateId(agent.user_id)}
              </Link>
            </p>
          </div>
        )}
        {agent.department_id && (
          <div>
            <span className="text-zinc-500">Department</span>
            <p>
              <Link href={`/departments/${agent.department_id}`} className="font-mono text-zinc-900 hover:underline">
                {truncateId(agent.department_id)}
              </Link>
            </p>
          </div>
        )}
      </div>

      {/* Config editor or viewer */}
      {editing ? (
        <div className="rounded-xl border border-zinc-200 bg-white p-5">
          <AgentConfigEditor
            agentId={id}
            currentConfig={config}
            currentAllowlist={tools}
            onDone={() => setEditing(false)}
          />
        </div>
      ) : (
        <>
          <div>
            <h2 className="mb-3 text-sm font-medium text-zinc-900">Configuration</h2>
            <div className="rounded-xl border border-zinc-200 bg-white p-4">
              <pre className="text-xs font-mono text-zinc-600 overflow-auto">
                {JSON.stringify(config, null, 2)}
              </pre>
            </div>
          </div>

          <div>
            <h2 className="mb-3 text-sm font-medium text-zinc-900">Tool Allowlist</h2>
            <div className="rounded-xl border border-zinc-200 bg-white p-4">
              {tools.length === 0 ? (
                <p className="text-sm text-zinc-500">No tool restrictions.</p>
              ) : (
                <div className="flex flex-wrap gap-2">
                  {tools.map((tool) => (
                    <Badge key={tool} variant="outline" className="font-mono text-xs">
                      <Wrench size={12} className="mr-1" />
                      {tool}
                    </Badge>
                  ))}
                </div>
              )}
            </div>
          </div>
        </>
      )}

      {/* Debug Console — only shown to users with agents:write permission */}
      {canWrite && (
        <div>
          <h2 className="mb-3 text-sm font-medium text-zinc-900">Debug Console</h2>
          <AgentChat agentId={id} agentStatus={agent.status} />
        </div>
      )}
    </div>
  )
}
