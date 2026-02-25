import Link from "next/link"
import { AgentStatusDot } from "./agent-status-badge"
import { formatDate, formatTimeAgo, truncateId } from "@/lib/format"
import type { AgentInstance } from "@/lib/types"

export function AgentCard({ agent }: { agent: AgentInstance }) {
  return (
    <Link
      href={`/agents/${agent.id}`}
      className="rounded-xl border border-zinc-200 bg-white p-4 transition-colors hover:bg-zinc-50 active:scale-[0.99]"
    >
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <AgentStatusDot status={agent.status} />
          <span className="text-sm font-medium text-zinc-900">{agent.status}</span>
        </div>
        <span className="font-mono text-xs text-zinc-400" title={agent.id}>
          {truncateId(agent.id)}
        </span>
      </div>

      <div className="mt-3 space-y-1.5 text-xs text-zinc-500">
        {agent.user_id && (
          <div className="flex justify-between">
            <span>User</span>
            <span className="font-mono text-zinc-700">{truncateId(agent.user_id)}</span>
          </div>
        )}
        {agent.department_id && (
          <div className="flex justify-between">
            <span>Department</span>
            <span className="font-mono text-zinc-700">{truncateId(agent.department_id)}</span>
          </div>
        )}
        <div className="flex justify-between">
          <span>VM Driver</span>
          <span className="text-zinc-700">{agent.vm_driver || "unknown"}</span>
        </div>
        <div className="flex justify-between">
          <span>Last Health</span>
          <span className="font-mono text-zinc-700">{formatTimeAgo(agent.last_health_check)}</span>
        </div>
        <div className="flex justify-between">
          <span>Created</span>
          <span className="text-zinc-700">{formatDate(agent.created_at)}</span>
        </div>
      </div>
    </Link>
  )
}
