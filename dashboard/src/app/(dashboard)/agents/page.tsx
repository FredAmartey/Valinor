import Link from "next/link"
import { auth } from "@/lib/auth"
import { hasPermission } from "@/lib/permissions"
import { AgentGrid } from "@/components/agents/agent-grid"
import { Plus } from "@phosphor-icons/react/dist/ssr"

export default async function AgentsPage() {
  const session = await auth()
  const canProvision = hasPermission(
    session?.user?.isPlatformAdmin ?? false,
    session?.user?.roles ?? [],
    "agents:write",
  )

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-zinc-900">Agents</h1>
          <p className="mt-1 text-sm text-zinc-500">Manage AI agent instances.</p>
        </div>
        {canProvision && (
          <Link
            href="/agents/new"
            className="flex items-center gap-2 rounded-lg bg-zinc-900 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-zinc-800 active:scale-[0.98]"
          >
            <Plus size={16} />
            Provision agent
          </Link>
        )}
      </div>
      <AgentGrid />
    </div>
  )
}
