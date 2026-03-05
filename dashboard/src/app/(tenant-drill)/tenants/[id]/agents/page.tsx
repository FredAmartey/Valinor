import { AgentGrid } from "@/components/agents/agent-grid"

export default async function TenantAgentsPage({
  params,
}: {
  params: Promise<{ id: string }>
}) {
  const { id } = await params

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight text-zinc-900">Agents</h1>
        <p className="mt-1 text-sm text-zinc-500">Agents in this tenant.</p>
      </div>
      <AgentGrid tenantId={id} readOnly />
    </div>
  )
}
