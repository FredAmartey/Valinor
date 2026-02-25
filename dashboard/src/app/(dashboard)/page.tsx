import { api } from "@/lib/api"
import { PlatformOverview } from "@/components/overview/platform-overview"
import type { Tenant, AgentInstance } from "@/lib/types"

export default async function OverviewPage() {
  const [tenants, agents] = await Promise.all([
    api<Tenant[]>("/api/v1/tenants").catch(() => [] as Tenant[]),
    api<AgentInstance[]>("/api/v1/agents").catch(() => [] as AgentInstance[]),
  ])

  return <PlatformOverview initialTenants={tenants} initialAgents={agents} />
}
