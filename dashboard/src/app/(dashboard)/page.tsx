import { api } from "@/lib/api"
import { PlatformOverview } from "@/components/overview/platform-overview"
import type { Tenant, AgentInstance } from "@/lib/types"

export default async function OverviewPage() {
  const [tenants, agents] = await Promise.all([
    api<Tenant[]>("/api/v1/tenants").catch((err) => {
      console.error("Failed to fetch tenants for overview SSR:", err)
      return [] as Tenant[]
    }),
    api<AgentInstance[]>("/api/v1/agents").catch((err) => {
      console.error("Failed to fetch agents for overview SSR:", err)
      return [] as AgentInstance[]
    }),
  ])

  return <PlatformOverview initialTenants={tenants} initialAgents={agents} />
}
