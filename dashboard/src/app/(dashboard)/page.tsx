import { api } from "@/lib/api"
import { auth } from "@/lib/auth"
import { PlatformOverview } from "@/components/overview/platform-overview"
import type { Tenant, AgentInstance } from "@/lib/types"

export default async function OverviewPage() {
  const session = await auth()
  const isPlatformAdmin = session?.user?.isPlatformAdmin ?? false

  const [tenants, agents] = await Promise.all([
    isPlatformAdmin
      ? api<Tenant[]>("/api/v1/tenants").catch(() => [] as Tenant[])
      : ([] as Tenant[]),
    api<{ agents: AgentInstance[] }>("/api/v1/agents")
      .then((r) => r.agents)
      .catch((err) => {
        console.error("Failed to fetch agents for overview SSR:", err)
        return [] as AgentInstance[]
      }),
  ])

  return <PlatformOverview initialTenants={tenants} initialAgents={agents} />
}
