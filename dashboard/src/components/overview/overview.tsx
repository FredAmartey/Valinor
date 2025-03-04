"use client"

import { useQuery } from "@tanstack/react-query"
import { apiClient } from "@/lib/api-client"
import { useCan } from "@/components/providers/permission-provider"
import { tenantKeys } from "@/lib/queries/tenants"
import { agentKeys, fetchAgents } from "@/lib/queries/agents"
import { StatCard } from "./stat-card"
import { RecentEvents } from "./recent-events"
import { Skeleton } from "@/components/ui/skeleton"
import { Buildings, Robot, Warning, Users, ChatCircle, Heartbeat } from "@phosphor-icons/react"
import type { Tenant, AgentInstance } from "@/lib/types"

interface OverviewProps {
  userName: string
  isPlatformAdmin: boolean
  hasTenant: boolean
  initialTenants: Tenant[]
  initialAgents: AgentInstance[]
}

function getSubtitle(isPlatformAdmin: boolean, canReadUsers: boolean): string {
  if (isPlatformAdmin) return "Platform health and activity across all tenants."
  if (canReadUsers) return "Here\u2019s what\u2019s happening in your organization."
  return "Here\u2019s what\u2019s happening with your agents."
}

export function Overview({
  userName,
  isPlatformAdmin,
  hasTenant,
  initialTenants,
  initialAgents,
}: OverviewProps) {
  const canReadUsers = useCan("users:read")
  const canReadAudit = useCan("audit:read")
  const canReadConnectors = useCan("connectors:read")

  const { data: tenants, isLoading: tenantsLoading } = useQuery({
    queryKey: tenantKeys.list(),
    queryFn: () => apiClient<Tenant[]>("/api/v1/tenants"),
    initialData: initialTenants,
    refetchInterval: 30_000,
    enabled: isPlatformAdmin,
  })

  const { data: agentData, isLoading: agentsLoading } = useQuery({
    queryKey: agentKeys.list(),
    queryFn: () => fetchAgents(),
    initialData: { agents: initialAgents },
    refetchInterval: 30_000,
  })

  const agents = agentData?.agents ?? []
  const firstName = userName.split(" ")[0] || userName

  const statCards = buildStatCards({
    isPlatformAdmin,
    canReadUsers,
    canReadConnectors,
    tenants: tenants ?? [],
    agents,
  })

  const isLoading = (isPlatformAdmin && tenantsLoading) || agentsLoading

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight text-zinc-900">
          Welcome back, {firstName}
        </h1>
        <p className="mt-1 text-sm text-zinc-500">
          {getSubtitle(isPlatformAdmin, canReadUsers)}
        </p>
      </div>

      {isLoading ? (
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
          {Array.from({ length: statCards.length || 2 }).map((_, i) => (
            <Skeleton key={i} className="h-28 rounded-xl" />
          ))}
        </div>
      ) : (
        <div className={`grid grid-cols-1 gap-4 md:grid-cols-2 ${statCards.length > 2 ? "xl:grid-cols-4" : ""}`}>
          {statCards.map((card) => (
            <StatCard key={card.label} {...card} />
          ))}
        </div>
      )}

      <div className={isPlatformAdmin ? "grid grid-cols-1 gap-6 xl:grid-cols-[2fr_1fr]" : ""}>
        <div>
          <h2 className="mb-3 text-sm font-medium text-zinc-900">Recent Activity</h2>
          <div className="rounded-xl border border-zinc-200 bg-white p-4">
            {/* Platform admin has hasTenant=false — activity feed shows empty state; Quick Stats is their primary panel */}
            <RecentEvents canReadAudit={canReadAudit} hasTenant={hasTenant} />
          </div>
        </div>
        {isPlatformAdmin && (
          <div>
            <h2 className="mb-3 text-sm font-medium text-zinc-900">Quick Stats</h2>
            <div className="rounded-xl border border-zinc-200 bg-white p-4">
              <div className="space-y-3 text-sm">
                <div className="flex justify-between">
                  <span className="text-zinc-500">Suspended Tenants</span>
                  <span className="font-mono text-zinc-900">
                    {tenants?.filter((t) => t.status === "suspended").length ?? 0}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-zinc-500">Archived Tenants</span>
                  <span className="font-mono text-zinc-900">
                    {tenants?.filter((t) => t.status === "archived").length ?? 0}
                  </span>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

function buildStatCards({
  isPlatformAdmin,
  canReadUsers,
  canReadConnectors,
  tenants,
  agents,
}: {
  isPlatformAdmin: boolean
  canReadUsers: boolean
  canReadConnectors: boolean
  tenants: Tenant[]
  agents: AgentInstance[]
}) {
  const totalAgents = agents.length
  const healthyAgents = agents.filter((a) => a.status === "running" || a.status === "warm").length
  const unhealthyAgents = agents.filter((a) => a.status === "unhealthy").length

  if (isPlatformAdmin) {
    const activeTenants = tenants.filter((t) => t.status === "active").length
    return [
      { label: "Total Tenants", value: tenants.length, icon: <Buildings size={20} /> },
      { label: "Active Tenants", value: activeTenants, icon: <Buildings size={20} /> },
      { label: "Running Agents", value: totalAgents, icon: <Robot size={20} /> },
      { label: "Unhealthy Agents", value: unhealthyAgents, icon: <Warning size={20} /> },
    ]
  }

  if (canReadUsers) {
    return [
      { label: "Running Agents", value: totalAgents, icon: <Robot size={20} /> },
      { label: "Unhealthy Agents", value: unhealthyAgents, icon: <Warning size={20} /> },
      { label: "Total Users", value: "\u2014" as string | number, icon: <Users size={20} /> },
      ...(canReadConnectors ? [{ label: "Active Channels", value: "\u2014" as string | number, icon: <ChatCircle size={20} /> }] : []),
    ]
  }

  return [
    { label: "Running Agents", value: totalAgents, icon: <Robot size={20} /> },
    { label: "Agents Online", value: healthyAgents, icon: <Heartbeat size={20} /> },
  ]
}
