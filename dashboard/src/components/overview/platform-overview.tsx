"use client"

import { useSession } from "next-auth/react"
import { useQuery } from "@tanstack/react-query"
import { apiClient } from "@/lib/api-client"
import { StatCard } from "./stat-card"
import { RecentEvents } from "./recent-events"
import { Skeleton } from "@/components/ui/skeleton"
import { Buildings, Robot, Users, Warning } from "@phosphor-icons/react"
import type { Tenant, AgentInstance } from "@/lib/types"

export function PlatformOverview() {
  const { data: session } = useSession()

  const { data: tenants, isLoading: tenantsLoading } = useQuery({
    queryKey: ["tenants", "list"],
    queryFn: () => apiClient<Tenant[]>("/api/v1/tenants", session!.accessToken),
    enabled: !!session?.accessToken,
  })

  const { data: agents, isLoading: agentsLoading } = useQuery({
    queryKey: ["agents", "list"],
    queryFn: () => apiClient<AgentInstance[]>("/api/v1/agents", session!.accessToken),
    enabled: !!session?.accessToken,
  })

  const isLoading = tenantsLoading || agentsLoading

  const activeTenants = tenants?.filter((t) => t.status === "active").length ?? 0
  const totalAgents = agents?.length ?? 0
  const unhealthyAgents = agents?.filter((a) => a.status === "unhealthy").length ?? 0

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight text-zinc-900">
          Platform Overview
        </h1>
        <p className="mt-1 text-sm text-zinc-500">
          System health and recent activity across all tenants.
        </p>
      </div>

      {isLoading ? (
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
          {Array.from({ length: 4 }).map((_, i) => (
            <Skeleton key={i} className="h-28 rounded-xl" />
          ))}
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
          <StatCard
            label="Total Tenants"
            value={tenants?.length ?? 0}
            icon={<Buildings size={20} />}
          />
          <StatCard
            label="Active Tenants"
            value={activeTenants}
            icon={<Buildings size={20} />}
          />
          <StatCard
            label="Running Agents"
            value={totalAgents}
            icon={<Robot size={20} />}
          />
          <StatCard
            label="Unhealthy Agents"
            value={unhealthyAgents}
            icon={<Warning size={20} />}
          />
        </div>
      )}

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-[2fr_1fr]">
        <div>
          <h2 className="mb-3 text-sm font-medium text-zinc-900">Recent Activity</h2>
          <div className="rounded-xl border border-zinc-200 bg-white p-4">
            <RecentEvents />
          </div>
        </div>
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
      </div>
    </div>
  )
}
