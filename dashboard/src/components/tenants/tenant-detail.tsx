"use client"

import { useTenantQuery } from "@/lib/queries/tenants"
import { formatDate } from "@/lib/format"
import { TenantStatusBadge } from "./tenant-status-badge"
import { Skeleton } from "@/components/ui/skeleton"
import { Users, TreeStructure, Robot, Plugs } from "@phosphor-icons/react"

export function TenantDetail({ id }: { id: string }) {
  const { data: tenant, isLoading, isError } = useTenantQuery(id)

  if (isLoading) {
    return (
      <div className="space-y-6">
        <Skeleton className="h-12 w-72" />
        <div className="grid grid-cols-1 gap-4 md:grid-cols-4">
          {Array.from({ length: 4 }).map((_, i) => (
            <Skeleton key={i} className="h-20 rounded-xl" />
          ))}
        </div>
      </div>
    )
  }

  if (isError || !tenant) {
    return (
      <div className="rounded-xl border border-rose-200 bg-rose-50 p-4">
        <p className="text-sm text-rose-700">
          Failed to load tenant details. The tenant may not exist.
        </p>
      </div>
    )
  }

  return (
    <div className="space-y-8">
      <div>
        <div className="flex items-center gap-3">
          <h1 className="text-2xl font-semibold tracking-tight text-zinc-900">
            {tenant.name}
          </h1>
          <TenantStatusBadge status={tenant.status} />
        </div>
        <div className="mt-2 flex items-center gap-4 text-sm text-zinc-500">
          <span className="font-mono">{tenant.slug}</span>
          <span>Created {formatDate(tenant.created_at, "long")}</span>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
        <div className="flex items-center gap-3 rounded-xl border border-zinc-200 bg-white p-4">
          <Users size={20} className="text-zinc-400" />
          <div>
            <p className="text-xs text-zinc-500">Users</p>
            <p className="text-lg font-semibold text-zinc-900">--</p>
          </div>
        </div>
        <div className="flex items-center gap-3 rounded-xl border border-zinc-200 bg-white p-4">
          <TreeStructure size={20} className="text-zinc-400" />
          <div>
            <p className="text-xs text-zinc-500">Departments</p>
            <p className="text-lg font-semibold text-zinc-900">--</p>
          </div>
        </div>
        <div className="flex items-center gap-3 rounded-xl border border-zinc-200 bg-white p-4">
          <Robot size={20} className="text-zinc-400" />
          <div>
            <p className="text-xs text-zinc-500">Agents</p>
            <p className="text-lg font-semibold text-zinc-900">--</p>
          </div>
        </div>
        <div className="flex items-center gap-3 rounded-xl border border-zinc-200 bg-white p-4">
          <Plugs size={20} className="text-zinc-400" />
          <div>
            <p className="text-xs text-zinc-500">Connectors</p>
            <p className="text-lg font-semibold text-zinc-900">--</p>
          </div>
        </div>
      </div>

      <div>
        <h2 className="mb-3 text-sm font-medium text-zinc-900">Settings</h2>
        <div className="rounded-xl border border-zinc-200 bg-white p-4">
          <pre className="text-xs font-mono text-zinc-600 overflow-auto">
            {JSON.stringify(tenant.settings, null, 2)}
          </pre>
        </div>
      </div>
    </div>
  )
}
