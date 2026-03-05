"use client"

import { useState } from "react"
import Link from "next/link"
import { useTenantQuery } from "@/lib/queries/tenants"
import { formatDate } from "@/lib/format"
import { TenantStatusBadge } from "./tenant-status-badge"
import { Skeleton } from "@/components/ui/skeleton"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog"
import { Users, TreeStructure, Robot, Plugs, Warning } from "@phosphor-icons/react"
import { signIn } from "next-auth/react"
import { apiClient } from "@/lib/api-client"

export function TenantDetail({ id }: { id: string }) {
  const { data: tenant, isLoading, isError } = useTenantQuery(id)
  const [showImpersonateDialog, setShowImpersonateDialog] = useState(false)
  const [isImpersonating, setIsImpersonating] = useState(false)

  const handleImpersonate = async () => {
    setIsImpersonating(true)
    try {
      const data = await apiClient<{ token: string; expires_in: number; tenant_name: string }>(
        `/api/v1/tenants/${id}/impersonate`,
        { method: "POST" },
      )

      await signIn("impersonate", {
        token: data.token,
        tenantName: data.tenant_name,
        redirect: false,
      })

      // Reload to pick up the new impersonation session
      window.location.href = "/"
    } catch (err) {
      console.error("Impersonation failed:", err)
      setIsImpersonating(false)
    }
  }

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
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-semibold tracking-tight text-zinc-900">
              {tenant.name}
            </h1>
            <TenantStatusBadge status={tenant.status} />
          </div>
          <Dialog open={showImpersonateDialog} onOpenChange={setShowImpersonateDialog}>
            <DialogTrigger asChild>
              <button
                className="flex items-center gap-2 rounded-lg border border-red-200 bg-red-50 px-4 py-2 text-sm font-medium text-red-700 transition-colors hover:bg-red-100 active:scale-[0.98]"
              >
                <Warning size={16} />
                Enter Tenant
              </button>
            </DialogTrigger>
            <DialogContent className="sm:max-w-md">
              <DialogHeader>
                <DialogTitle>Emergency Access</DialogTitle>
                <DialogDescription>
                  You are about to enter <strong>{tenant.name}</strong> with full admin
                  privileges. All actions will be logged in the audit trail.
                </DialogDescription>
              </DialogHeader>
              <DialogFooter>
                <button
                  onClick={() => setShowImpersonateDialog(false)}
                  className="rounded-lg px-4 py-2 text-sm text-zinc-600 hover:bg-zinc-100 transition-colors"
                >
                  Cancel
                </button>
                <button
                  onClick={handleImpersonate}
                  disabled={isImpersonating}
                  className="rounded-lg bg-red-600 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-red-700 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {isImpersonating ? "Entering..." : "Enter Tenant"}
                </button>
              </DialogFooter>
            </DialogContent>
          </Dialog>
        </div>
        <div className="mt-2 flex items-center gap-4 text-sm text-zinc-500">
          <span className="font-mono">{tenant.slug}</span>
          <span>Created {formatDate(tenant.created_at, "long")}</span>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
        <Link
          href={`/tenants/${id}/users`}
          className="flex items-center gap-3 rounded-xl border border-zinc-200 bg-white p-4 transition-colors hover:border-zinc-300 hover:bg-zinc-50"
        >
          <Users size={20} className="text-zinc-400" />
          <div>
            <p className="text-xs text-zinc-500">Users</p>
            <p className="text-lg font-semibold text-zinc-900">{tenant.stats?.users ?? "--"}</p>
          </div>
        </Link>
        <Link
          href={`/tenants/${id}/departments`}
          className="flex items-center gap-3 rounded-xl border border-zinc-200 bg-white p-4 transition-colors hover:border-zinc-300 hover:bg-zinc-50"
        >
          <TreeStructure size={20} className="text-zinc-400" />
          <div>
            <p className="text-xs text-zinc-500">Departments</p>
            <p className="text-lg font-semibold text-zinc-900">{tenant.stats?.departments ?? "--"}</p>
          </div>
        </Link>
        <Link
          href={`/tenants/${id}/agents`}
          className="flex items-center gap-3 rounded-xl border border-zinc-200 bg-white p-4 transition-colors hover:border-zinc-300 hover:bg-zinc-50"
        >
          <Robot size={20} className="text-zinc-400" />
          <div>
            <p className="text-xs text-zinc-500">Agents</p>
            <p className="text-lg font-semibold text-zinc-900">{tenant.stats?.agents ?? "--"}</p>
          </div>
        </Link>
        <Link
          href={`/tenants/${id}/connectors`}
          className="flex items-center gap-3 rounded-xl border border-zinc-200 bg-white p-4 transition-colors hover:border-zinc-300 hover:bg-zinc-50"
        >
          <Plugs size={20} className="text-zinc-400" />
          <div>
            <p className="text-xs text-zinc-500">Connectors</p>
            <p className="text-lg font-semibold text-zinc-900">{tenant.stats?.connectors ?? "--"}</p>
          </div>
        </Link>
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
