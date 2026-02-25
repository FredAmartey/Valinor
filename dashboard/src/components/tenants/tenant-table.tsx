"use client"

import { useState } from "react"
import Link from "next/link"
import { useTenantsQuery } from "@/lib/queries/tenants"
import { formatDate } from "@/lib/format"
import { TenantStatusBadge } from "./tenant-status-badge"
import { Input } from "@/components/ui/input"
import { Skeleton } from "@/components/ui/skeleton"
import { MagnifyingGlass } from "@phosphor-icons/react"

export function TenantTable() {
  const { data: tenants, isLoading, isError } = useTenantsQuery()
  const [search, setSearch] = useState("")

  const filtered = tenants?.filter(
    (t) =>
      t.name.toLowerCase().includes(search.toLowerCase()) ||
      t.slug.toLowerCase().includes(search.toLowerCase()),
  )

  if (isLoading) {
    return (
      <div className="space-y-3">
        <Skeleton className="h-10 w-64" />
        {Array.from({ length: 5 }).map((_, i) => (
          <Skeleton key={i} className="h-14 w-full" />
        ))}
      </div>
    )
  }

  if (isError) {
    return (
      <div className="rounded-xl border border-rose-200 bg-rose-50 p-4">
        <p className="text-sm text-rose-700">Failed to load tenants. Please try again.</p>
      </div>
    )
  }

  if (!tenants || tenants.length === 0) {
    return (
      <div className="py-12 text-center">
        <p className="text-sm font-medium text-zinc-900">No tenants yet</p>
        <p className="mt-1 text-sm text-zinc-500">
          Create your first tenant to get started.
        </p>
        <Link
          href="/tenants/new"
          className="mt-4 inline-block rounded-lg bg-zinc-900 px-4 py-2 text-sm font-medium text-white hover:bg-zinc-800 transition-colors active:scale-[0.98]"
        >
          Create tenant
        </Link>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      <div className="relative max-w-sm">
        <MagnifyingGlass
          size={16}
          className="absolute left-3 top-1/2 -translate-y-1/2 text-zinc-400"
        />
        <Input
          placeholder="Search tenants..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="pl-9"
        />
      </div>

      <div className="rounded-xl border border-zinc-200 bg-white">
        <div className="grid grid-cols-[2fr_1fr_1fr_1fr] gap-4 border-b border-zinc-100 px-4 py-3 text-xs font-medium uppercase tracking-wider text-zinc-500">
          <span>Name</span>
          <span>Slug</span>
          <span>Status</span>
          <span>Created</span>
        </div>
        <div className="divide-y divide-zinc-100">
          {filtered?.map((tenant) => (
            <Link
              key={tenant.id}
              href={`/tenants/${tenant.id}`}
              className="grid grid-cols-[2fr_1fr_1fr_1fr] gap-4 px-4 py-3 text-sm transition-colors hover:bg-zinc-50"
            >
              <span className="font-medium text-zinc-900">{tenant.name}</span>
              <span className="font-mono text-zinc-500">{tenant.slug}</span>
              <TenantStatusBadge status={tenant.status} />
              <span className="text-zinc-500">{formatDate(tenant.created_at)}</span>
            </Link>
          ))}
        </div>
      </div>
    </div>
  )
}
