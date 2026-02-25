"use client"

import { useState, useDeferredValue } from "react"
import Link from "next/link"
import { useAgentsQuery } from "@/lib/queries/agents"
import { AgentCard } from "./agent-card"
import { Input } from "@/components/ui/input"
import { Skeleton } from "@/components/ui/skeleton"
import { MagnifyingGlass } from "@phosphor-icons/react"

const STATUS_OPTIONS = ["all", "running", "provisioning", "unhealthy", "warm"] as const

export function AgentGrid() {
  const [statusFilter, setStatusFilter] = useState<string>("all")
  const [search, setSearch] = useState("")
  const deferredSearch = useDeferredValue(search)
  const { data, isLoading, isError } = useAgentsQuery(statusFilter)

  const agents = data?.agents ?? []
  const filtered = deferredSearch
    ? agents.filter(
        (a) =>
          a.id.toLowerCase().includes(deferredSearch.toLowerCase()) ||
          (a.user_id ?? "").toLowerCase().includes(deferredSearch.toLowerCase()),
      )
    : agents

  if (isLoading) {
    return (
      <div className="space-y-4">
        <div className="flex gap-3">
          <Skeleton className="h-10 w-64" />
          <Skeleton className="h-10 w-40" />
        </div>
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
          {Array.from({ length: 6 }).map((_, i) => (
            <Skeleton key={i} className="h-48 rounded-xl" />
          ))}
        </div>
      </div>
    )
  }

  if (isError) {
    return (
      <div className="rounded-xl border border-rose-200 bg-rose-50 p-4">
        <p className="text-sm text-rose-700">Failed to load agents.</p>
      </div>
    )
  }

  if (agents.length === 0 && statusFilter === "all") {
    return (
      <div className="py-12 text-center">
        <p className="text-sm font-medium text-zinc-900">No agents running</p>
        <p className="mt-1 text-sm text-zinc-500">Provision your first agent to get started.</p>
        <Link
          href="/agents/new"
          className="mt-4 inline-block rounded-lg bg-zinc-900 px-4 py-2 text-sm font-medium text-white hover:bg-zinc-800 transition-colors active:scale-[0.98]"
        >
          Provision agent
        </Link>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <div className="relative max-w-sm flex-1">
          <MagnifyingGlass size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-zinc-400" />
          <Input
            placeholder="Search by ID or user..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-9"
          />
        </div>
        <select
          className="rounded-lg border border-zinc-200 bg-white px-3 py-2 text-sm text-zinc-900"
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
        >
          {STATUS_OPTIONS.map((s) => (
            <option key={s} value={s}>
              {s === "all" ? "All statuses" : s}
            </option>
          ))}
        </select>
      </div>

      {filtered.length === 0 ? (
        <p className="py-8 text-center text-sm text-zinc-500">
          No agents match your filters.
        </p>
      ) : (
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
          {filtered.map((agent) => (
            <AgentCard key={agent.id} agent={agent} />
          ))}
        </div>
      )}
    </div>
  )
}
