"use client"

import { useState } from "react"
import { useOutboxQuery, useRequeueOutboxMutation } from "@/lib/queries/channels"
import { formatTimeAgo, truncateId } from "@/lib/format"
import { Skeleton } from "@/components/ui/skeleton"
import { ArrowCounterClockwise } from "@phosphor-icons/react"
import { PlatformIcon } from "./platform-icon"
import type { ChannelOutbox } from "@/lib/types"

const STATUS_TABS = ["all", "pending", "sending", "sent", "dead"] as const
const PROVIDER_OPTIONS = ["all", "slack", "whatsapp", "telegram"] as const

const STATUS_PILL: Record<string, string> = {
  pending: "bg-amber-50 text-amber-700",
  sending: "bg-blue-50 text-blue-700",
  sent: "bg-emerald-50 text-emerald-700",
  dead: "bg-rose-50 text-rose-700",
}

export function OutboxTab({ canWrite }: { canWrite: boolean }) {
  const [statusTab, setStatusTab] = useState<string>("all")
  const [providerFilter, setProviderFilter] = useState("all")
  const { data: jobs, isLoading, isError, refetch } = useOutboxQuery(statusTab)
  const requeueMutation = useRequeueOutboxMutation()

  const filtered = (jobs ?? []).filter((job) => {
    if (providerFilter !== "all" && job.provider !== providerFilter) return false
    return true
  })

  const handleRequeue = (job: ChannelOutbox) => {
    requeueMutation.mutate(job.id)
  }

  if (isLoading) {
    return (
      <div className="space-y-4">
        <div className="flex gap-1">
          {STATUS_TABS.map((s) => (
            <Skeleton key={s} className="h-9 w-20 rounded-lg" />
          ))}
        </div>
        <div className="divide-y divide-zinc-100 rounded-xl border border-zinc-200">
          {Array.from({ length: 5 }).map((_, i) => (
            <div key={i} className="flex items-center gap-4 px-4 py-3">
              <Skeleton className="h-4 w-16" />
              <Skeleton className="h-4 w-24" />
              <Skeleton className="h-4 w-16" />
              <Skeleton className="h-4 w-12" />
              <Skeleton className="h-4 w-20" />
            </div>
          ))}
        </div>
      </div>
    )
  }

  if (isError) {
    return (
      <div className="flex items-center justify-between rounded-xl border border-rose-200 bg-rose-50 p-4">
        <p className="text-sm text-rose-700">Failed to load outbox.</p>
        <button
          onClick={() => refetch()}
          className="flex items-center gap-1.5 rounded-lg bg-rose-100 px-3 py-1.5 text-sm font-medium text-rose-700 hover:bg-rose-200 transition-colors"
        >
          <ArrowCounterClockwise size={14} />
          Retry
        </button>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      {/* Status tabs + provider filter */}
      <div className="flex flex-wrap items-center gap-3">
        <div role="tablist" aria-label="Outbox status" className="flex gap-1 rounded-lg border border-zinc-200 p-1">
          {STATUS_TABS.map((s) => (
            <button
              key={s}
              role="tab"
              aria-selected={statusTab === s}
              onClick={() => setStatusTab(s)}
              className={`rounded-md px-3 py-1.5 text-sm font-medium transition-colors ${
                statusTab === s
                  ? "bg-zinc-900 text-white"
                  : "text-zinc-500 hover:text-zinc-700"
              }`}
            >
              {s.charAt(0).toUpperCase() + s.slice(1)}
            </button>
          ))}
        </div>
        <select
          aria-label="Filter by provider"
          className="rounded-lg border border-zinc-200 bg-white px-3 py-2 text-sm text-zinc-900"
          value={providerFilter}
          onChange={(e) => setProviderFilter(e.target.value)}
        >
          {PROVIDER_OPTIONS.map((p) => (
            <option key={p} value={p}>
              {p === "all" ? "All providers" : p.charAt(0).toUpperCase() + p.slice(1)}
            </option>
          ))}
        </select>
      </div>

      {/* Table */}
      {filtered.length === 0 ? (
        <div className="py-12 text-center">
          <p className="text-sm font-medium text-zinc-900">No outbox jobs</p>
          <p className="mt-1 text-sm text-zinc-500">
            {statusTab !== "all"
              ? `No ${statusTab} jobs. Try a different status filter.`
              : "Messages will appear here when they are queued for delivery."}
          </p>
        </div>
      ) : (
        <div role="table" aria-label="Outbox jobs" className="divide-y divide-zinc-100 rounded-xl border border-zinc-200 bg-white">
          <div role="row" className="grid grid-cols-[80px_1fr_90px_70px_100px_1fr_60px] gap-4 px-4 py-2 text-xs font-medium uppercase tracking-wider text-zinc-400">
            <span role="columnheader">Provider</span>
            <span role="columnheader">Recipient</span>
            <span role="columnheader">Status</span>
            <span role="columnheader">Attempts</span>
            <span role="columnheader">Next Attempt</span>
            <span role="columnheader">Last Error</span>
            <span role="columnheader" className="text-right">Actions</span>
          </div>
          {filtered.map((job) => (
            <div
              key={job.id}
              role="row"
              className="grid grid-cols-[80px_1fr_90px_70px_100px_1fr_60px] gap-4 px-4 py-3 text-sm hover:bg-zinc-50 transition-colors"
            >
              <span role="cell" className="flex items-center gap-1.5 self-center">
                <PlatformIcon platform={job.provider} size={14} />
                <span className="capitalize text-zinc-700">{job.provider}</span>
              </span>
              <span role="cell" className="self-center truncate font-mono text-xs text-zinc-600" title={job.recipient_id}>
                {truncateId(job.recipient_id, 16)}
              </span>
              <span role="cell" className="self-center">
                <span className={`inline-block rounded-full px-2 py-0.5 text-xs font-medium ${STATUS_PILL[job.status] ?? "bg-zinc-100 text-zinc-500"}`}>
                  {job.status}
                </span>
              </span>
              <span role="cell" className="self-center font-mono text-xs text-zinc-500" aria-label={`${job.attempt_count} of ${job.max_attempts} attempts`}>
                {job.attempt_count}/{job.max_attempts}
              </span>
              <span role="cell" className="self-center text-xs text-zinc-500">
                {job.status === "pending" || job.status === "sending"
                  ? formatTimeAgo(job.next_attempt_at)
                  : "\u2014"}
              </span>
              <span
                role="cell"
                className="self-center truncate text-xs text-zinc-500"
                title={job.last_error ?? undefined}
              >
                {job.last_error ?? "\u2014"}
              </span>
              <span role="cell" className="flex justify-end self-center">
                {canWrite && job.status === "dead" && (
                  <button
                    onClick={() => handleRequeue(job)}
                    disabled={requeueMutation.isPending}
                    className="flex items-center gap-1 rounded p-1 text-zinc-400 hover:text-zinc-700 transition-colors disabled:opacity-50"
                    title="Requeue job"
                  >
                    <ArrowCounterClockwise size={16} />
                  </button>
                )}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
