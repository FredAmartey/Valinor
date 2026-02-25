"use client"

import { useSession } from "next-auth/react"
import { useQuery } from "@tanstack/react-query"
import { apiClient } from "@/lib/api-client"
import { Skeleton } from "@/components/ui/skeleton"
import { formatTimeAgo } from "@/lib/format"
import type { AuditEvent } from "@/lib/types"

export function RecentEvents() {
  const { data: session } = useSession()
  const { data: events, isLoading, isError } = useQuery({
    queryKey: ["audit", "recent"],
    queryFn: () =>
      apiClient<{ count: number; events: AuditEvent[] }>("/api/v1/audit/events", session!.accessToken, {
        params: { limit: "10" },
      }),
    select: (data) => data.events,
    enabled: !!session?.accessToken,
    refetchInterval: 30_000,
  })

  if (isLoading) {
    return (
      <div className="space-y-3">
        {Array.from({ length: 5 }).map((_, i) => (
          <Skeleton key={i} className="h-10 w-full" />
        ))}
      </div>
    )
  }

  if (isError) {
    return (
      <p className="text-sm text-zinc-500">Failed to load recent events.</p>
    )
  }

  if (!events || events.length === 0) {
    return (
      <div className="py-8 text-center">
        <p className="text-sm text-zinc-500">No audit events recorded yet.</p>
        <p className="mt-1 text-xs text-zinc-400">
          Events appear here as users interact with the platform.
        </p>
      </div>
    )
  }

  return (
    <div className="divide-y divide-zinc-100">
      {events.map((event) => (
        <div key={event.id} className="flex items-center justify-between py-2.5">
          <div className="flex items-center gap-3">
            <span className="text-sm font-medium text-zinc-900">{event.action}</span>
            {event.resource_type && (
              <span className="text-xs text-zinc-400">{event.resource_type}</span>
            )}
          </div>
          <span className="text-xs text-zinc-400 font-mono">
            {formatTimeAgo(event.created_at)}
          </span>
        </div>
      ))}
    </div>
  )
}
