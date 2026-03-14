"use client";

import { useAgentActivityQuery } from "@/lib/queries/activity";
import { formatDate, formatTimeAgo } from "@/lib/format";
import { Skeleton } from "@/components/ui/skeleton";
import {
  ShieldCheck,
  WarningCircle,
  Wrench,
  ChatCircleText,
  ClockCounterClockwise,
} from "@phosphor-icons/react";
import type { ActivityEvent } from "@/lib/types";

function eventIcon(event: ActivityEvent) {
  if (event.kind.startsWith("security."))
    return <ShieldCheck size={16} className="text-emerald-700" />;
  if (event.kind.startsWith("tool."))
    return <Wrench size={16} className="text-amber-700" />;
  if (event.kind.startsWith("channel."))
    return <ChatCircleText size={16} className="text-sky-700" />;
  return <ClockCounterClockwise size={16} className="text-zinc-500" />;
}

function statusClasses(status: string) {
  switch (status) {
    case "blocked":
    case "failed":
    case "halted":
      return "border-rose-200 bg-rose-50 text-rose-700";
    case "approval_required":
    case "flagged":
      return "border-amber-200 bg-amber-50 text-amber-700";
    default:
      return "border-emerald-200 bg-emerald-50 text-emerald-700";
  }
}

export function AgentActivityTimeline({ agentId }: { agentId: string }) {
  const { data, isLoading, isError, refetch, isFetching } =
    useAgentActivityQuery(agentId, { limit: "25" });
  const events = data?.events ?? [];

  if (isLoading) {
    return (
      <div className="space-y-3">
        {Array.from({ length: 4 }).map((_, idx) => (
          <div
            key={idx}
            className="rounded-xl border border-zinc-200 bg-white p-4"
          >
            <Skeleton className="h-4 w-48" />
            <Skeleton className="mt-3 h-3 w-full" />
            <Skeleton className="mt-2 h-3 w-64" />
          </div>
        ))}
      </div>
    );
  }

  if (isError) {
    return (
      <div className="rounded-xl border border-rose-200 bg-rose-50 p-4">
        <div className="flex items-center justify-between gap-4">
          <div>
            <p className="text-sm font-medium text-rose-700">
              Failed to load agent timeline.
            </p>
            <p className="mt-1 text-sm text-rose-600">
              The trust activity stream is unavailable right now.
            </p>
          </div>
          <button
            onClick={() => refetch()}
            className="rounded-lg border border-rose-200 bg-white px-3 py-1.5 text-sm font-medium text-rose-700 hover:bg-rose-100"
          >
            Retry
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-sm font-medium text-zinc-900">
            Activity timeline
          </h2>
          <p className="mt-1 text-sm text-zinc-500">
            See what this agent did, what was blocked, and what happened next.
          </p>
        </div>
        {isFetching && <p className="text-xs text-zinc-400">Refreshing…</p>}
      </div>

      {events.length === 0 ? (
        <div className="rounded-xl border border-dashed border-zinc-300 bg-zinc-50 px-4 py-8 text-center">
          <p className="text-sm font-medium text-zinc-900">No activity yet</p>
          <p className="mt-1 text-sm text-zinc-500">
            Prompts, tool calls, security events, and deliveries will appear
            here.
          </p>
        </div>
      ) : (
        <div className="space-y-3">
          {events.map((event) => (
            <div
              key={event.id}
              className="rounded-xl border border-zinc-200 bg-white p-4 shadow-sm"
            >
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div className="flex items-start gap-3">
                  <div className="mt-0.5 flex h-8 w-8 items-center justify-center rounded-full bg-zinc-100">
                    {event.status === "blocked" || event.status === "failed" ? (
                      <WarningCircle size={16} className="text-rose-700" />
                    ) : (
                      eventIcon(event)
                    )}
                  </div>
                  <div>
                    <p className="text-sm font-semibold text-zinc-900">
                      {event.title}
                    </p>
                    <p className="mt-1 text-sm text-zinc-600">
                      {event.summary}
                    </p>
                  </div>
                </div>
                <div className="text-right">
                  <span
                    className={`inline-flex rounded-full border px-2.5 py-1 text-[11px] font-medium uppercase tracking-wide ${statusClasses(event.status)}`}
                  >
                    {event.status.replaceAll("_", " ")}
                  </span>
                  <p
                    className="mt-2 text-xs text-zinc-400"
                    title={formatDate(event.occurred_at, "long")}
                  >
                    {formatTimeAgo(event.occurred_at)}
                  </p>
                </div>
              </div>

              <div className="mt-3 flex flex-wrap gap-2 text-xs text-zinc-500">
                <span className="rounded-full bg-zinc-100 px-2 py-1 font-mono">
                  {event.kind}
                </span>
                <span className="rounded-full bg-zinc-100 px-2 py-1">
                  {event.source}
                </span>
                {event.provenance && (
                  <span className="rounded-full bg-zinc-100 px-2 py-1">
                    {event.provenance.replaceAll("_", " ")}
                  </span>
                )}
                {event.binding && (
                  <span className="rounded-full bg-zinc-100 px-2 py-1">
                    {event.binding}
                  </span>
                )}
                {event.runtime_source && (
                  <span className="rounded-full bg-zinc-100 px-2 py-1">
                    {event.runtime_source}
                  </span>
                )}
                {event.risk_class && (
                  <span className="rounded-full bg-amber-50 px-2 py-1 text-amber-700">
                    {event.risk_class.replaceAll("_", " ")}
                  </span>
                )}
                {event.sensitive_content_ref?.preview && (
                  <span className="rounded-full bg-zinc-100 px-2 py-1">
                    {event.sensitive_content_ref.preview}
                  </span>
                )}
              </div>

              {(event.delivery_target || event.internal_event_type) && (
                <div className="mt-3 flex flex-wrap gap-4 text-xs text-zinc-500">
                  {event.delivery_target && (
                    <span>
                      Target:{" "}
                      <span className="font-mono text-zinc-700">
                        {event.delivery_target}
                      </span>
                    </span>
                  )}
                  {event.internal_event_type && (
                    <span>
                      Event:{" "}
                      <span className="font-mono text-zinc-700">
                        {event.internal_event_type}
                      </span>
                    </span>
                  )}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
