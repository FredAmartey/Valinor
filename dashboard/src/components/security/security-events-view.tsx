"use client";

import {
  useSecurityEventsQuery,
  useSecurityOverviewQuery,
} from "@/lib/queries/activity";
import { connectorGovernanceLabels } from "@/lib/connector-governance";
import { formatDate, formatTimeAgo } from "@/lib/format";
import { Skeleton } from "@/components/ui/skeleton";
import type { ActivityEvent, SecurityCheck } from "@/lib/types";
import {
  ShieldWarning,
  WarningCircle,
  Eye,
  ArrowsClockwise,
  LockKey,
  Warning,
  Checks,
} from "@phosphor-icons/react";

function severityTone(event: ActivityEvent) {
  if (event.status === "blocked" || event.status === "halted") {
    return "border-rose-200 bg-rose-50 text-rose-700";
  }
  if (event.status === "approval_required" || event.status === "flagged") {
    return "border-amber-200 bg-amber-50 text-amber-700";
  }
  return "border-emerald-200 bg-emerald-50 text-emerald-700";
}

function checkTone(status: SecurityCheck["status"]) {
  switch (status) {
    case "critical":
      return "border-rose-200 bg-rose-50";
    case "warning":
      return "border-amber-200 bg-amber-50";
    default:
      return "border-emerald-200 bg-emerald-50";
  }
}

function checkIcon(status: SecurityCheck["status"]) {
  switch (status) {
    case "critical":
      return <LockKey size={16} className="text-rose-700" />;
    case "warning":
      return <Warning size={16} className="text-amber-700" />;
    default:
      return <Checks size={16} className="text-emerald-700" />;
  }
}

export function SecurityEventsView({ tenantId }: { tenantId?: string }) {
  const { data, isLoading, isError, refetch, isFetching } =
    useSecurityEventsQuery({ limit: "50" }, tenantId);
  const { data: overview } = useSecurityOverviewQuery(tenantId);
  const events = data?.events ?? [];
  const checks = overview?.checks ?? [];

  if (isLoading) {
    return (
      <div className="space-y-3">
        {Array.from({ length: 5 }).map((_, idx) => (
          <div
            key={idx}
            className="rounded-xl border border-zinc-200 bg-white p-4"
          >
            <Skeleton className="h-4 w-40" />
            <Skeleton className="mt-3 h-3 w-full" />
            <Skeleton className="mt-2 h-3 w-80" />
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
              Failed to load security events.
            </p>
            <p className="mt-1 text-sm text-rose-600">
              Retry to refresh the latest security decisions and halts.
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
      <div className="flex items-center justify-between gap-4">
        <div>
          <h2 className="text-lg font-semibold tracking-tight text-zinc-900">
            Security Center
          </h2>
          <p className="mt-1 text-sm text-zinc-500">
            Scan blocks, halted sessions, trust posture, and review-required
            actions across your tenant.
          </p>
        </div>
        <div className="flex items-center gap-2 text-xs text-zinc-400">
          <Eye size={14} />
          {isFetching ? "Refreshing…" : `${events.length} visible`}
        </div>
      </div>

      {checks.length > 0 && (
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
          {checks.map((check) => (
            <div
              key={check.id}
              className={`rounded-xl border p-4 shadow-sm ${checkTone(check.status)}`}
            >
              <div className="flex items-start justify-between gap-3">
                <div className="flex items-center gap-2">
                  {checkIcon(check.status)}
                  <p className="text-sm font-semibold text-zinc-900">
                    {check.title}
                  </p>
                </div>
                <span className="rounded-full bg-white/80 px-2 py-1 text-[11px] font-semibold uppercase tracking-wide text-zinc-600">
                  {check.status}
                </span>
              </div>
              <p className="mt-3 text-sm text-zinc-700">{check.summary}</p>
              {check.details && (
                <p className="mt-2 text-xs text-zinc-500">{check.details}</p>
              )}
            </div>
          ))}
        </div>
      )}

      {events.length === 0 ? (
        <div className="rounded-xl border border-dashed border-zinc-300 bg-zinc-50 px-4 py-8 text-center">
          <p className="text-sm font-medium text-zinc-900">
            No security events recorded
          </p>
          <p className="mt-1 text-sm text-zinc-500">
            Blocked prompts, halted sessions, and risky outbound actions will
            show up here.
          </p>
        </div>
      ) : (
        <div className="space-y-3">
          {events.map((event) => {
            const governanceLabels = connectorGovernanceLabels(event.metadata);

            return (
              <div
                key={event.id}
                className="rounded-xl border border-zinc-200 bg-white p-4 shadow-sm"
              >
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div className="flex items-start gap-3">
                  <div className="mt-0.5 flex h-9 w-9 items-center justify-center rounded-full bg-zinc-100">
                    {event.status === "blocked" || event.status === "halted" ? (
                      <WarningCircle size={18} className="text-rose-700" />
                    ) : (
                      <ShieldWarning size={18} className="text-amber-700" />
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
                    className={`inline-flex rounded-full border px-2.5 py-1 text-[11px] font-medium uppercase tracking-wide ${severityTone(event)}`}
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
                {event.risk_class && (
                  <span className="rounded-full bg-amber-50 px-2 py-1 text-amber-700">
                    {event.risk_class.replaceAll("_", " ")}
                  </span>
                )}
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
                {governanceLabels.map((label) => (
                  <span
                    key={label}
                    className="rounded-full bg-violet-50 px-2 py-1 text-violet-700"
                  >
                    {label}
                  </span>
                ))}
                <span className="rounded-full bg-zinc-100 px-2 py-1">
                  {event.source}
                </span>
                {event.agent_id && (
                  <span className="rounded-full bg-zinc-100 px-2 py-1 font-mono">
                    {event.agent_id.slice(0, 8)}
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
            );
          })}
        </div>
      )}

      <div className="rounded-xl border border-zinc-200 bg-zinc-50 px-4 py-3 text-sm text-zinc-600">
        <div className="flex items-center gap-2">
          <ArrowsClockwise size={14} className="text-zinc-400" />
          This view is powered by the same append-only activity stream as the
          per-agent timeline.
        </div>
      </div>
    </div>
  );
}
