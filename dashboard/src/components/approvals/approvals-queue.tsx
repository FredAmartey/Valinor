"use client";

import { useState } from "react";
import {
  useApprovalsQuery,
  useApproveRequestMutation,
  useDenyRequestMutation,
} from "@/lib/queries/approvals";
import { formatDate, formatTimeAgo } from "@/lib/format";
import { Skeleton } from "@/components/ui/skeleton";
import { useCan } from "@/components/providers/permission-provider";

export function ApprovalsQueue({ tenantId }: { tenantId?: string }) {
  const [statusFilter, setStatusFilter] = useState("pending");
  const canResolve = useCan("agents:write");
  const { data, isLoading, isError, refetch } = useApprovalsQuery(
    statusFilter,
    tenantId,
  );
  const approveMutation = useApproveRequestMutation();
  const denyMutation = useDenyRequestMutation();
  const approvals = data?.approvals ?? [];

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
              Failed to load approvals.
            </p>
            <p className="mt-1 text-sm text-rose-600">
              Retry to refresh pending review requests.
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
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-lg font-semibold tracking-tight text-zinc-900">
            Approvals
          </h2>
          <p className="mt-1 text-sm text-zinc-500">
            Review high-risk actions before they touch users or external
            systems.
          </p>
        </div>
        <select
          value={statusFilter}
          onChange={(event) => setStatusFilter(event.target.value)}
          className="rounded-lg border border-zinc-200 bg-white px-3 py-2 text-sm text-zinc-900"
        >
          <option value="pending">Pending</option>
          <option value="approved">Approved</option>
          <option value="denied">Denied</option>
          <option value="all">All</option>
        </select>
      </div>

      {approvals.length === 0 ? (
        <div className="rounded-xl border border-dashed border-zinc-300 bg-zinc-50 px-4 py-8 text-center">
          <p className="text-sm font-medium text-zinc-900">
            No approval requests
          </p>
          <p className="mt-1 text-sm text-zinc-500">
            Ambiguous outbound actions and governed writes will appear here.
          </p>
        </div>
      ) : (
        <div className="space-y-3">
          {approvals.map((approval) => (
            <div
              key={approval.id}
              className="rounded-xl border border-zinc-200 bg-white p-4 shadow-sm"
            >
              <div className="flex flex-wrap items-start justify-between gap-4">
                <div>
                  <p className="text-sm font-semibold text-zinc-900">
                    {approval.action_summary}
                  </p>
                  <p className="mt-1 text-sm text-zinc-600">
                    {approval.target_label}
                  </p>
                </div>
                <span className="rounded-full border border-amber-200 bg-amber-50 px-2.5 py-1 text-[11px] font-medium uppercase tracking-wide text-amber-700">
                  {approval.status}
                </span>
              </div>

              <div className="mt-3 flex flex-wrap gap-2 text-xs text-zinc-500">
                <span className="rounded-full bg-zinc-100 px-2 py-1">
                  {approval.target_type}
                </span>
                <span className="rounded-full bg-zinc-100 px-2 py-1">
                  {approval.risk_class.replaceAll("_", " ")}
                </span>
                <span
                  className="rounded-full bg-zinc-100 px-2 py-1"
                  title={formatDate(approval.created_at, "long")}
                >
                  {formatTimeAgo(approval.created_at)}
                </span>
              </div>

              {canResolve && approval.status === "pending" && (
                <div className="mt-4 flex gap-2">
                  <button
                    onClick={() => approveMutation.mutate(approval.id)}
                    disabled={
                      approveMutation.isPending || denyMutation.isPending
                    }
                    className="rounded-lg bg-emerald-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-emerald-700 disabled:opacity-50"
                  >
                    Approve
                  </button>
                  <button
                    onClick={() => denyMutation.mutate(approval.id)}
                    disabled={
                      approveMutation.isPending || denyMutation.isPending
                    }
                    className="rounded-lg border border-rose-200 bg-white px-3 py-1.5 text-sm font-medium text-rose-700 hover:bg-rose-50 disabled:opacity-50"
                  >
                    Deny
                  </button>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
