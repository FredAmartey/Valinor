"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useSession } from "next-auth/react";
import { apiClient } from "@/lib/api-client";
import type { ApprovalListResponse } from "@/lib/types";

export const approvalKeys = {
  all: ["approvals"] as const,
  list: (status?: string, tenantId?: string) =>
    [...approvalKeys.all, "list", status ?? "all", tenantId ?? "self"] as const,
};

export async function fetchApprovals(
  status?: string,
  tenantId?: string,
): Promise<ApprovalListResponse> {
  const path = tenantId
    ? `/api/v1/tenants/${tenantId}/approvals`
    : "/api/v1/approvals";
  return apiClient<ApprovalListResponse>(path, {
    params: status ? { status } : undefined,
  });
}

export async function approveRequest(id: string) {
  return apiClient(`/api/v1/approvals/${id}/approve`, { method: "POST" });
}

export async function denyRequest(id: string) {
  return apiClient(`/api/v1/approvals/${id}/deny`, { method: "POST" });
}

export function useApprovalsQuery(status = "pending", tenantId?: string) {
  const { data: session } = useSession();
  return useQuery({
    queryKey: approvalKeys.list(status, tenantId),
    queryFn: () =>
      fetchApprovals(status === "all" ? undefined : status, tenantId),
    enabled: !!session,
    staleTime: 10_000,
  });
}

export function useApproveRequestMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => approveRequest(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: approvalKeys.all });
    },
  });
}

export function useDenyRequestMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => denyRequest(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: approvalKeys.all });
    },
  });
}
