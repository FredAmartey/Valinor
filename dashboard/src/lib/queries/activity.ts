"use client";

import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { useSession } from "next-auth/react";
import { apiClient } from "@/lib/api-client";
import type {
  ActivityFilters,
  ActivityListResponse,
  SecurityOverview,
} from "@/lib/types";

export const activityKeys = {
  all: ["activity"] as const,
  agent: (agentId: string, filters?: ActivityFilters) =>
    [...activityKeys.all, "agent", agentId, filters ?? {}] as const,
  tenant: (filters?: ActivityFilters, tenantId?: string) =>
    [...activityKeys.all, "tenant", filters ?? {}, tenantId ?? "self"] as const,
  security: (filters?: ActivityFilters, tenantId?: string) =>
    [
      ...activityKeys.all,
      "security",
      filters ?? {},
      tenantId ?? "self",
    ] as const,
  securityOverview: (tenantId?: string) =>
    [...activityKeys.all, "security-overview", tenantId ?? "self"] as const,
};

function buildParams(filters?: ActivityFilters) {
  const params: Record<string, string> = {};
  if (!filters) return params;
  for (const [key, value] of Object.entries(filters)) {
    if (value !== undefined && value !== "") {
      params[key] = value;
    }
  }
  return params;
}

export async function fetchAgentActivity(
  agentId: string,
  filters?: ActivityFilters,
): Promise<ActivityListResponse> {
  return apiClient<ActivityListResponse>(`/api/v1/agents/${agentId}/activity`, {
    params: buildParams(filters),
  });
}

export async function fetchTenantActivity(
  filters?: ActivityFilters,
  tenantId?: string,
): Promise<ActivityListResponse> {
  const path = tenantId
    ? `/api/v1/tenants/${tenantId}/activity`
    : "/api/v1/activity";
  return apiClient<ActivityListResponse>(path, {
    params: buildParams(filters),
  });
}

export async function fetchSecurityEvents(
  filters?: ActivityFilters,
  tenantId?: string,
): Promise<ActivityListResponse> {
  const path = tenantId
    ? `/api/v1/tenants/${tenantId}/security/events`
    : "/api/v1/security/events";
  return apiClient<ActivityListResponse>(path, {
    params: buildParams(filters),
  });
}

export async function fetchSecurityOverview(
  tenantId?: string,
): Promise<SecurityOverview> {
  const path = tenantId
    ? `/api/v1/tenants/${tenantId}/security/overview`
    : "/api/v1/security/overview";
  return apiClient<SecurityOverview>(path);
}

export function useAgentActivityQuery(
  agentId: string,
  filters?: ActivityFilters,
) {
  const { data: session } = useSession();
  return useQuery({
    queryKey: activityKeys.agent(agentId, filters),
    queryFn: () => fetchAgentActivity(agentId, filters),
    enabled: !!session && !!agentId,
    staleTime: 15_000,
    placeholderData: keepPreviousData,
  });
}

export function useTenantActivityQuery(
  filters?: ActivityFilters,
  tenantId?: string,
) {
  const { data: session } = useSession();
  return useQuery({
    queryKey: activityKeys.tenant(filters, tenantId),
    queryFn: () => fetchTenantActivity(filters, tenantId),
    enabled: !!session,
    staleTime: 15_000,
    placeholderData: keepPreviousData,
  });
}

export function useSecurityEventsQuery(
  filters?: ActivityFilters,
  tenantId?: string,
) {
  const { data: session } = useSession();
  return useQuery({
    queryKey: activityKeys.security(filters, tenantId),
    queryFn: () => fetchSecurityEvents(filters, tenantId),
    enabled: !!session,
    staleTime: 15_000,
    placeholderData: keepPreviousData,
  });
}

export function useSecurityOverviewQuery(tenantId?: string) {
  const { data: session } = useSession();
  return useQuery({
    queryKey: activityKeys.securityOverview(tenantId),
    queryFn: () => fetchSecurityOverview(tenantId),
    enabled: !!session,
    staleTime: 30_000,
    placeholderData: keepPreviousData,
  });
}
