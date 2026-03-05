"use client"

import { useQuery, keepPreviousData } from "@tanstack/react-query"
import { useSession } from "next-auth/react"
import { apiClient } from "@/lib/api-client"
import type { AuditListResponse, AuditFilters } from "@/lib/types"

export const auditKeys = {
  all: ["auditEvents"] as const,
  list: (filters?: AuditFilters, tenantId?: string) =>
    [...auditKeys.all, "list", filters ?? {}, tenantId ?? "self"] as const,
}

export async function fetchAuditEvents(
  filters?: AuditFilters,
  tenantId?: string,
): Promise<AuditListResponse> {
  const params: Record<string, string> = {}
  if (filters) {
    for (const [key, value] of Object.entries(filters)) {
      if (value !== undefined && value !== "") {
        params[key] = value
      }
    }
  }
  const path = tenantId ? `/api/v1/tenants/${tenantId}/audit/events` : "/api/v1/audit/events"
  return apiClient<AuditListResponse>(path, { params })
}

export function useAuditEventsQuery(filters?: AuditFilters, tenantId?: string) {
  const { data: session } = useSession()
  return useQuery({
    queryKey: auditKeys.list(filters, tenantId),
    queryFn: () => fetchAuditEvents(filters, tenantId),
    enabled: !!session,
    staleTime: 30_000,
    placeholderData: keepPreviousData,
  })
}
