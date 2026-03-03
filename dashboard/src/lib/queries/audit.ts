"use client"

import { useQuery, keepPreviousData } from "@tanstack/react-query"
import { useSession } from "next-auth/react"
import { apiClient } from "@/lib/api-client"
import type { AuditListResponse, AuditFilters } from "@/lib/types"

export const auditKeys = {
  all: ["auditEvents"] as const,
  list: (filters?: AuditFilters) => [...auditKeys.all, "list", filters ?? {}] as const,
}

export async function fetchAuditEvents(
  filters?: AuditFilters,
): Promise<AuditListResponse> {
  const params: Record<string, string> = {}
  if (filters) {
    for (const [key, value] of Object.entries(filters)) {
      if (value !== undefined && value !== "") {
        params[key] = value
      }
    }
  }
  return apiClient<AuditListResponse>("/api/v1/audit/events", { params })
}

export function useAuditEventsQuery(filters?: AuditFilters) {
  const { data: session } = useSession()
  return useQuery({
    queryKey: auditKeys.list(filters),
    queryFn: () => fetchAuditEvents(filters),
    enabled: !!session,
    staleTime: 30_000,
    placeholderData: keepPreviousData,
  })
}
