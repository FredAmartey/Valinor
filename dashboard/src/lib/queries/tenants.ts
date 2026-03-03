"use client"

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query"
import { useSession } from "next-auth/react"
import { apiClient } from "@/lib/api-client"
import type { Tenant, TenantCreateRequest } from "@/lib/types"

// Query key factory
export const tenantKeys = {
  all: ["tenants"] as const,
  list: () => [...tenantKeys.all, "list"] as const,
  detail: (id: string) => [...tenantKeys.all, "detail", id] as const,
}

// Fetch functions (exported for testing)
export async function fetchTenants(
  params?: Record<string, string>,
): Promise<Tenant[]> {
  return apiClient<Tenant[]>("/api/v1/tenants", params ? { params } : undefined)
}

export async function fetchTenant(
  id: string,
): Promise<Tenant> {
  return apiClient<Tenant>(`/api/v1/tenants/${id}`, undefined)
}

export async function createTenant(
  data: TenantCreateRequest,
): Promise<Tenant> {
  return apiClient<Tenant>("/api/v1/tenants", {
    method: "POST",
    body: JSON.stringify(data),
  })
}

// React hooks
export function useTenantsQuery() {
  const { data: session } = useSession()
  return useQuery({
    queryKey: tenantKeys.list(),
    queryFn: () => fetchTenants(),
    enabled: !!session,
    staleTime: 30_000,
  })
}

export function useTenantQuery(id: string) {
  const { data: session } = useSession()
  return useQuery({
    queryKey: tenantKeys.detail(id),
    queryFn: () => fetchTenant(id),
    enabled: !!session && !!id,
  })
}

export function useCreateTenantMutation() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (data: TenantCreateRequest) =>
      createTenant(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: tenantKeys.all })
    },
  })
}
