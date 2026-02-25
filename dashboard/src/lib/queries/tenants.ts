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
  accessToken: string,
  params?: Record<string, string>,
): Promise<Tenant[]> {
  return apiClient<Tenant[]>("/api/v1/tenants", accessToken, params ? { params } : undefined)
}

export async function fetchTenant(
  accessToken: string,
  id: string,
): Promise<Tenant> {
  return apiClient<Tenant>(`/api/v1/tenants/${id}`, accessToken, undefined)
}

export async function createTenant(
  accessToken: string,
  data: TenantCreateRequest,
): Promise<Tenant> {
  return apiClient<Tenant>("/api/v1/tenants", accessToken, {
    method: "POST",
    body: JSON.stringify(data),
  })
}

// React hooks
export function useTenantsQuery() {
  const { data: session } = useSession()
  return useQuery({
    queryKey: tenantKeys.list(),
    queryFn: () => fetchTenants(session!.accessToken),
    enabled: !!session?.accessToken,
    staleTime: 30_000,
  })
}

export function useTenantQuery(id: string) {
  const { data: session } = useSession()
  return useQuery({
    queryKey: tenantKeys.detail(id),
    queryFn: () => fetchTenant(session!.accessToken, id),
    enabled: !!session?.accessToken && !!id,
  })
}

export function useCreateTenantMutation() {
  const { data: session } = useSession()
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (data: TenantCreateRequest) =>
      createTenant(session!.accessToken, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: tenantKeys.all })
    },
  })
}
