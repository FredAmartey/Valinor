"use client"

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query"
import { useSession } from "next-auth/react"
import { apiClient } from "@/lib/api-client"
import type { Department, CreateDepartmentRequest, UpdateDepartmentRequest } from "@/lib/types"

export const departmentKeys = {
  all: ["departments"] as const,
  list: (tenantId?: string) => [...departmentKeys.all, "list", tenantId ?? "self"] as const,
  detail: (id: string) => [...departmentKeys.all, "detail", id] as const,
}

export async function fetchDepartments(tenantId?: string): Promise<Department[]> {
  const path = tenantId ? `/api/v1/tenants/${tenantId}/departments` : "/api/v1/departments"
  return apiClient<Department[]>(path, undefined)
}

export async function fetchDepartment(
  id: string,
): Promise<Department> {
  return apiClient<Department>(`/api/v1/departments/${id}`, undefined)
}

export async function createDepartment(
  data: CreateDepartmentRequest,
): Promise<Department> {
  return apiClient<Department>("/api/v1/departments", {
    method: "POST",
    body: JSON.stringify(data),
  })
}

export async function updateDepartment(
  id: string,
  data: UpdateDepartmentRequest,
): Promise<Department> {
  return apiClient<Department>(`/api/v1/departments/${id}`, {
    method: "PUT",
    body: JSON.stringify(data),
  })
}

export async function deleteDepartment(
  id: string,
): Promise<{ status: string }> {
  return apiClient<{ status: string }>(`/api/v1/departments/${id}`, {
    method: "DELETE",
  })
}

export function useDepartmentsQuery(tenantId?: string) {
  const { data: session } = useSession()
  return useQuery({
    queryKey: departmentKeys.list(tenantId),
    queryFn: () => fetchDepartments(tenantId),
    enabled: !!session,
    staleTime: 30_000,
  })
}

export function useDepartmentQuery(id: string) {
  const { data: session } = useSession()
  return useQuery({
    queryKey: departmentKeys.detail(id),
    queryFn: () => fetchDepartment(id),
    enabled: !!session && !!id,
  })
}

export function useCreateDepartmentMutation() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (data: CreateDepartmentRequest) =>
      createDepartment(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: departmentKeys.all })
    },
  })
}

export function useUpdateDepartmentMutation(id: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (data: UpdateDepartmentRequest) =>
      updateDepartment(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: departmentKeys.detail(id) })
      queryClient.invalidateQueries({ queryKey: departmentKeys.list() })
    },
  })
}

export function useDeleteDepartmentMutation(id: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: () => deleteDepartment(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: departmentKeys.all })
    },
  })
}
