"use client"

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query"
import { useSession } from "next-auth/react"
import { apiClient } from "@/lib/api-client"
import { userKeys } from "./users"
import type { Role, UserRole, AssignRoleRequest, UpdateRoleRequest } from "@/lib/types"

export const roleKeys = {
  all: ["roles"] as const,
  list: (tenantId?: string) => [...roleKeys.all, "list", tenantId ?? "self"] as const,
  userRoles: (userId: string) => ["userRoles", userId] as const,
}

export async function fetchRoles(tenantId?: string): Promise<Role[]> {
  const path = tenantId ? `/api/v1/tenants/${tenantId}/roles` : "/api/v1/roles"
  return apiClient<Role[]>(path, undefined)
}

export async function fetchUserRoles(
  userId: string,
): Promise<UserRole[]> {
  return apiClient<UserRole[]>(`/api/v1/users/${userId}/roles`, undefined)
}

export async function assignRole(
  userId: string,
  data: AssignRoleRequest,
): Promise<{ status: string }> {
  return apiClient<{ status: string }>(`/api/v1/users/${userId}/roles`, {
    method: "POST",
    body: JSON.stringify(data),
  })
}

export async function removeRole(
  userId: string,
  data: AssignRoleRequest,
): Promise<{ status: string }> {
  return apiClient<{ status: string }>(`/api/v1/users/${userId}/roles`, {
    method: "DELETE",
    body: JSON.stringify(data),
  })
}

export function useRolesQuery(tenantId?: string) {
  const { data: session } = useSession()
  return useQuery({
    queryKey: roleKeys.list(tenantId),
    queryFn: () => fetchRoles(tenantId),
    enabled: !!session,
    staleTime: 60_000,
  })
}

export function useUserRolesQuery(userId: string) {
  const { data: session } = useSession()
  return useQuery({
    queryKey: roleKeys.userRoles(userId),
    queryFn: () => fetchUserRoles(userId),
    enabled: !!session && !!userId,
  })
}

export function useAssignRoleMutation(userId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (data: AssignRoleRequest) =>
      assignRole(userId, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: roleKeys.userRoles(userId) })
      queryClient.invalidateQueries({ queryKey: userKeys.detail(userId) })
    },
  })
}

export async function updateRole(
  roleId: string,
  data: UpdateRoleRequest,
): Promise<Role> {
  return apiClient<Role>(`/api/v1/roles/${roleId}`, {
    method: "PUT",
    body: JSON.stringify(data),
  })
}

export async function deleteRole(
  roleId: string,
): Promise<void> {
  return apiClient<void>(`/api/v1/roles/${roleId}`, {
    method: "DELETE",
  })
}

export function useCreateRoleMutation() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (data: { name: string; permissions: string[] }) =>
      apiClient<Role>("/api/v1/roles", {
        method: "POST",
        body: JSON.stringify(data),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: roleKeys.list() })
    },
  })
}

export function useUpdateRoleMutation() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ roleId, data }: { roleId: string; data: UpdateRoleRequest }) =>
      updateRole(roleId, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: roleKeys.list() })
    },
  })
}

export function useDeleteRoleMutation() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (roleId: string) =>
      deleteRole(roleId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: roleKeys.list() })
    },
  })
}

export function useRemoveRoleMutation(userId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (data: AssignRoleRequest) =>
      removeRole(userId, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: roleKeys.userRoles(userId) })
      queryClient.invalidateQueries({ queryKey: userKeys.detail(userId) })
    },
  })
}
