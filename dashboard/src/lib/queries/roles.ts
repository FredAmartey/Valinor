"use client"

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query"
import { useSession } from "next-auth/react"
import { apiClient } from "@/lib/api-client"
import { userKeys } from "./users"
import type { Role, UserRole, AssignRoleRequest, UpdateRoleRequest } from "@/lib/types"

export const roleKeys = {
  all: ["roles"] as const,
  list: () => [...roleKeys.all, "list"] as const,
  userRoles: (userId: string) => ["userRoles", userId] as const,
}

export async function fetchRoles(accessToken: string): Promise<Role[]> {
  return apiClient<Role[]>("/api/v1/roles", accessToken, undefined)
}

export async function fetchUserRoles(
  accessToken: string,
  userId: string,
): Promise<UserRole[]> {
  return apiClient<UserRole[]>(`/api/v1/users/${userId}/roles`, accessToken, undefined)
}

export async function assignRole(
  accessToken: string,
  userId: string,
  data: AssignRoleRequest,
): Promise<{ status: string }> {
  return apiClient<{ status: string }>(`/api/v1/users/${userId}/roles`, accessToken, {
    method: "POST",
    body: JSON.stringify(data),
  })
}

export async function removeRole(
  accessToken: string,
  userId: string,
  data: AssignRoleRequest,
): Promise<{ status: string }> {
  return apiClient<{ status: string }>(`/api/v1/users/${userId}/roles`, accessToken, {
    method: "DELETE",
    body: JSON.stringify(data),
  })
}

export function useRolesQuery() {
  const { data: session } = useSession()
  return useQuery({
    queryKey: roleKeys.list(),
    queryFn: () => fetchRoles(session!.accessToken),
    enabled: !!session?.accessToken,
    staleTime: 60_000,
  })
}

export function useUserRolesQuery(userId: string) {
  const { data: session } = useSession()
  return useQuery({
    queryKey: roleKeys.userRoles(userId),
    queryFn: () => fetchUserRoles(session!.accessToken, userId),
    enabled: !!session?.accessToken && !!userId,
  })
}

export function useAssignRoleMutation(userId: string) {
  const { data: session } = useSession()
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (data: AssignRoleRequest) =>
      assignRole(session!.accessToken, userId, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: roleKeys.userRoles(userId) })
      queryClient.invalidateQueries({ queryKey: userKeys.detail(userId) })
    },
  })
}

export async function updateRole(
  accessToken: string,
  roleId: string,
  data: UpdateRoleRequest,
): Promise<Role> {
  return apiClient<Role>(`/api/v1/roles/${roleId}`, accessToken, {
    method: "PUT",
    body: JSON.stringify(data),
  })
}

export async function deleteRole(
  accessToken: string,
  roleId: string,
): Promise<void> {
  return apiClient<void>(`/api/v1/roles/${roleId}`, accessToken, {
    method: "DELETE",
  })
}

export function useUpdateRoleMutation() {
  const { data: session } = useSession()
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ roleId, data }: { roleId: string; data: UpdateRoleRequest }) =>
      updateRole(session!.accessToken, roleId, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: roleKeys.list() })
    },
  })
}

export function useDeleteRoleMutation() {
  const { data: session } = useSession()
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (roleId: string) =>
      deleteRole(session!.accessToken, roleId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: roleKeys.list() })
    },
  })
}

export function useRemoveRoleMutation(userId: string) {
  const { data: session } = useSession()
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (data: AssignRoleRequest) =>
      removeRole(session!.accessToken, userId, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: roleKeys.userRoles(userId) })
      queryClient.invalidateQueries({ queryKey: userKeys.detail(userId) })
    },
  })
}
