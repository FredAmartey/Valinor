"use client"

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query"
import { useSession } from "next-auth/react"
import { apiClient } from "@/lib/api-client"
import type { User, CreateUserRequest, UpdateUserRequest, Department } from "@/lib/types"

export const userKeys = {
  all: ["users"] as const,
  list: (tenantId?: string) => [...userKeys.all, "list", tenantId ?? "self"] as const,
  detail: (id: string) => [...userKeys.all, "detail", id] as const,
  userDepartments: (id: string) => [...userKeys.all, "departments", id] as const,
}

export async function fetchUsers(
  params?: Record<string, string>,
  tenantId?: string,
): Promise<User[]> {
  const path = tenantId ? `/api/v1/tenants/${tenantId}/users` : "/api/v1/users"
  return apiClient<User[]>(path, params ? { params } : undefined)
}

export async function fetchUser(
  id: string,
): Promise<User> {
  return apiClient<User>(`/api/v1/users/${id}`, undefined)
}

export async function createUser(
  data: CreateUserRequest,
): Promise<User> {
  return apiClient<User>("/api/v1/users", {
    method: "POST",
    body: JSON.stringify(data),
  })
}

export async function fetchUserDepartments(
  userId: string,
): Promise<Department[]> {
  return apiClient<Department[]>(`/api/v1/users/${userId}/departments`, undefined)
}

export async function addUserToDepartment(
  userId: string,
  departmentId: string,
): Promise<{ status: string }> {
  return apiClient<{ status: string }>(`/api/v1/users/${userId}/departments`, {
    method: "POST",
    body: JSON.stringify({ department_id: departmentId }),
  })
}

export async function updateUser(
  id: string,
  data: UpdateUserRequest,
): Promise<User> {
  return apiClient<User>(`/api/v1/users/${id}`, {
    method: "PUT",
    body: JSON.stringify(data),
  })
}

export async function deleteUser(
  id: string,
): Promise<{ status: string }> {
  return apiClient<{ status: string }>(`/api/v1/users/${id}`, {
    method: "DELETE",
  })
}

export async function removeUserFromDepartment(
  userId: string,
  departmentId: string,
): Promise<{ status: string }> {
  return apiClient<{ status: string }>(`/api/v1/users/${userId}/departments/${departmentId}`, {
    method: "DELETE",
  })
}

// React hooks
export function useUsersQuery(tenantId?: string) {
  const { data: session } = useSession()
  return useQuery({
    queryKey: userKeys.list(tenantId),
    queryFn: () => fetchUsers(undefined, tenantId),
    enabled: !!session,
    staleTime: 30_000,
  })
}

export function useUserQuery(id: string) {
  const { data: session } = useSession()
  return useQuery({
    queryKey: userKeys.detail(id),
    queryFn: () => fetchUser(id),
    enabled: !!session && !!id,
  })
}

export function useUserDepartmentsQuery(userId: string) {
  const { data: session } = useSession()
  return useQuery({
    queryKey: userKeys.userDepartments(userId),
    queryFn: () => fetchUserDepartments(userId),
    enabled: !!session && !!userId,
  })
}

export function useCreateUserMutation() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (data: CreateUserRequest) => createUser(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: userKeys.all })
    },
  })
}

export function useAddUserToDepartmentMutation(userId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (departmentId: string) =>
      addUserToDepartment(userId, departmentId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: userKeys.userDepartments(userId) })
    },
  })
}

export function useRemoveUserFromDepartmentMutation(userId: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (departmentId: string) =>
      removeUserFromDepartment(userId, departmentId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: userKeys.userDepartments(userId) })
    },
  })
}

export function useUpdateUserMutation(id: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (data: UpdateUserRequest) =>
      updateUser(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: userKeys.detail(id) })
      queryClient.invalidateQueries({ queryKey: userKeys.list() })
    },
  })
}

export function useDeleteUserMutation(id: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: () => deleteUser(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: userKeys.all })
    },
  })
}
