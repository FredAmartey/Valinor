"use client"

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query"
import { useSession } from "next-auth/react"
import { apiClient } from "@/lib/api-client"
import type { User, CreateUserRequest } from "@/lib/types"

export const userKeys = {
  all: ["users"] as const,
  list: () => [...userKeys.all, "list"] as const,
  detail: (id: string) => [...userKeys.all, "detail", id] as const,
}

export async function fetchUsers(
  accessToken: string,
  params?: Record<string, string>,
): Promise<User[]> {
  return apiClient<User[]>("/api/v1/users", accessToken, params ? { params } : undefined)
}

export async function fetchUser(
  accessToken: string,
  id: string,
): Promise<User> {
  return apiClient<User>(`/api/v1/users/${id}`, accessToken, undefined)
}

export async function createUser(
  accessToken: string,
  data: CreateUserRequest,
): Promise<User> {
  return apiClient<User>("/api/v1/users", accessToken, {
    method: "POST",
    body: JSON.stringify(data),
  })
}

export async function addUserToDepartment(
  accessToken: string,
  userId: string,
  departmentId: string,
): Promise<{ status: string }> {
  return apiClient<{ status: string }>(`/api/v1/users/${userId}/departments`, accessToken, {
    method: "POST",
    body: JSON.stringify({ department_id: departmentId }),
  })
}

export async function removeUserFromDepartment(
  accessToken: string,
  userId: string,
  departmentId: string,
): Promise<{ status: string }> {
  return apiClient<{ status: string }>(`/api/v1/users/${userId}/departments/${departmentId}`, accessToken, {
    method: "DELETE",
  })
}

// React hooks
export function useUsersQuery() {
  const { data: session } = useSession()
  return useQuery({
    queryKey: userKeys.list(),
    queryFn: () => fetchUsers(session!.accessToken),
    enabled: !!session?.accessToken,
    staleTime: 30_000,
  })
}

export function useUserQuery(id: string) {
  const { data: session } = useSession()
  return useQuery({
    queryKey: userKeys.detail(id),
    queryFn: () => fetchUser(session!.accessToken, id),
    enabled: !!session?.accessToken && !!id,
  })
}

export function useCreateUserMutation() {
  const { data: session } = useSession()
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (data: CreateUserRequest) => createUser(session!.accessToken, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: userKeys.all })
    },
  })
}

export function useAddUserToDepartmentMutation(userId: string) {
  const { data: session } = useSession()
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (departmentId: string) =>
      addUserToDepartment(session!.accessToken, userId, departmentId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: userKeys.detail(userId) })
    },
  })
}

export function useRemoveUserFromDepartmentMutation(userId: string) {
  const { data: session } = useSession()
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (departmentId: string) =>
      removeUserFromDepartment(session!.accessToken, userId, departmentId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: userKeys.detail(userId) })
    },
  })
}
