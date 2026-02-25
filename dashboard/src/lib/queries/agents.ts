"use client"

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query"
import { useSession } from "next-auth/react"
import { apiClient } from "@/lib/api-client"
import type { AgentInstance, ProvisionAgentRequest, ConfigureAgentRequest } from "@/lib/types"

export const agentKeys = {
  all: ["agents"] as const,
  list: () => [...agentKeys.all, "list"] as const,
  detail: (id: string) => [...agentKeys.all, "detail", id] as const,
}

interface AgentListResponse {
  agents: AgentInstance[]
}

export async function fetchAgents(accessToken: string): Promise<AgentListResponse> {
  return apiClient<AgentListResponse>("/api/v1/agents", accessToken, undefined)
}

export async function fetchAgent(accessToken: string, id: string): Promise<AgentInstance> {
  return apiClient<AgentInstance>(`/api/v1/agents/${id}`, accessToken, undefined)
}

export async function provisionAgent(
  accessToken: string,
  data: ProvisionAgentRequest,
): Promise<AgentInstance> {
  return apiClient<AgentInstance>("/api/v1/agents", accessToken, {
    method: "POST",
    body: JSON.stringify(data),
  })
}

export async function destroyAgent(
  accessToken: string,
  id: string,
): Promise<void> {
  return apiClient<void>(`/api/v1/agents/${id}`, accessToken, {
    method: "DELETE",
  })
}

export async function configureAgent(
  accessToken: string,
  id: string,
  data: ConfigureAgentRequest,
): Promise<AgentInstance> {
  return apiClient<AgentInstance>(`/api/v1/agents/${id}/configure`, accessToken, {
    method: "POST",
    body: JSON.stringify(data),
  })
}

export function useAgentsQuery(statusFilter?: string) {
  const { data: session } = useSession()
  return useQuery({
    queryKey: agentKeys.list(),
    queryFn: () => fetchAgents(session!.accessToken),
    select: (data) => {
      if (statusFilter && statusFilter !== "all") {
        return { agents: data.agents.filter((a) => a.status === statusFilter) }
      }
      return data
    },
    enabled: !!session?.accessToken,
    refetchInterval: 10_000,
  })
}

export function useAgentQuery(id: string) {
  const { data: session } = useSession()
  return useQuery({
    queryKey: agentKeys.detail(id),
    queryFn: () => fetchAgent(session!.accessToken, id),
    enabled: !!session?.accessToken && !!id,
    refetchInterval: 10_000,
  })
}

export function useProvisionAgentMutation() {
  const { data: session } = useSession()
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (data: ProvisionAgentRequest) =>
      provisionAgent(session!.accessToken, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: agentKeys.all })
    },
  })
}

export function useDestroyAgentMutation() {
  const { data: session } = useSession()
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => destroyAgent(session!.accessToken, id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: agentKeys.all })
    },
  })
}

export function useConfigureAgentMutation(id: string) {
  const { data: session } = useSession()
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (data: ConfigureAgentRequest) =>
      configureAgent(session!.accessToken, id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: agentKeys.detail(id) })
      queryClient.invalidateQueries({ queryKey: agentKeys.list() })
    },
  })
}
