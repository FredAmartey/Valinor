"use client"

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query"
import { useSession } from "next-auth/react"
import { apiClient } from "@/lib/api-client"
import type { AgentInstance, ProvisionAgentRequest, ConfigureAgentRequest } from "@/lib/types"

export const agentKeys = {
  all: ["agents"] as const,
  list: (tenantId?: string) => [...agentKeys.all, "list", tenantId ?? "self"] as const,
  detail: (id: string) => [...agentKeys.all, "detail", id] as const,
}

interface AgentListResponse {
  agents: AgentInstance[]
}

export async function fetchAgents(tenantId?: string): Promise<AgentListResponse> {
  const path = tenantId ? `/api/v1/tenants/${tenantId}/agents` : "/api/v1/agents"
  return apiClient<AgentListResponse>(path, undefined)
}

export async function fetchAgent(id: string): Promise<AgentInstance> {
  return apiClient<AgentInstance>(`/api/v1/agents/${id}`, undefined)
}

export async function provisionAgent(
  data: ProvisionAgentRequest,
): Promise<AgentInstance> {
  return apiClient<AgentInstance>("/api/v1/agents", {
    method: "POST",
    body: JSON.stringify(data),
  })
}

export async function destroyAgent(
  id: string,
): Promise<void> {
  return apiClient<void>(`/api/v1/agents/${id}`, {
    method: "DELETE",
  })
}

export async function configureAgent(
  id: string,
  data: ConfigureAgentRequest,
): Promise<AgentInstance> {
  return apiClient<AgentInstance>(`/api/v1/agents/${id}/configure`, {
    method: "POST",
    body: JSON.stringify(data),
  })
}

export function useAgentsQuery(statusFilter?: string, tenantId?: string) {
  const { data: session } = useSession()
  return useQuery({
    queryKey: agentKeys.list(tenantId),
    queryFn: () => fetchAgents(tenantId),
    select: (data) => {
      if (statusFilter && statusFilter !== "all") {
        return { agents: data.agents.filter((a) => a.status === statusFilter) }
      }
      return data
    },
    enabled: !!session,
    refetchInterval: 10_000,
  })
}

export function useAgentQuery(id: string) {
  const { data: session } = useSession()
  return useQuery({
    queryKey: agentKeys.detail(id),
    queryFn: () => fetchAgent(id),
    enabled: !!session && !!id,
    refetchInterval: 10_000,
  })
}

export function useProvisionAgentMutation() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (data: ProvisionAgentRequest) =>
      provisionAgent(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: agentKeys.all })
    },
  })
}

export function useDestroyAgentMutation() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => destroyAgent(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: agentKeys.all })
    },
  })
}

export function useConfigureAgentMutation(id: string) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (data: ConfigureAgentRequest) =>
      configureAgent(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: agentKeys.detail(id) })
      queryClient.invalidateQueries({ queryKey: agentKeys.list() })
    },
  })
}
