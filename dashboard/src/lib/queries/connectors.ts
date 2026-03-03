"use client"

import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query"
import { useSession } from "next-auth/react"
import { apiClient } from "@/lib/api-client"
import type { Connector, CreateConnectorRequest } from "@/lib/types"

export const connectorKeys = {
  all: ["connectors"] as const,
  list: () => [...connectorKeys.all, "list"] as const,
}

// --- Fetch functions ---

export async function fetchConnectors(): Promise<Connector[]> {
  return apiClient<Connector[]>("/api/v1/connectors", undefined)
}

export async function createConnector(
  data: CreateConnectorRequest,
): Promise<Connector> {
  return apiClient<Connector>("/api/v1/connectors", {
    method: "POST",
    body: JSON.stringify(data),
  })
}

export async function deleteConnector(id: string): Promise<void> {
  return apiClient<void>(`/api/v1/connectors/${id}`, {
    method: "DELETE",
  })
}

// --- Query hooks ---

export function useConnectorsQuery() {
  const { data: session } = useSession()
  return useQuery({
    queryKey: connectorKeys.list(),
    queryFn: () => fetchConnectors(),
    enabled: !!session,
    staleTime: 30_000,
  })
}

// --- Mutation hooks ---

export function useCreateConnectorMutation() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (data: CreateConnectorRequest) =>
      createConnector(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: connectorKeys.all })
    },
  })
}

export function useDeleteConnectorMutation() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => deleteConnector(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: connectorKeys.all })
    },
  })
}
