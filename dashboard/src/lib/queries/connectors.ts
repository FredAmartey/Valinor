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

export async function fetchConnectors(accessToken: string): Promise<Connector[]> {
  return apiClient<Connector[]>("/api/v1/connectors", accessToken, undefined)
}

export async function createConnector(
  accessToken: string,
  data: CreateConnectorRequest,
): Promise<Connector> {
  return apiClient<Connector>("/api/v1/connectors", accessToken, {
    method: "POST",
    body: JSON.stringify(data),
  })
}

export async function deleteConnector(accessToken: string, id: string): Promise<void> {
  return apiClient<void>(`/api/v1/connectors/${id}`, accessToken, {
    method: "DELETE",
  })
}

// --- Query hooks ---

export function useConnectorsQuery() {
  const { data: session } = useSession()
  return useQuery({
    queryKey: connectorKeys.list(),
    queryFn: () => fetchConnectors(session!.accessToken),
    enabled: !!session?.accessToken,
    staleTime: 30_000,
  })
}

// --- Mutation hooks ---

export function useCreateConnectorMutation() {
  const { data: session } = useSession()
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (data: CreateConnectorRequest) =>
      createConnector(session!.accessToken, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: connectorKeys.all })
    },
  })
}

export function useDeleteConnectorMutation() {
  const { data: session } = useSession()
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => deleteConnector(session!.accessToken, id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: connectorKeys.all })
    },
  })
}
