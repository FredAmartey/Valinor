"use client"

import { useQuery, useMutation, useQueryClient, keepPreviousData } from "@tanstack/react-query"
import { useSession } from "next-auth/react"
import { apiClient } from "@/lib/api-client"
import type {
  ChannelLink,
  ChannelOutbox,
  ProviderCredentialResponse,
  CreateChannelLinkRequest,
  UpsertProviderCredentialRequest,
} from "@/lib/types"

export type ProviderName = "slack" | "whatsapp" | "telegram"

export const channelKeys = {
  all: ["channels"] as const,
  links: (tenantId?: string) => [...channelKeys.all, "links", tenantId ?? "self"] as const,
  outbox: (status?: string) => [...channelKeys.all, "outbox", status ?? "all"] as const,
  provider: (name: ProviderName) => [...channelKeys.all, "provider", name] as const,
}

// --- Fetch functions ---

export async function fetchChannelLinks(tenantId?: string): Promise<ChannelLink[]> {
  const path = tenantId ? `/api/v1/tenants/${tenantId}/channels/links` : "/api/v1/channels/links"
  return apiClient<ChannelLink[]>(path, undefined)
}

export async function fetchOutbox(
  status?: string,
): Promise<ChannelOutbox[]> {
  const params: Record<string, string> = { limit: "100" }
  if (status && status !== "all") {
    params.status = status
  }
  return apiClient<ChannelOutbox[]>("/api/v1/channels/outbox", { params })
}

export async function fetchProviderCredential(
  provider: ProviderName,
): Promise<ProviderCredentialResponse> {
  return apiClient<ProviderCredentialResponse>(
    `/api/v1/channels/providers/${provider}/credentials`,
    undefined,
  )
}

// --- Mutation functions ---

export async function createChannelLink(
  data: CreateChannelLinkRequest,
): Promise<ChannelLink> {
  return apiClient<ChannelLink>("/api/v1/channels/links", {
    method: "POST",
    body: JSON.stringify(data),
  })
}

export async function deleteChannelLink(id: string): Promise<void> {
  return apiClient<void>(`/api/v1/channels/links/${id}`, {
    method: "DELETE",
  })
}

export async function requeueOutboxJob(id: string): Promise<void> {
  return apiClient<void>(`/api/v1/channels/outbox/${id}/requeue`, {
    method: "POST",
  })
}

export async function upsertProviderCredential(
  provider: ProviderName,
  data: UpsertProviderCredentialRequest,
): Promise<ProviderCredentialResponse> {
  return apiClient<ProviderCredentialResponse>(
    `/api/v1/channels/providers/${provider}/credentials`,
    { method: "PUT", body: JSON.stringify(data) },
  )
}

export async function deleteProviderCredential(
  provider: ProviderName,
): Promise<void> {
  return apiClient<void>(
    `/api/v1/channels/providers/${provider}/credentials`,
    { method: "DELETE" },
  )
}

// --- Query hooks ---

export function useChannelLinksQuery(tenantId?: string) {
  const { data: session } = useSession()
  return useQuery({
    queryKey: channelKeys.links(tenantId),
    queryFn: () => fetchChannelLinks(tenantId),
    enabled: !!session,
    staleTime: 30_000,
  })
}

export function useOutboxQuery(status?: string) {
  const { data: session } = useSession()
  return useQuery({
    queryKey: channelKeys.outbox(status),
    queryFn: () => fetchOutbox(status),
    enabled: !!session,
    refetchInterval: status === "pending" || status === "sending" ? 10_000 : undefined,
    placeholderData: keepPreviousData,
  })
}

export function useProviderCredentialQuery(provider: ProviderName) {
  const { data: session } = useSession()
  return useQuery({
    queryKey: channelKeys.provider(provider),
    queryFn: () => fetchProviderCredential(provider),
    enabled: !!session,
    retry: false,
  })
}

// --- Mutation hooks ---

export function useCreateChannelLinkMutation() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (data: CreateChannelLinkRequest) =>
      createChannelLink(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: channelKeys.links() })
    },
  })
}

export function useDeleteChannelLinkMutation() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => deleteChannelLink(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: channelKeys.links() })
    },
  })
}

export function useRequeueOutboxMutation() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => requeueOutboxJob(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: channelKeys.all })
    },
  })
}

export function useUpsertProviderCredentialMutation(provider: ProviderName) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (data: UpsertProviderCredentialRequest) =>
      upsertProviderCredential(provider, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: channelKeys.provider(provider) })
    },
  })
}

export function useDeleteProviderCredentialMutation(provider: ProviderName) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: () => deleteProviderCredential(provider),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: channelKeys.provider(provider) })
    },
  })
}
