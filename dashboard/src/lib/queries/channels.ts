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
  links: () => [...channelKeys.all, "links"] as const,
  outbox: (status?: string) => [...channelKeys.all, "outbox", status ?? "all"] as const,
  provider: (name: ProviderName) => [...channelKeys.all, "provider", name] as const,
}

// --- Fetch functions ---

export async function fetchChannelLinks(accessToken: string): Promise<ChannelLink[]> {
  return apiClient<ChannelLink[]>("/api/v1/channels/links", accessToken, undefined)
}

export async function fetchOutbox(
  accessToken: string,
  status?: string,
): Promise<ChannelOutbox[]> {
  const params: Record<string, string> = { limit: "100" }
  if (status && status !== "all") {
    params.status = status
  }
  return apiClient<ChannelOutbox[]>("/api/v1/channels/outbox", accessToken, { params })
}

export async function fetchProviderCredential(
  accessToken: string,
  provider: ProviderName,
): Promise<ProviderCredentialResponse> {
  return apiClient<ProviderCredentialResponse>(
    `/api/v1/channels/providers/${provider}/credentials`,
    accessToken,
    undefined,
  )
}

// --- Mutation functions ---

export async function createChannelLink(
  accessToken: string,
  data: CreateChannelLinkRequest,
): Promise<ChannelLink> {
  return apiClient<ChannelLink>("/api/v1/channels/links", accessToken, {
    method: "POST",
    body: JSON.stringify(data),
  })
}

export async function deleteChannelLink(accessToken: string, id: string): Promise<void> {
  return apiClient<void>(`/api/v1/channels/links/${id}`, accessToken, {
    method: "DELETE",
  })
}

export async function requeueOutboxJob(accessToken: string, id: string): Promise<void> {
  return apiClient<void>(`/api/v1/channels/outbox/${id}/requeue`, accessToken, {
    method: "POST",
  })
}

export async function upsertProviderCredential(
  accessToken: string,
  provider: ProviderName,
  data: UpsertProviderCredentialRequest,
): Promise<ProviderCredentialResponse> {
  return apiClient<ProviderCredentialResponse>(
    `/api/v1/channels/providers/${provider}/credentials`,
    accessToken,
    { method: "PUT", body: JSON.stringify(data) },
  )
}

export async function deleteProviderCredential(
  accessToken: string,
  provider: ProviderName,
): Promise<void> {
  return apiClient<void>(
    `/api/v1/channels/providers/${provider}/credentials`,
    accessToken,
    { method: "DELETE" },
  )
}

// --- Query hooks ---

export function useChannelLinksQuery() {
  const { data: session } = useSession()
  return useQuery({
    queryKey: channelKeys.links(),
    queryFn: () => fetchChannelLinks(session!.accessToken),
    enabled: !!session?.accessToken,
    staleTime: 30_000,
  })
}

export function useOutboxQuery(status?: string) {
  const { data: session } = useSession()
  return useQuery({
    queryKey: channelKeys.outbox(status),
    queryFn: () => fetchOutbox(session!.accessToken, status),
    enabled: !!session?.accessToken,
    refetchInterval: status === "pending" || status === "sending" ? 10_000 : undefined,
    placeholderData: keepPreviousData,
  })
}

export function useProviderCredentialQuery(provider: ProviderName) {
  const { data: session } = useSession()
  return useQuery({
    queryKey: channelKeys.provider(provider),
    queryFn: () => fetchProviderCredential(session!.accessToken, provider),
    enabled: !!session?.accessToken,
    retry: false,
  })
}

// --- Mutation hooks ---

export function useCreateChannelLinkMutation() {
  const { data: session } = useSession()
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (data: CreateChannelLinkRequest) =>
      createChannelLink(session!.accessToken, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: channelKeys.links() })
    },
  })
}

export function useDeleteChannelLinkMutation() {
  const { data: session } = useSession()
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => deleteChannelLink(session!.accessToken, id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: channelKeys.links() })
    },
  })
}

export function useRequeueOutboxMutation() {
  const { data: session } = useSession()
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (id: string) => requeueOutboxJob(session!.accessToken, id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: channelKeys.all })
    },
  })
}

export function useUpsertProviderCredentialMutation(provider: ProviderName) {
  const { data: session } = useSession()
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (data: UpsertProviderCredentialRequest) =>
      upsertProviderCredential(session!.accessToken, provider, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: channelKeys.provider(provider) })
    },
  })
}

export function useDeleteProviderCredentialMutation(provider: ProviderName) {
  const { data: session } = useSession()
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: () => deleteProviderCredential(session!.accessToken, provider),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: channelKeys.provider(provider) })
    },
  })
}
