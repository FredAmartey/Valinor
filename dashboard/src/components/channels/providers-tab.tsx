"use client"

import { useState } from "react"
import {
  useProviderCredentialQuery,
  useUpsertProviderCredentialMutation,
  useDeleteProviderCredentialMutation,
} from "@/lib/queries/channels"
import { formatDate } from "@/lib/format"
import { Skeleton } from "@/components/ui/skeleton"
import {
  SlackLogo,
  WhatsappLogo,
  TelegramLogo,
  Check,
  Minus,
  PencilSimple,
  Trash,
  X,
} from "@phosphor-icons/react"
import type { ProviderCredentialResponse, UpsertProviderCredentialRequest } from "@/lib/types"
import { ApiError } from "@/lib/api-error"

type ProviderName = "slack" | "whatsapp" | "telegram"

interface ProviderConfig {
  name: ProviderName
  label: string
  icon: React.ReactNode
  fields: { key: keyof UpsertProviderCredentialRequest; label: string; type: "password" | "text" }[]
  secrets: { key: keyof ProviderCredentialResponse; label: string }[]
}

const PROVIDERS: ProviderConfig[] = [
  {
    name: "slack",
    label: "Slack",
    icon: <SlackLogo size={24} weight="fill" className="text-[#4A154B]" />,
    fields: [
      { key: "access_token", label: "Bot Token", type: "password" },
      { key: "signing_secret", label: "Signing Secret", type: "password" },
    ],
    secrets: [
      { key: "has_access_token", label: "Bot Token" },
      { key: "has_signing_secret", label: "Signing Secret" },
    ],
  },
  {
    name: "whatsapp",
    label: "WhatsApp",
    icon: <WhatsappLogo size={24} weight="fill" className="text-[#25D366]" />,
    fields: [
      { key: "access_token", label: "Access Token", type: "password" },
      { key: "signing_secret", label: "Signing Secret", type: "password" },
      { key: "phone_number_id", label: "Phone Number ID", type: "text" },
      { key: "api_base_url", label: "API Base URL", type: "text" },
      { key: "api_version", label: "API Version", type: "text" },
    ],
    secrets: [
      { key: "has_access_token", label: "Access Token" },
      { key: "has_signing_secret", label: "Signing Secret" },
    ],
  },
  {
    name: "telegram",
    label: "Telegram",
    icon: <TelegramLogo size={24} weight="fill" className="text-[#2AABEE]" />,
    fields: [
      { key: "access_token", label: "Bot Token", type: "password" },
      { key: "secret_token", label: "Webhook Secret", type: "password" },
    ],
    secrets: [
      { key: "has_access_token", label: "Bot Token" },
      { key: "has_secret_token", label: "Webhook Secret" },
    ],
  },
]

export function ProvidersTab({ canWrite }: { canWrite: boolean }) {
  return (
    <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
      {PROVIDERS.map((provider) => (
        <ProviderCard key={provider.name} config={provider} canWrite={canWrite} />
      ))}
    </div>
  )
}

function ProviderCard({ config, canWrite }: { config: ProviderConfig; canWrite: boolean }) {
  const { data, isLoading, isError, error } = useProviderCredentialQuery(config.name)
  const [editing, setEditing] = useState(false)

  const isNotConfigured = isError && error instanceof ApiError && error.status === 404

  if (isLoading) {
    return (
      <div className="rounded-xl border border-zinc-200 bg-white p-5 space-y-3">
        <div className="flex items-center gap-3">
          {config.icon}
          <Skeleton className="h-5 w-20" />
        </div>
        <Skeleton className="h-4 w-full" />
        <Skeleton className="h-4 w-2/3" />
      </div>
    )
  }

  if (isError && !isNotConfigured) {
    return (
      <div className="rounded-xl border border-rose-200 bg-rose-50 p-5">
        <div className="flex items-center gap-3">
          {config.icon}
          <span className="text-sm font-medium text-zinc-900">{config.label}</span>
        </div>
        <p className="mt-2 text-sm text-rose-600">Failed to load credentials.</p>
      </div>
    )
  }

  if (editing) {
    return (
      <EditProviderForm
        config={config}
        onClose={() => setEditing(false)}
      />
    )
  }

  if (isNotConfigured) {
    return (
      <div className="rounded-xl border border-dashed border-zinc-300 bg-zinc-50 p-5">
        <div className="flex items-center gap-3">
          {config.icon}
          <span className="text-sm font-medium text-zinc-900">{config.label}</span>
        </div>
        <p className="mt-2 text-sm text-zinc-500">Not configured</p>
        {canWrite && (
          <button
            onClick={() => setEditing(true)}
            className="mt-3 rounded-lg bg-zinc-900 px-3 py-1.5 text-sm font-medium text-white hover:bg-zinc-800 transition-colors active:scale-[0.98]"
          >
            Set up
          </button>
        )}
      </div>
    )
  }

  return (
    <ConfiguredProviderCard
      config={config}
      credential={data!}
      canWrite={canWrite}
      onEdit={() => setEditing(true)}
    />
  )
}

function ConfiguredProviderCard({
  config,
  credential,
  canWrite,
  onEdit,
}: {
  config: ProviderConfig
  credential: ProviderCredentialResponse
  canWrite: boolean
  onEdit: () => void
}) {
  const deleteMutation = useDeleteProviderCredentialMutation(config.name)

  const handleDelete = () => {
    if (!window.confirm(`Delete ${config.label} credentials? This cannot be undone.`)) return
    deleteMutation.mutate()
  }

  return (
    <div className="rounded-xl border border-zinc-200 bg-white p-5 space-y-3">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          {config.icon}
          <span className="text-sm font-medium text-zinc-900">{config.label}</span>
        </div>
        {canWrite && (
          <div className="flex gap-1">
            <button
              onClick={onEdit}
              className="rounded p-1.5 text-zinc-400 hover:text-zinc-700 transition-colors"
              title="Edit credentials"
            >
              <PencilSimple size={16} />
            </button>
            <button
              onClick={handleDelete}
              disabled={deleteMutation.isPending}
              className="rounded p-1.5 text-zinc-400 hover:text-rose-600 transition-colors disabled:opacity-50"
              title="Delete credentials"
            >
              <Trash size={16} />
            </button>
          </div>
        )}
      </div>

      {/* Secret status indicators */}
      <div className="space-y-1.5">
        {config.secrets.map(({ key, label }) => {
          const hasValue = credential[key] as boolean
          return (
            <div key={key} className="flex items-center gap-2 text-sm">
              {hasValue ? (
                <Check size={14} weight="bold" className="text-emerald-500" />
              ) : (
                <Minus size={14} className="text-zinc-300" />
              )}
              <span className={hasValue ? "text-zinc-700" : "text-zinc-400"}>{label}</span>
            </div>
          )
        })}
      </div>

      {/* Metadata */}
      {credential.api_base_url && (
        <div className="text-xs text-zinc-500">
          <span className="font-medium">API:</span> {credential.api_base_url}
          {credential.api_version && ` (${credential.api_version})`}
        </div>
      )}
      {credential.phone_number_id && (
        <div className="text-xs text-zinc-500">
          <span className="font-medium">Phone:</span> {credential.phone_number_id}
        </div>
      )}

      <div className="text-xs text-zinc-400">
        Updated {formatDate(credential.updated_at, "short")}
      </div>
    </div>
  )
}

function EditProviderForm({
  config,
  onClose,
}: {
  config: ProviderConfig
  onClose: () => void
}) {
  const mutation = useUpsertProviderCredentialMutation(config.name)
  const [form, setForm] = useState<UpsertProviderCredentialRequest>({})

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    // Only send fields that have values
    const payload: UpsertProviderCredentialRequest = {}
    for (const [key, value] of Object.entries(form)) {
      if (value) {
        ;(payload as Record<string, string>)[key] = value
      }
    }
    mutation.mutate(payload, {
      onSuccess: () => onClose(),
    })
  }

  return (
    <form
      onSubmit={handleSubmit}
      className="rounded-xl border border-zinc-200 bg-white p-5 space-y-3"
    >
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          {config.icon}
          <span className="text-sm font-medium text-zinc-900">{config.label}</span>
        </div>
        <button
          type="button"
          onClick={onClose}
          className="rounded p-1 text-zinc-400 hover:text-zinc-700 transition-colors"
        >
          <X size={16} />
        </button>
      </div>

      <div className="space-y-2">
        {config.fields.map(({ key, label, type }) => (
          <div key={key}>
            <label className="mb-1 block text-xs font-medium text-zinc-500">{label}</label>
            <input
              type={type}
              value={(form[key] as string) ?? ""}
              onChange={(e) => setForm({ ...form, [key]: e.target.value })}
              className="w-full rounded-lg border border-zinc-200 px-3 py-2 text-sm text-zinc-900 placeholder:text-zinc-400"
              placeholder="Enter new value to update"
              autoComplete="off"
            />
          </div>
        ))}
      </div>

      <div className="flex justify-end gap-2">
        <button
          type="button"
          onClick={onClose}
          className="rounded-lg border border-zinc-200 px-3 py-1.5 text-sm text-zinc-700 hover:bg-zinc-50 transition-colors"
        >
          Cancel
        </button>
        <button
          type="submit"
          disabled={mutation.isPending}
          className="rounded-lg bg-zinc-900 px-3 py-1.5 text-sm font-medium text-white hover:bg-zinc-800 transition-colors active:scale-[0.98] disabled:opacity-50"
        >
          {mutation.isPending ? "Saving..." : "Save"}
        </button>
      </div>
      {mutation.isError && (
        <p className="text-sm text-rose-600">Failed to save credentials.</p>
      )}
    </form>
  )
}
