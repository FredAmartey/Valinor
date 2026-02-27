"use client"

import { useState } from "react"
import {
  useConnectorsQuery,
  useCreateConnectorMutation,
  useDeleteConnectorMutation,
} from "@/lib/queries/connectors"
import { formatTimeAgo, formatDate } from "@/lib/format"
import { Skeleton } from "@/components/ui/skeleton"
import { Plus, Trash, ArrowCounterClockwise } from "@phosphor-icons/react"
import { ApiError } from "@/lib/api-error"
import type { Connector, CreateConnectorRequest } from "@/lib/types"

const STATUS_PILL: Record<string, string> = {
  active: "bg-emerald-50 text-emerald-700",
  inactive: "bg-zinc-100 text-zinc-500",
}

export function ConnectorsView({ canWrite }: { canWrite: boolean }) {
  const [showCreate, setShowCreate] = useState(false)
  const { data: connectors, isLoading, isError, refetch } = useConnectorsQuery()
  const deleteMutation = useDeleteConnectorMutation()

  const handleDelete = (connector: Connector) => {
    if (!window.confirm(`Delete connector "${connector.name}"? This cannot be undone.`)) return
    deleteMutation.mutate(connector.id)
  }

  const deleteError = deleteMutation.isError
    ? (deleteMutation.error instanceof ApiError ? deleteMutation.error.body?.error : null) ??
      "Failed to delete connector."
    : null

  if (isLoading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-10 w-40" />
        <div className="divide-y divide-zinc-100 rounded-xl border border-zinc-200">
          {Array.from({ length: 3 }).map((_, i) => (
            <div key={i} className="flex items-center gap-4 px-4 py-3">
              <Skeleton className="h-4 w-32" />
              <Skeleton className="h-4 w-48" />
              <Skeleton className="h-4 w-16" />
              <Skeleton className="h-4 w-20" />
            </div>
          ))}
        </div>
      </div>
    )
  }

  if (isError) {
    return (
      <div className="flex items-center justify-between rounded-xl border border-rose-200 bg-rose-50 p-4">
        <p className="text-sm text-rose-700">Failed to load connectors.</p>
        <button
          onClick={() => refetch()}
          className="flex items-center gap-1.5 rounded-lg bg-rose-100 px-3 py-1.5 text-sm font-medium text-rose-700 hover:bg-rose-200 transition-colors"
        >
          <ArrowCounterClockwise size={14} />
          Retry
        </button>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      {/* Toolbar */}
      <div className="flex items-center">
        <div className="flex-1" />
        {canWrite && (
          <button
            onClick={() => setShowCreate(true)}
            className="flex items-center gap-1.5 rounded-lg bg-zinc-900 px-3 py-2 text-sm font-medium text-white hover:bg-zinc-800 transition-colors active:scale-[0.98]"
          >
            <Plus size={14} weight="bold" />
            Register connector
          </button>
        )}
      </div>

      {/* Create form */}
      {showCreate && (
        <CreateConnectorForm onClose={() => setShowCreate(false)} />
      )}

      {/* Delete error */}
      {deleteError && (
        <p className="text-sm text-rose-600">{deleteError}</p>
      )}

      {/* List */}
      {(connectors ?? []).length === 0 ? (
        <div className="py-12 text-center">
          <p className="text-sm font-medium text-zinc-900">No connectors registered</p>
          <p className="mt-1 text-sm text-zinc-500">
            Register an MCP connector to make tools available to agents.
          </p>
        </div>
      ) : (
        <div
          role="table"
          aria-label="Connectors"
          className="divide-y divide-zinc-100 rounded-xl border border-zinc-200 bg-white"
        >
          <div
            role="row"
            className="grid grid-cols-[1fr_1fr_120px_100px_60px] gap-4 px-4 py-2 text-xs font-medium uppercase tracking-wider text-zinc-400"
          >
            <span role="columnheader">Name</span>
            <span role="columnheader">Endpoint</span>
            <span role="columnheader">Status</span>
            <span role="columnheader">Created</span>
            <span role="columnheader" className="text-right">Actions</span>
          </div>
          {(connectors ?? []).map((connector) => (
            <div
              key={connector.id}
              role="row"
              className="grid grid-cols-[1fr_1fr_120px_100px_60px] gap-4 px-4 py-3 text-sm hover:bg-zinc-50 transition-colors"
            >
              <span role="cell" className="self-center">
                <span className="font-medium text-zinc-900">{connector.name}</span>
                {connector.tools.length > 0 && (
                  <span className="ml-2 text-xs text-zinc-400">
                    {connector.tools.length} tool{connector.tools.length !== 1 ? "s" : ""}
                  </span>
                )}
              </span>
              <span
                role="cell"
                className="self-center truncate font-mono text-xs text-zinc-500"
                title={connector.endpoint}
              >
                {connector.endpoint}
              </span>
              <span role="cell" className="self-center">
                <span
                  className={`inline-block rounded-full px-2 py-0.5 text-xs font-medium ${STATUS_PILL[connector.status] ?? "bg-zinc-100 text-zinc-500"}`}
                >
                  {connector.status}
                </span>
              </span>
              <span
                role="cell"
                className="self-center text-zinc-500"
                title={formatDate(connector.created_at, "long")}
              >
                {formatTimeAgo(connector.created_at)}
              </span>
              <span role="cell" className="flex justify-end self-center">
                {canWrite && (
                  <button
                    onClick={() => handleDelete(connector)}
                    disabled={deleteMutation.isPending}
                    className="rounded p-1 text-zinc-400 hover:text-rose-600 transition-colors disabled:opacity-50"
                    title="Delete connector"
                  >
                    <Trash size={16} />
                  </button>
                )}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function CreateConnectorForm({ onClose }: { onClose: () => void }) {
  const mutation = useCreateConnectorMutation()
  const [form, setForm] = useState({
    name: "",
    endpoint: "",
    tools: "",
    auth_config: "",
  })
  const [jsonError, setJsonError] = useState<string | null>(null)

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    setJsonError(null)
    const payload: CreateConnectorRequest = {
      name: form.name.trim(),
      endpoint: form.endpoint.trim(),
      tools: form.tools
        .split(",")
        .map((t) => t.trim())
        .filter(Boolean),
    }
    if (form.auth_config.trim()) {
      try {
        payload.auth_config = JSON.parse(form.auth_config)
      } catch {
        setJsonError("Invalid JSON in auth config.")
        return
      }
    }
    mutation.mutate(payload, {
      onSuccess: () => onClose(),
    })
  }

  const errorMessage = mutation.isError
    ? (mutation.error instanceof ApiError ? mutation.error.body?.error : null) ??
      "Failed to register connector."
    : null

  return (
    <form
      onSubmit={handleSubmit}
      className="rounded-xl border border-zinc-200 bg-white p-4 space-y-3"
    >
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-medium text-zinc-900">Register connector</h3>
        <button
          type="button"
          onClick={onClose}
          className="text-sm text-zinc-500 hover:text-zinc-700 transition-colors"
        >
          Cancel
        </button>
      </div>
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
        <div>
          <label className="mb-1 block text-xs font-medium text-zinc-500">Name</label>
          <input
            type="text"
            required
            value={form.name}
            onChange={(e) => setForm({ ...form, name: e.target.value })}
            className="w-full rounded-lg border border-zinc-200 px-3 py-2 text-sm text-zinc-900 placeholder:text-zinc-400"
            placeholder="e.g. marcelo-scouting"
          />
        </div>
        <div>
          <label className="mb-1 block text-xs font-medium text-zinc-500">Endpoint</label>
          <input
            type="url"
            required
            value={form.endpoint}
            onChange={(e) => setForm({ ...form, endpoint: e.target.value })}
            className="w-full rounded-lg border border-zinc-200 px-3 py-2 text-sm text-zinc-900 placeholder:text-zinc-400"
            placeholder="https://api.example.com/mcp"
          />
        </div>
      </div>
      <div>
        <label className="mb-1 block text-xs font-medium text-zinc-500">
          Tools <span className="text-zinc-400">(comma-separated, optional)</span>
        </label>
        <input
          type="text"
          value={form.tools}
          onChange={(e) => setForm({ ...form, tools: e.target.value })}
          className="w-full rounded-lg border border-zinc-200 px-3 py-2 text-sm text-zinc-900 placeholder:text-zinc-400"
          placeholder="search_players, get_report"
        />
      </div>
      <div>
        <label className="mb-1 block text-xs font-medium text-zinc-500">
          Auth config <span className="text-zinc-400">(JSON, optional)</span>
        </label>
        <textarea
          value={form.auth_config}
          onChange={(e) => setForm({ ...form, auth_config: e.target.value })}
          rows={2}
          className="w-full rounded-lg border border-zinc-200 px-3 py-2 font-mono text-xs text-zinc-900 placeholder:text-zinc-400"
          placeholder='{"type": "bearer", "token": "sk-..."}'
        />
      </div>
      <div className="flex justify-end">
        <button
          type="submit"
          disabled={mutation.isPending}
          className="rounded-lg bg-zinc-900 px-4 py-2 text-sm font-medium text-white hover:bg-zinc-800 transition-colors active:scale-[0.98] disabled:opacity-50"
        >
          {mutation.isPending ? "Registering..." : "Register"}
        </button>
      </div>
      {jsonError && <p className="text-sm text-rose-600">{jsonError}</p>}
      {errorMessage && <p className="text-sm text-rose-600">{errorMessage}</p>}
    </form>
  )
}
