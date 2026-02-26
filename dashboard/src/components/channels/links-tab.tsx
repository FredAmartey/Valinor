"use client"

import { useState } from "react"
import { useChannelLinksQuery, useCreateChannelLinkMutation, useDeleteChannelLinkMutation } from "@/lib/queries/channels"
import { formatTimeAgo, formatDate, truncateId } from "@/lib/format"
import { Skeleton } from "@/components/ui/skeleton"
import { Plus, Trash, ArrowCounterClockwise } from "@phosphor-icons/react"
import { PlatformIcon } from "./platform-icon"
import type { ChannelLink, CreateChannelLinkRequest } from "@/lib/types"
import { ApiError } from "@/lib/api-error"

const PLATFORMS = ["all", "slack", "whatsapp", "telegram"] as const
const STATES = ["all", "verified", "pending_verification", "revoked"] as const

const STATE_PILL: Record<string, string> = {
  verified: "bg-emerald-50 text-emerald-700",
  pending_verification: "bg-amber-50 text-amber-700",
  revoked: "bg-zinc-100 text-zinc-500",
}

export function LinksTab({ canWrite }: { canWrite: boolean }) {
  const [platformFilter, setPlatformFilter] = useState("all")
  const [stateFilter, setStateFilter] = useState("all")
  const [showCreate, setShowCreate] = useState(false)
  const { data: links, isLoading, isError, refetch } = useChannelLinksQuery()
  const deleteMutation = useDeleteChannelLinkMutation()

  const filtered = (links ?? []).filter((link) => {
    if (platformFilter !== "all" && link.platform !== platformFilter) return false
    if (stateFilter !== "all" && link.status !== stateFilter) return false
    return true
  })

  const handleRevoke = (link: ChannelLink) => {
    if (!window.confirm(`Revoke ${link.platform} link for ${truncateId(link.user_id)}?`)) return
    deleteMutation.mutate(link.id)
  }

  if (isLoading) {
    return (
      <div className="space-y-4">
        <div className="flex gap-3">
          <Skeleton className="h-10 w-36" />
          <Skeleton className="h-10 w-36" />
        </div>
        <div className="divide-y divide-zinc-100 rounded-xl border border-zinc-200">
          {Array.from({ length: 5 }).map((_, i) => (
            <div key={i} className="flex items-center gap-4 px-4 py-3">
              <Skeleton className="h-4 w-16" />
              <Skeleton className="h-4 w-24" />
              <Skeleton className="h-4 w-24" />
              <Skeleton className="h-4 w-20" />
              <Skeleton className="h-4 w-16" />
            </div>
          ))}
        </div>
      </div>
    )
  }

  if (isError) {
    return (
      <div className="flex items-center justify-between rounded-xl border border-rose-200 bg-rose-50 p-4">
        <p className="text-sm text-rose-700">Failed to load channel links.</p>
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
      <div className="flex flex-wrap items-center gap-3">
        <select
          aria-label="Filter by platform"
          className="rounded-lg border border-zinc-200 bg-white px-3 py-2 text-sm text-zinc-900"
          value={platformFilter}
          onChange={(e) => setPlatformFilter(e.target.value)}
        >
          {PLATFORMS.map((p) => (
            <option key={p} value={p}>
              {p === "all" ? "All platforms" : p.charAt(0).toUpperCase() + p.slice(1)}
            </option>
          ))}
        </select>
        <select
          aria-label="Filter by state"
          className="rounded-lg border border-zinc-200 bg-white px-3 py-2 text-sm text-zinc-900"
          value={stateFilter}
          onChange={(e) => setStateFilter(e.target.value)}
        >
          {STATES.map((s) => (
            <option key={s} value={s}>
              {s === "all" ? "All states" : s.replaceAll("_", " ")}
            </option>
          ))}
        </select>
        <div className="flex-1" />
        {canWrite && (
          <button
            onClick={() => setShowCreate(true)}
            className="flex items-center gap-1.5 rounded-lg bg-zinc-900 px-3 py-2 text-sm font-medium text-white hover:bg-zinc-800 transition-colors active:scale-[0.98]"
          >
            <Plus size={14} weight="bold" />
            Create link
          </button>
        )}
      </div>

      {/* Create dialog */}
      {showCreate && (
        <CreateLinkForm onClose={() => setShowCreate(false)} />
      )}

      {/* Table */}
      {filtered.length === 0 ? (
        <div className="py-12 text-center">
          <p className="text-sm font-medium text-zinc-900">No channel links</p>
          <p className="mt-1 text-sm text-zinc-500">
            Create a link to connect a user to a messaging platform.
          </p>
        </div>
      ) : (
        <div role="table" aria-label="Channel links" className="divide-y divide-zinc-100 rounded-xl border border-zinc-200 bg-white">
          <div role="row" className="grid grid-cols-[100px_1fr_1fr_120px_100px_60px] gap-4 px-4 py-2 text-xs font-medium uppercase tracking-wider text-zinc-400">
            <span role="columnheader">Platform</span>
            <span role="columnheader">Platform User</span>
            <span role="columnheader">User ID</span>
            <span role="columnheader">State</span>
            <span role="columnheader">Created</span>
            <span role="columnheader" className="text-right">Actions</span>
          </div>
          {filtered.map((link) => (
            <div
              key={link.id}
              role="row"
              className="grid grid-cols-[100px_1fr_1fr_120px_100px_60px] gap-4 px-4 py-3 text-sm hover:bg-zinc-50 transition-colors"
            >
              <span role="cell" className="flex items-center gap-2">
                <PlatformIcon platform={link.platform} />
                <span className="capitalize text-zinc-900">{link.platform}</span>
              </span>
              <span role="cell" className="font-mono text-xs text-zinc-600 self-center">
                {link.platform_user_id}
              </span>
              <span role="cell" className="font-mono text-xs text-zinc-500 self-center">
                {truncateId(link.user_id)}
              </span>
              <span role="cell" className="self-center">
                <span className={`inline-block rounded-full px-2 py-0.5 text-xs font-medium ${STATE_PILL[link.status] ?? "bg-zinc-100 text-zinc-500"}`}>
                  {link.status.replaceAll("_", " ")}
                </span>
              </span>
              <span role="cell" className="text-zinc-500 self-center" title={formatDate(link.created_at, "long")}>
                {formatTimeAgo(link.created_at)}
              </span>
              <span role="cell" className="flex justify-end self-center">
                {canWrite && link.status !== "revoked" && (
                  <button
                    onClick={() => handleRevoke(link)}
                    disabled={deleteMutation.isPending}
                    className="rounded p-1 text-zinc-400 hover:text-rose-600 transition-colors disabled:opacity-50"
                    title="Revoke link"
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

function CreateLinkForm({ onClose }: { onClose: () => void }) {
  const mutation = useCreateChannelLinkMutation()
  const [form, setForm] = useState<CreateChannelLinkRequest>({
    user_id: "",
    platform: "slack",
    platform_user_id: "",
  })

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    mutation.mutate(form, {
      onSuccess: () => onClose(),
    })
  }

  const errorMessage = mutation.isError
    ? (mutation.error instanceof ApiError ? mutation.error.body?.error : null) ?? "Failed to create link. Check your input and try again."
    : null

  return (
    <form
      onSubmit={handleSubmit}
      className="rounded-xl border border-zinc-200 bg-white p-4 space-y-3"
    >
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-medium text-zinc-900">Create channel link</h3>
        <button
          type="button"
          onClick={onClose}
          className="text-sm text-zinc-500 hover:text-zinc-700 transition-colors"
        >
          Cancel
        </button>
      </div>
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
        <div>
          <label className="mb-1 block text-xs font-medium text-zinc-500">User ID</label>
          <input
            type="text"
            required
            value={form.user_id}
            onChange={(e) => setForm({ ...form, user_id: e.target.value })}
            className="w-full rounded-lg border border-zinc-200 px-3 py-2 text-sm text-zinc-900 placeholder:text-zinc-400"
            placeholder="User UUID"
          />
        </div>
        <div>
          <label className="mb-1 block text-xs font-medium text-zinc-500">Platform</label>
          <select
            value={form.platform}
            onChange={(e) => setForm({ ...form, platform: e.target.value as CreateChannelLinkRequest["platform"] })}
            className="w-full rounded-lg border border-zinc-200 bg-white px-3 py-2 text-sm text-zinc-900"
          >
            <option value="slack">Slack</option>
            <option value="whatsapp">WhatsApp</option>
            <option value="telegram">Telegram</option>
          </select>
        </div>
        <div>
          <label className="mb-1 block text-xs font-medium text-zinc-500">Platform User ID</label>
          <input
            type="text"
            required
            value={form.platform_user_id}
            onChange={(e) => setForm({ ...form, platform_user_id: e.target.value })}
            className="w-full rounded-lg border border-zinc-200 px-3 py-2 text-sm text-zinc-900 placeholder:text-zinc-400"
            placeholder="e.g. U12345ABC"
          />
        </div>
      </div>
      <div className="flex justify-end">
        <button
          type="submit"
          disabled={mutation.isPending}
          className="rounded-lg bg-zinc-900 px-4 py-2 text-sm font-medium text-white hover:bg-zinc-800 transition-colors active:scale-[0.98] disabled:opacity-50"
        >
          {mutation.isPending ? "Creating..." : "Create"}
        </button>
      </div>
      {errorMessage && (
        <p className="text-sm text-rose-600">{errorMessage}</p>
      )}
    </form>
  )
}
