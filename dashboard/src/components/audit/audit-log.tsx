"use client"

import { useState, useDeferredValue } from "react"
import { useAuditEventsQuery } from "@/lib/queries/audit"
import { formatTimeAgo, formatDate, truncateId } from "@/lib/format"
import { Input } from "@/components/ui/input"
import { Skeleton } from "@/components/ui/skeleton"
import { MagnifyingGlass, CaretDown, CaretUp, Copy, ArrowLeft, ArrowRight } from "@phosphor-icons/react"
import type { AuditEvent, AuditFilters } from "@/lib/types"
import {
  getActionLabel,
  getCategoryColor,
  SOURCE_LABELS,
  RESOURCE_TYPES,
  SOURCES,
} from "./audit-labels"

const PAGE_SIZE = 50

export function AuditLog() {
  const [actionFilter, setActionFilter] = useState("")
  const [resourceType, setResourceType] = useState("")
  const [sourceFilter, setSourceFilter] = useState("")
  const [search, setSearch] = useState("")
  const deferredSearch = useDeferredValue(search)
  const [expandedId, setExpandedId] = useState<string | null>(null)
  const [cursor, setCursor] = useState<{ after?: string; before?: string }>({})

  const filters: AuditFilters = {
    ...(actionFilter ? { action: actionFilter } : {}),
    ...(resourceType ? { resource_type: resourceType } : {}),
    ...(sourceFilter ? { source: sourceFilter } : {}),
    ...cursor,
    limit: String(PAGE_SIZE),
  }

  const { data, isLoading, isError } = useAuditEventsQuery(filters)
  const events = data?.events ?? []

  const filtered = deferredSearch
    ? events.filter(
        (e) =>
          e.action.toLowerCase().includes(deferredSearch.toLowerCase()) ||
          (e.resource_id ?? "").toLowerCase().includes(deferredSearch.toLowerCase()) ||
          (e.user_id ?? "").toLowerCase().includes(deferredSearch.toLowerCase()),
      )
    : events

  const hasFilters = actionFilter || resourceType || sourceFilter || search
  const clearFilters = () => {
    setActionFilter("")
    setResourceType("")
    setSourceFilter("")
    setSearch("")
    setCursor({})
  }

  if (isLoading) {
    return (
      <div className="space-y-4">
        <div className="flex gap-3">
          <Skeleton className="h-10 w-64" />
          <Skeleton className="h-10 w-36" />
          <Skeleton className="h-10 w-36" />
          <Skeleton className="h-10 w-36" />
        </div>
        <div className="divide-y divide-zinc-100 rounded-xl border border-zinc-200">
          {Array.from({ length: 6 }).map((_, i) => (
            <div key={i} className="flex items-center gap-4 px-4 py-3">
              <Skeleton className="h-4 w-20" />
              <Skeleton className="h-4 w-32" />
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
      <div className="rounded-xl border border-rose-200 bg-rose-50 p-4">
        <p className="text-sm text-rose-700">Failed to load audit events.</p>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      {/* Filter bar */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="relative max-w-xs flex-1">
          <MagnifyingGlass size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-zinc-400" />
          <Input
            placeholder="Search by ID..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-9"
          />
        </div>
        <select
          className="rounded-lg border border-zinc-200 bg-white px-3 py-2 text-sm text-zinc-900"
          value={resourceType}
          onChange={(e) => { setResourceType(e.target.value); setCursor({}) }}
        >
          {RESOURCE_TYPES.map((r) => (
            <option key={r.value} value={r.value}>{r.label}</option>
          ))}
        </select>
        <select
          className="rounded-lg border border-zinc-200 bg-white px-3 py-2 text-sm text-zinc-900"
          value={sourceFilter}
          onChange={(e) => { setSourceFilter(e.target.value); setCursor({}) }}
        >
          {SOURCES.map((s) => (
            <option key={s.value} value={s.value}>{s.label}</option>
          ))}
        </select>
        {hasFilters && (
          <button
            onClick={clearFilters}
            className="rounded-lg px-3 py-2 text-sm text-zinc-500 hover:text-zinc-900 transition-colors"
          >
            Clear filters
          </button>
        )}
      </div>

      {/* Table */}
      {filtered.length === 0 ? (
        <div className="py-12 text-center">
          <p className="text-sm font-medium text-zinc-900">
            {hasFilters ? "No events match your filters" : "No events recorded yet"}
          </p>
          <p className="mt-1 text-sm text-zinc-500">
            {hasFilters ? "Try adjusting your filters." : "Audit events will appear here as actions occur."}
          </p>
          {hasFilters && (
            <button
              onClick={clearFilters}
              className="mt-3 text-sm font-medium text-zinc-900 underline underline-offset-4 hover:text-zinc-700"
            >
              Clear filters
            </button>
          )}
        </div>
      ) : (
        <>
          <div className="divide-y divide-zinc-100 rounded-xl border border-zinc-200 bg-white">
            {/* Header */}
            <div className="grid grid-cols-[140px_1fr_1fr_1fr_100px] gap-4 px-4 py-2 text-xs font-medium uppercase tracking-wider text-zinc-400">
              <span>Time</span>
              <span>Action</span>
              <span>Resource</span>
              <span>Actor</span>
              <span>Source</span>
            </div>
            {filtered.map((event) => (
              <AuditRow
                key={event.id}
                event={event}
                expanded={expandedId === event.id}
                onToggle={() => setExpandedId(expandedId === event.id ? null : event.id)}
              />
            ))}
          </div>

          {/* Pagination */}
          <div className="flex items-center justify-between">
            <p className="text-sm text-zinc-500">
              {data?.count ?? 0} event{(data?.count ?? 0) !== 1 ? "s" : ""}
            </p>
            <div className="flex gap-2">
              {cursor.before && (
                <button
                  onClick={() => setCursor({})}
                  className="flex items-center gap-1 rounded-lg border border-zinc-200 px-3 py-1.5 text-sm text-zinc-700 hover:bg-zinc-50 transition-colors"
                >
                  <ArrowLeft size={14} /> Newer
                </button>
              )}
              {events.length === PAGE_SIZE && (
                <button
                  onClick={() => setCursor({ before: events[events.length - 1].created_at })}
                  className="flex items-center gap-1 rounded-lg border border-zinc-200 px-3 py-1.5 text-sm text-zinc-700 hover:bg-zinc-50 transition-colors"
                >
                  Older <ArrowRight size={14} />
                </button>
              )}
            </div>
          </div>
        </>
      )}
    </div>
  )
}

function AuditRow({
  event,
  expanded,
  onToggle,
}: {
  event: AuditEvent
  expanded: boolean
  onToggle: () => void
}) {
  const actionLabel = getActionLabel(event.action)
  const categoryColor = getCategoryColor(actionLabel.category)

  return (
    <div>
      <button
        onClick={onToggle}
        className="grid w-full grid-cols-[140px_1fr_1fr_1fr_100px] gap-4 px-4 py-3 text-left text-sm hover:bg-zinc-50 transition-colors"
      >
        <span className="text-zinc-500" title={formatDate(event.created_at, "long")}>
          {formatTimeAgo(event.created_at)}
        </span>
        <span className="flex items-center gap-2">
          <span className={`inline-block h-2 w-2 rounded-full ${categoryColor}`} />
          <span className="text-zinc-900">{actionLabel.label}</span>
        </span>
        <span className="text-zinc-600">
          {event.resource_type ?? "\u2014"}
          {event.resource_id && (
            <span className="ml-1 font-mono text-xs text-zinc-400">
              {truncateId(event.resource_id)}
            </span>
          )}
        </span>
        <span className="font-mono text-xs text-zinc-500">
          {event.user_id ? truncateId(event.user_id) : "System"}
        </span>
        <span className="flex items-center justify-between">
          <span className="rounded-full bg-zinc-100 px-2 py-0.5 text-xs font-medium text-zinc-600">
            {SOURCE_LABELS[event.source] ?? event.source}
          </span>
          {expanded ? <CaretUp size={14} className="text-zinc-400" /> : <CaretDown size={14} className="text-zinc-400" />}
        </span>
      </button>
      {expanded && <AuditRowDetail event={event} />}
    </div>
  )
}

function AuditRowDetail({ event }: { event: AuditEvent }) {
  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text)
  }

  return (
    <div className="border-t border-zinc-100 bg-zinc-50 px-4 py-3">
      <div className="grid grid-cols-2 gap-x-8 gap-y-2 text-sm">
        <DetailField label="Event ID" value={event.id} copyable onCopy={copyToClipboard} />
        {event.resource_id && (
          <DetailField label="Resource ID" value={event.resource_id} copyable onCopy={copyToClipboard} />
        )}
        {event.user_id && (
          <DetailField label="Actor ID" value={event.user_id} copyable onCopy={copyToClipboard} />
        )}
        <DetailField label="Timestamp" value={formatDate(event.created_at, "long")} />
        {event.metadata && Object.keys(event.metadata).length > 0 && (
          <div className="col-span-2 mt-2">
            <span className="text-xs font-medium uppercase tracking-wider text-zinc-400">Metadata</span>
            <div className="mt-1 space-y-1">
              {Object.entries(event.metadata).map(([key, value]) => (
                <div key={key} className="flex gap-2 text-sm">
                  <span className="font-mono text-zinc-500">{key}:</span>
                  <span className="font-mono text-zinc-700">
                    {typeof value === "string" ? value : JSON.stringify(value)}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

function DetailField({
  label,
  value,
  copyable,
  onCopy,
}: {
  label: string
  value: string
  copyable?: boolean
  onCopy?: (text: string) => void
}) {
  return (
    <div>
      <span className="text-xs font-medium uppercase tracking-wider text-zinc-400">{label}</span>
      <div className="flex items-center gap-1.5 mt-0.5">
        <span className="font-mono text-sm text-zinc-700">{value}</span>
        {copyable && onCopy && (
          <button
            onClick={() => onCopy(value)}
            className="rounded p-0.5 text-zinc-400 hover:text-zinc-600 transition-colors"
            title="Copy"
          >
            <Copy size={12} />
          </button>
        )}
      </div>
    </div>
  )
}
