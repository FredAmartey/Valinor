"use client"

import { useState, useDeferredValue, useCallback } from "react"
import { keepPreviousData } from "@tanstack/react-query"
import { useAuditEventsQuery } from "@/lib/queries/audit"
import { formatTimeAgo, formatDate, truncateId } from "@/lib/format"
import { Input } from "@/components/ui/input"
import { Skeleton } from "@/components/ui/skeleton"
import {
  MagnifyingGlass,
  CaretDown,
  CaretUp,
  Copy,
  Check,
  ArrowLeft,
  ArrowRight,
  ArrowCounterClockwise,
} from "@phosphor-icons/react"
import type { AuditEvent, AuditFilters } from "@/lib/types"
import {
  getActionLabel,
  getCategoryColor,
  SOURCE_LABELS,
  ACTION_CATEGORIES,
  RESOURCE_TYPES,
  SOURCES,
} from "./audit-labels"

const PAGE_SIZE = 50

export function AuditLog() {
  const [actionCategory, setActionCategory] = useState("")
  const [resourceType, setResourceType] = useState("")
  const [sourceFilter, setSourceFilter] = useState("")
  const [dateFrom, setDateFrom] = useState("")
  const [dateTo, setDateTo] = useState("")
  const [search, setSearch] = useState("")
  const deferredSearch = useDeferredValue(search)
  const [expandedId, setExpandedId] = useState<string | null>(null)
  const [cursor, setCursor] = useState<{ after?: string; before?: string }>({})

  const filters: AuditFilters = {
    ...(actionCategory ? { action: actionCategory } : {}),
    ...(resourceType ? { resource_type: resourceType } : {}),
    ...(sourceFilter ? { source: sourceFilter } : {}),
    ...(dateFrom ? { after: new Date(dateFrom).toISOString() } : {}),
    ...(dateTo ? { before: new Date(dateTo + "T23:59:59Z").toISOString() } : {}),
    ...cursor,
    limit: String(PAGE_SIZE),
  }

  const { data, isLoading, isError, refetch } = useAuditEventsQuery(filters)
  const events = data?.events ?? []

  const filtered = deferredSearch
    ? events.filter(
        (e) =>
          e.action.toLowerCase().includes(deferredSearch.toLowerCase()) ||
          (e.resource_id ?? "").toLowerCase().includes(deferredSearch.toLowerCase()) ||
          (e.user_id ?? "").toLowerCase().includes(deferredSearch.toLowerCase()),
      )
    : events

  const hasFilters = actionCategory || resourceType || sourceFilter || search || dateFrom || dateTo
  const clearFilters = () => {
    setActionCategory("")
    setResourceType("")
    setSourceFilter("")
    setDateFrom("")
    setDateTo("")
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
      <div className="rounded-xl border border-rose-200 bg-rose-50 p-4 flex items-center justify-between">
        <p className="text-sm text-rose-700">Failed to load audit events.</p>
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
          value={actionCategory}
          onChange={(e) => { setActionCategory(e.target.value); setCursor({}) }}
        >
          {ACTION_CATEGORIES.map((a) => (
            <option key={a.value} value={a.value}>{a.label}</option>
          ))}
        </select>
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
        <input
          type="date"
          value={dateFrom}
          onChange={(e) => { setDateFrom(e.target.value); setCursor({}) }}
          className="rounded-lg border border-zinc-200 bg-white px-3 py-2 text-sm text-zinc-900"
          aria-label="From date"
        />
        <input
          type="date"
          value={dateTo}
          onChange={(e) => { setDateTo(e.target.value); setCursor({}) }}
          className="rounded-lg border border-zinc-200 bg-white px-3 py-2 text-sm text-zinc-900"
          aria-label="To date"
        />
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
          <div role="table" aria-label="Audit events" className="divide-y divide-zinc-100 rounded-xl border border-zinc-200 bg-white">
            {/* Header */}
            <div role="row" className="grid grid-cols-[140px_1fr_1fr_1fr_100px] gap-4 px-4 py-2 text-xs font-medium uppercase tracking-wider text-zinc-400">
              <span role="columnheader">Time</span>
              <span role="columnheader">Action</span>
              <span role="columnheader">Resource</span>
              <span role="columnheader">Actor</span>
              <span role="columnheader">Source</span>
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
                  onClick={() => setCursor({ after: events[0]?.created_at })}
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
  const detailId = `audit-detail-${event.id}`

  return (
    <div role="row">
      <button
        onClick={onToggle}
        aria-expanded={expanded}
        aria-controls={detailId}
        className="grid w-full grid-cols-[140px_1fr_1fr_1fr_100px] gap-4 px-4 py-3 text-left text-sm hover:bg-zinc-50 transition-colors"
      >
        <span role="cell" className="text-zinc-500" title={formatDate(event.created_at, "long")}>
          {formatTimeAgo(event.created_at)}
        </span>
        <span role="cell" className="flex items-center gap-2">
          <span className={`inline-block h-2 w-2 rounded-full ${categoryColor}`} />
          <span className="text-zinc-900">{actionLabel.label}</span>
        </span>
        <span role="cell" className="text-zinc-600">
          {event.resource_type ?? "\u2014"}
          {event.resource_id && (
            <span className="ml-1 font-mono text-xs text-zinc-400">
              {truncateId(event.resource_id)}
            </span>
          )}
        </span>
        <span role="cell" className="font-mono text-xs text-zinc-500">
          {event.user_id ? truncateId(event.user_id) : "System"}
        </span>
        <span role="cell" className="flex items-center justify-between">
          <span className="rounded-full bg-zinc-100 px-2 py-0.5 text-xs font-medium text-zinc-600">
            {SOURCE_LABELS[event.source] ?? event.source}
          </span>
          {expanded ? <CaretUp size={14} className="text-zinc-400" /> : <CaretDown size={14} className="text-zinc-400" />}
        </span>
      </button>
      {expanded && (
        <div id={detailId} role="region" aria-label={`Details for ${actionLabel.label}`}>
          <AuditRowDetail event={event} />
        </div>
      )}
    </div>
  )
}

function AuditRowDetail({ event }: { event: AuditEvent }) {
  return (
    <div className="border-t border-zinc-100 bg-zinc-50 px-4 py-3">
      <div className="grid grid-cols-2 gap-x-8 gap-y-2 text-sm">
        <CopyableField label="Event ID" value={event.id} />
        {event.resource_id && (
          <CopyableField label="Resource ID" value={event.resource_id} />
        )}
        {event.user_id && (
          <CopyableField label="Actor ID" value={event.user_id} />
        )}
        <DetailField label="Timestamp" value={formatDate(event.created_at, "long")} />
        {event.metadata && Object.keys(event.metadata).length > 0 && (
          <div className="col-span-2 mt-2">
            <span className="text-xs font-medium uppercase tracking-wider text-zinc-400">Metadata</span>
            <div className="mt-1 space-y-1">
              {Object.entries(event.metadata).map(([key, value]) => (
                <div key={String(key)} className="flex gap-2 text-sm">
                  <span className="font-mono text-zinc-500">{String(key)}:</span>
                  <span className="font-mono text-zinc-700 break-all">
                    {String(typeof value === "object" && value !== null ? JSON.stringify(value) : value)}
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

function CopyableField({ label, value }: { label: string; value: string }) {
  const [copied, setCopied] = useState(false)

  const handleCopy = useCallback(() => {
    navigator.clipboard.writeText(value).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    })
  }, [value])

  return (
    <div>
      <span className="text-xs font-medium uppercase tracking-wider text-zinc-400">{label}</span>
      <div className="flex items-center gap-1.5 mt-0.5">
        <span className="font-mono text-sm text-zinc-700">{value}</span>
        <button
          onClick={handleCopy}
          className="rounded p-0.5 text-zinc-400 hover:text-zinc-600 transition-colors"
          title={copied ? "Copied" : "Copy"}
        >
          {copied ? <Check size={12} className="text-emerald-500" /> : <Copy size={12} />}
        </button>
      </div>
    </div>
  )
}

function DetailField({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <span className="text-xs font-medium uppercase tracking-wider text-zinc-400">{label}</span>
      <div className="mt-0.5">
        <span className="font-mono text-sm text-zinc-700">{value}</span>
      </div>
    </div>
  )
}
