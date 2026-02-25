"use client"

import { useState, useDeferredValue } from "react"
import Link from "next/link"
import { useDepartmentsQuery } from "@/lib/queries/departments"
import { Input } from "@/components/ui/input"
import { Skeleton } from "@/components/ui/skeleton"
import { MagnifyingGlass } from "@phosphor-icons/react"
import { formatDate } from "@/lib/format"
import type { Department } from "@/lib/types"

interface HierarchyItem {
  department: Department
  depth: number
}

export function buildHierarchy(departments: Department[]): HierarchyItem[] {
  const childrenMap = new Map<string | null, Department[]>()
  for (const dept of departments) {
    const parentKey = dept.parent_id ?? null
    if (!childrenMap.has(parentKey)) {
      childrenMap.set(parentKey, [])
    }
    childrenMap.get(parentKey)!.push(dept)
  }

  const result: HierarchyItem[] = []
  const visited = new Set<string>()

  function walk(parentId: string | null, depth: number) {
    const children = childrenMap.get(parentId) ?? []
    for (const child of children) {
      if (visited.has(child.id)) continue
      visited.add(child.id)
      result.push({ department: child, depth: Math.min(depth, 4) })
      walk(child.id, depth + 1)
    }
  }
  walk(null, 0)
  return result
}

export function DepartmentTable() {
  const { data: departments, isLoading, isError } = useDepartmentsQuery()
  const [search, setSearch] = useState("")
  const deferredSearch = useDeferredValue(search)

  if (isLoading) {
    return (
      <div className="space-y-3">
        <Skeleton className="h-10 w-64" />
        {Array.from({ length: 5 }).map((_, i) => (
          <Skeleton key={i} className="h-14 w-full" />
        ))}
      </div>
    )
  }

  if (isError) {
    return (
      <div className="rounded-xl border border-rose-200 bg-rose-50 p-4">
        <p className="text-sm text-rose-700">Failed to load departments.</p>
      </div>
    )
  }

  if (!departments || departments.length === 0) {
    return (
      <div className="py-12 text-center">
        <p className="text-sm font-medium text-zinc-900">No departments yet</p>
        <p className="mt-1 text-sm text-zinc-500">Create your first department to organize your team.</p>
        <Link
          href="/departments/new"
          className="mt-4 inline-block rounded-lg bg-zinc-900 px-4 py-2 text-sm font-medium text-white hover:bg-zinc-800 transition-colors active:scale-[0.98]"
        >
          Create department
        </Link>
      </div>
    )
  }

  const hierarchy = buildHierarchy(departments)
  const filtered = deferredSearch
    ? hierarchy.filter((h) => h.department.name.toLowerCase().includes(deferredSearch.toLowerCase()))
    : hierarchy

  const parentNames = new Map(departments.map((d) => [d.id, d.name]))

  return (
    <div className="space-y-4">
      <div className="relative max-w-sm">
        <MagnifyingGlass size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-zinc-400" />
        <Input
          placeholder="Search departments..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="pl-9"
        />
      </div>

      <div className="rounded-xl border border-zinc-200 bg-white">
        <div className="grid grid-cols-[3fr_2fr_1fr] gap-4 border-b border-zinc-100 px-4 py-3 text-xs font-medium uppercase tracking-wider text-zinc-500">
          <span>Name</span>
          <span>Parent</span>
          <span>Created</span>
        </div>
        <div className="divide-y divide-zinc-100">
          {filtered.map(({ department, depth }) => (
            <Link
              key={department.id}
              href={`/departments/${department.id}`}
              className="grid grid-cols-[3fr_2fr_1fr] gap-4 px-4 py-3 text-sm transition-colors hover:bg-zinc-50"
            >
              <span
                className="font-medium text-zinc-900"
                style={{ paddingLeft: `${Math.min(depth, 4) * 1.5}rem` }}
              >
                {depth > 0 && (
                  <span className="mr-2 text-zinc-300">|</span>
                )}
                {department.name}
              </span>
              <span className="text-zinc-500">
                {department.parent_id ? parentNames.get(department.parent_id) ?? "\u2014" : "\u2014"}
              </span>
              <span className="text-zinc-500">{formatDate(department.created_at)}</span>
            </Link>
          ))}
        </div>
      </div>
    </div>
  )
}
