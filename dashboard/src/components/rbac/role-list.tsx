"use client"

import { useRolesQuery } from "@/lib/queries/roles"
import { ShieldCheck } from "@phosphor-icons/react"
import type { Role } from "@/lib/types"

interface RoleListProps {
  selectedId: string | null
  onSelect: (role: Role) => void
}

export function RoleList({ selectedId, onSelect }: RoleListProps) {
  const { data: roles, isLoading } = useRolesQuery()

  if (isLoading) {
    return (
      <div className="space-y-2">
        {Array.from({ length: 4 }).map((_, i) => (
          <div key={i} className="h-14 animate-pulse rounded-lg bg-zinc-100" />
        ))}
      </div>
    )
  }

  if (!roles?.length) {
    return (
      <div className="flex flex-col items-center justify-center py-12 text-zinc-400">
        <ShieldCheck size={32} />
        <p className="mt-2 text-sm">No roles found.</p>
      </div>
    )
  }

  return (
    <div className="space-y-1">
      {roles.map((role) => (
        <button
          key={role.id}
          onClick={() => onSelect(role)}
          className={`flex w-full items-center justify-between rounded-lg px-3 py-2.5 text-left text-sm transition-colors ${
            selectedId === role.id
              ? "bg-zinc-900 text-white"
              : "text-zinc-700 hover:bg-zinc-100"
          }`}
        >
          <div className="flex items-center gap-2">
            <span className="font-medium">{role.name}</span>
            {role.is_system && (
              <span className={`inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wider ${
                selectedId === role.id
                  ? "bg-zinc-700 text-zinc-300"
                  : "bg-zinc-200 text-zinc-500"
              }`}>
                System
              </span>
            )}
          </div>
          <span className={`text-xs ${
            selectedId === role.id ? "text-zinc-300" : "text-zinc-400"
          }`}>
            {role.permissions.includes("*") ? "All" : `${role.permissions.length} perms`}
          </span>
        </button>
      ))}
    </div>
  )
}
