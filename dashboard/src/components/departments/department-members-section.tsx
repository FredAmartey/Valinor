"use client"

import { useState } from "react"
import Link from "next/link"
import { useUsersQuery } from "@/lib/queries/users"
import { UserStatusBadge } from "@/components/users/user-status-badge"
import { Skeleton } from "@/components/ui/skeleton"

interface DepartmentMembersSectionProps {
  departmentId: string
}

export function DepartmentMembersSection({ departmentId }: DepartmentMembersSectionProps) {
  const { data: allUsers, isLoading } = useUsersQuery()

  if (isLoading) {
    return <Skeleton className="h-32 w-full" />
  }

  return (
    <div>
      <h2 className="mb-3 text-sm font-medium text-zinc-900">Members</h2>
      {!allUsers || allUsers.length === 0 ? (
        <p className="text-sm text-zinc-500">No users in this organization yet.</p>
      ) : (
        <div className="space-y-2">
          {allUsers.map((user) => (
            <div
              key={user.id}
              className="flex items-center justify-between rounded-lg border border-zinc-200 bg-white px-3 py-2"
            >
              <Link href={`/users/${user.id}`} className="flex items-center gap-3 hover:underline">
                <span className="text-sm font-medium text-zinc-900">
                  {user.display_name || user.email}
                </span>
                <span className="text-xs text-zinc-400">{user.email}</span>
              </Link>
              <UserStatusBadge status={user.status as "active" | "suspended"} />
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
