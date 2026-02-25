"use client"

import { useUserQuery } from "@/lib/queries/users"
import { UserStatusBadge } from "./user-status-badge"
import { UserDepartmentsSection } from "./user-departments-section"
import { UserRolesSection } from "./user-roles-section"
import { Skeleton } from "@/components/ui/skeleton"
import { formatDate } from "@/lib/format"

interface UserDetailProps {
  id: string
  tenantId: string
}

export function UserDetail({ id, tenantId }: UserDetailProps) {
  const { data: user, isLoading, isError } = useUserQuery(id)

  if (isLoading) {
    return (
      <div className="space-y-6">
        <Skeleton className="h-12 w-72" />
        <Skeleton className="h-32 w-full rounded-xl" />
        <Skeleton className="h-32 w-full rounded-xl" />
      </div>
    )
  }

  if (isError || !user) {
    return (
      <div className="rounded-xl border border-rose-200 bg-rose-50 p-4">
        <p className="text-sm text-rose-700">Failed to load user details.</p>
      </div>
    )
  }

  return (
    <div className="space-y-8">
      <div>
        <div className="flex items-center gap-3">
          <h1 className="text-2xl font-semibold tracking-tight text-zinc-900">
            {user.display_name || user.email}
          </h1>
          <UserStatusBadge status={user.status as "active" | "suspended"} />
        </div>
        <div className="mt-2 flex items-center gap-4 text-sm text-zinc-500">
          <span>{user.email}</span>
          <span>Created {formatDate(user.created_at, "long")}</span>
        </div>
      </div>

      <div className="grid grid-cols-1 gap-8 xl:grid-cols-2">
        <div className="rounded-xl border border-zinc-200 bg-white p-5">
          <UserDepartmentsSection userId={id} memberDepartmentIds={[]} />
        </div>
        <div className="rounded-xl border border-zinc-200 bg-white p-5">
          <UserRolesSection userId={id} tenantId={tenantId} />
        </div>
      </div>
    </div>
  )
}
