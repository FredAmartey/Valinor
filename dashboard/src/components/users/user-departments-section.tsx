"use client"

import { useState } from "react"
import Link from "next/link"
import {
  useAddUserToDepartmentMutation,
  useRemoveUserFromDepartmentMutation,
} from "@/lib/queries/users"
import { useDepartmentsQuery } from "@/lib/queries/departments"
import { Skeleton } from "@/components/ui/skeleton"
import { X, Plus } from "@phosphor-icons/react"

interface UserDepartmentsSectionProps {
  userId: string
  memberDepartmentIds: string[]
}

export function UserDepartmentsSection({ userId, memberDepartmentIds }: UserDepartmentsSectionProps) {
  const { data: allDepartments, isLoading } = useDepartmentsQuery()
  const addMutation = useAddUserToDepartmentMutation(userId)
  const removeMutation = useRemoveUserFromDepartmentMutation(userId)
  const [adding, setAdding] = useState(false)

  if (isLoading) {
    return <Skeleton className="h-24 w-full" />
  }

  const memberDepartments = allDepartments?.filter((d) =>
    memberDepartmentIds.includes(d.id),
  ) ?? []

  const availableDepartments = allDepartments?.filter(
    (d) => !memberDepartmentIds.includes(d.id),
  ) ?? []

  return (
    <div>
      <h2 className="mb-3 text-sm font-medium text-zinc-900">Departments</h2>
      {memberDepartments.length === 0 ? (
        <p className="text-sm text-zinc-500">Not a member of any department.</p>
      ) : (
        <div className="space-y-2">
          {memberDepartments.map((dept) => (
            <div
              key={dept.id}
              className="flex items-center justify-between rounded-lg border border-zinc-200 bg-white px-3 py-2"
            >
              <Link href={`/departments/${dept.id}`} className="text-sm font-medium text-zinc-900 hover:underline">
                {dept.name}
              </Link>
              <button
                onClick={() => removeMutation.mutate(dept.id)}
                disabled={removeMutation.isPending}
                className="rounded p-1 text-zinc-400 hover:bg-zinc-100 hover:text-zinc-600 transition-colors"
                aria-label={`Remove from ${dept.name}`}
              >
                <X size={14} />
              </button>
            </div>
          ))}
        </div>
      )}
      {adding ? (
        <div className="mt-3">
          <select
            className="w-full rounded-lg border border-zinc-200 bg-white px-3 py-2 text-sm text-zinc-900"
            defaultValue=""
            onChange={(e) => {
              if (e.target.value) {
                addMutation.mutate(e.target.value)
                setAdding(false)
              }
            }}
          >
            <option value="" disabled>Select a department...</option>
            {availableDepartments.map((d) => (
              <option key={d.id} value={d.id}>{d.name}</option>
            ))}
          </select>
        </div>
      ) : (
        <button
          onClick={() => setAdding(true)}
          disabled={availableDepartments.length === 0}
          className="mt-3 flex items-center gap-1.5 text-sm font-medium text-zinc-500 hover:text-zinc-700 transition-colors disabled:opacity-50"
        >
          <Plus size={14} />
          Add to department
        </button>
      )}
    </div>
  )
}
