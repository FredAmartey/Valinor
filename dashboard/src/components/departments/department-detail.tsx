"use client"

import { useDepartmentQuery, useDepartmentsQuery } from "@/lib/queries/departments"
import { DepartmentMembersSection } from "./department-members-section"
import { Skeleton } from "@/components/ui/skeleton"
import { formatDate } from "@/lib/format"
import Link from "next/link"

export function DepartmentDetail({ id }: { id: string }) {
  const { data: department, isLoading, isError } = useDepartmentQuery(id)
  const { data: allDepartments } = useDepartmentsQuery()

  if (isLoading) {
    return (
      <div className="space-y-6">
        <Skeleton className="h-12 w-72" />
        <Skeleton className="h-48 w-full rounded-xl" />
      </div>
    )
  }

  if (isError || !department) {
    return (
      <div className="rounded-xl border border-rose-200 bg-rose-50 p-4">
        <p className="text-sm text-rose-700">Failed to load department details.</p>
      </div>
    )
  }

  const parentName = department.parent_id
    ? allDepartments?.find((d) => d.id === department.parent_id)?.name
    : null

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight text-zinc-900">
          {department.name}
        </h1>
        <div className="mt-2 flex items-center gap-4 text-sm text-zinc-500">
          {parentName ? (
            <span>
              Parent:{" "}
              <Link href={`/departments/${department.parent_id}`} className="text-zinc-700 hover:underline">
                {parentName}
              </Link>
            </span>
          ) : (
            <span>Top-level department</span>
          )}
          <span>Created {formatDate(department.created_at, "long")}</span>
        </div>
      </div>

      <div className="rounded-xl border border-zinc-200 bg-white p-5">
        <DepartmentMembersSection departmentId={id} />
      </div>
    </div>
  )
}
