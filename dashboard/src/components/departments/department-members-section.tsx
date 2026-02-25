"use client"

import Link from "next/link"

interface DepartmentMembersSectionProps {
  departmentId: string
}

export function DepartmentMembersSection({ departmentId }: DepartmentMembersSectionProps) {
  return (
    <div>
      <h2 className="mb-3 text-sm font-medium text-zinc-900">Members</h2>
      <div className="py-6 text-center">
        <p className="text-sm text-zinc-500">
          Department membership is managed from individual user pages.
        </p>
        <Link
          href="/users"
          className="mt-2 inline-block text-sm font-medium text-zinc-700 hover:text-zinc-900 transition-colors"
        >
          Go to Users
        </Link>
      </div>
    </div>
  )
}
