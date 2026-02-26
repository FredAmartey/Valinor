import Link from "next/link"
import { auth } from "@/lib/auth"
import { hasPermission } from "@/lib/permissions"
import { DepartmentTable } from "@/components/departments/department-table"
import { Plus } from "@phosphor-icons/react/dist/ssr"

export default async function DepartmentsPage() {
  const session = await auth()
  const canCreate = hasPermission(
    session?.user?.isPlatformAdmin ?? false,
    session?.user?.roles ?? [],
    "departments:write",
  )

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-zinc-900">Departments</h1>
          <p className="mt-1 text-sm text-zinc-500">Organize your team into departments.</p>
        </div>
        {canCreate && (
          <Link
            href="/departments/new"
            className="flex items-center gap-2 rounded-lg bg-zinc-900 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-zinc-800 active:scale-[0.98]"
          >
            <Plus size={16} />
            Create department
          </Link>
        )}
      </div>
      <DepartmentTable />
    </div>
  )
}
