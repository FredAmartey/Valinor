import { auth } from "@/lib/auth"
import { hasPermission } from "@/lib/permissions"
import { CreateDepartmentForm } from "@/components/departments/create-department-form"

export default async function NewDepartmentPage() {
  const session = await auth()
  if (!hasPermission(session?.user?.isPlatformAdmin ?? false, session?.user?.roles ?? [], "departments:write")) {
    return (
      <div className="rounded-xl border border-rose-200 bg-rose-50 p-6 max-w-lg">
        <h2 className="text-sm font-semibold text-rose-800">Permission denied</h2>
        <p className="mt-1 text-sm text-rose-700">
          You need the <span className="font-mono">departments:write</span> permission to create departments.
        </p>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight text-zinc-900">Create Department</h1>
        <p className="mt-1 text-sm text-zinc-500">Add a new department to your organization.</p>
      </div>
      <CreateDepartmentForm />
    </div>
  )
}
