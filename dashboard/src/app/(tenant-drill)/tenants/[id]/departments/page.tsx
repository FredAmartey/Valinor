import { DepartmentTable } from "@/components/departments/department-table"

export default async function TenantDepartmentsPage({
  params,
}: {
  params: Promise<{ id: string }>
}) {
  const { id } = await params

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight text-zinc-900">Departments</h1>
        <p className="mt-1 text-sm text-zinc-500">Departments in this tenant.</p>
      </div>
      <DepartmentTable tenantId={id} readOnly basePath={`/tenants/${id}/departments`} />
    </div>
  )
}
