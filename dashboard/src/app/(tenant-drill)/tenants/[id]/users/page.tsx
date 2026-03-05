import { UserTable } from "@/components/users/user-table"

export default async function TenantUsersPage({
  params,
}: {
  params: Promise<{ id: string }>
}) {
  const { id } = await params

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight text-zinc-900">Users</h1>
        <p className="mt-1 text-sm text-zinc-500">Users in this tenant.</p>
      </div>
      <UserTable tenantId={id} readOnly basePath={`/tenants/${id}/users`} />
    </div>
  )
}
