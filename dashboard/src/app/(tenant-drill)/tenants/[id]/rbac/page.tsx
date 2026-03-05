import { RBACView } from "@/components/rbac/rbac-view"

export default async function TenantRBACPage({
  params,
}: {
  params: Promise<{ id: string }>
}) {
  const { id } = await params

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight text-zinc-900">Roles &amp; Permissions</h1>
        <p className="mt-1 text-sm text-zinc-500">RBAC configuration for this tenant.</p>
      </div>
      <RBACView tenantId={id} readOnly />
    </div>
  )
}
