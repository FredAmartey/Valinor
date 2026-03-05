import { AuditLog } from "@/components/audit/audit-log"

export default async function TenantAuditPage({
  params,
}: {
  params: Promise<{ id: string }>
}) {
  const { id } = await params

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight text-zinc-900">Audit Log</h1>
        <p className="mt-1 text-sm text-zinc-500">Audit events for this tenant.</p>
      </div>
      <AuditLog tenantId={id} />
    </div>
  )
}
