import { ConnectorsView } from "@/components/connectors/connectors-view"

export default async function TenantConnectorsPage({
  params,
}: {
  params: Promise<{ id: string }>
}) {
  const { id } = await params

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight text-zinc-900">Connectors</h1>
        <p className="mt-1 text-sm text-zinc-500">Connectors configured for this tenant.</p>
      </div>
      <ConnectorsView canWrite={false} tenantId={id} />
    </div>
  )
}
