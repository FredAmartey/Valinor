import { ChannelsView } from "@/components/channels/channels-view"
import type { ChannelPermissions } from "@/components/channels/channels-view"

const READ_ONLY_PERMISSIONS: ChannelPermissions = {
  canWriteLinks: false,
  canReadProviders: true,
  canWriteProviders: false,
  canReadOutbox: true,
  canWriteOutbox: false,
}

export default async function TenantChannelsPage({
  params,
}: {
  params: Promise<{ id: string }>
}) {
  const { id } = await params

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight text-zinc-900">Channels</h1>
        <p className="mt-1 text-sm text-zinc-500">Channel links and providers for this tenant.</p>
      </div>
      <ChannelsView permissions={READ_ONLY_PERMISSIONS} tenantId={id} />
    </div>
  )
}
