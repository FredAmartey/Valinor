import { auth } from "@/lib/auth"
import { hasPermission } from "@/lib/permissions"
import { ConnectorsView } from "@/components/connectors/connectors-view"
import { Plugs } from "@phosphor-icons/react/dist/ssr"

export default async function ConnectorsPage() {
  const session = await auth()
  const isPlatformAdmin = session?.user?.isPlatformAdmin ?? false
  const roles = session?.user?.roles ?? []

  const canRead = hasPermission(isPlatformAdmin, roles, "connectors:read")

  if (!canRead) {
    return (
      <div className="py-12 text-center">
        <p className="text-sm font-medium text-zinc-900">Access denied</p>
        <p className="mt-1 text-sm text-zinc-500">You do not have permission to manage connectors.</p>
      </div>
    )
  }

  const canWrite = hasPermission(isPlatformAdmin, roles, "connectors:write")

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <Plugs size={24} className="text-zinc-400" />
        <div>
          <h1 className="text-2xl font-semibold tracking-tight text-zinc-900">Connectors</h1>
          <p className="mt-1 text-sm text-zinc-500">Manage MCP tool connectors available to agents.</p>
        </div>
      </div>
      <ConnectorsView canWrite={canWrite} />
    </div>
  )
}
