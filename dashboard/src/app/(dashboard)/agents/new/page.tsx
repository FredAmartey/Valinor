import { auth } from "@/lib/auth"
import { hasPermission } from "@/lib/permissions"
import { ProvisionAgentForm } from "@/components/agents/provision-agent-form"

export default async function NewAgentPage() {
  const session = await auth()
  if (!hasPermission(session?.user?.isPlatformAdmin ?? false, session?.user?.roles ?? [], "agents:write")) {
    return (
      <div className="rounded-xl border border-rose-200 bg-rose-50 p-6 max-w-lg">
        <h2 className="text-sm font-semibold text-rose-800">Permission denied</h2>
        <p className="mt-1 text-sm text-rose-700">
          You need the <span className="font-mono">agents:write</span> permission to provision agents.
        </p>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight text-zinc-900">Provision Agent</h1>
        <p className="mt-1 text-sm text-zinc-500">Start a new AI agent instance.</p>
      </div>
      <ProvisionAgentForm />
    </div>
  )
}
