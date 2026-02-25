import { ProvisionAgentForm } from "@/components/agents/provision-agent-form"

export default function NewAgentPage() {
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
