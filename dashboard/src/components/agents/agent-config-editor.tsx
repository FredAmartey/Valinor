"use client"

import { useState } from "react"
import { useConfigureAgentMutation } from "@/lib/queries/agents"
import { Label } from "@/components/ui/label"

interface AgentConfigEditorProps {
  agentId: string
  currentConfig: Record<string, unknown>
  currentAllowlist: string[]
  onDone: () => void
}

export function AgentConfigEditor({
  agentId,
  currentConfig,
  currentAllowlist,
  onDone,
}: AgentConfigEditorProps) {
  const mutation = useConfigureAgentMutation(agentId)
  const [configJson, setConfigJson] = useState(JSON.stringify(currentConfig, null, 2))
  const [allowlist, setAllowlist] = useState(currentAllowlist.join(", "))
  const [jsonError, setJsonError] = useState("")

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setJsonError("")

    let parsedConfig: Record<string, unknown>
    try {
      parsedConfig = JSON.parse(configJson)
    } catch {
      setJsonError("Invalid JSON")
      return
    }

    const tools = allowlist
      .split(",")
      .map((t) => t.trim())
      .filter(Boolean)

    mutation.mutate(
      { config: parsedConfig, tool_allowlist: tools },
      { onSuccess: () => onDone() },
    )
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div className="space-y-2">
        <Label htmlFor="config">Config (JSON)</Label>
        <textarea
          id="config"
          value={configJson}
          onChange={(e) => setConfigJson(e.target.value)}
          rows={8}
          className="w-full rounded-lg border border-zinc-200 bg-white px-3 py-2 font-mono text-xs text-zinc-900 focus:border-zinc-400 focus:outline-none focus:ring-1 focus:ring-zinc-400"
        />
        {jsonError && <p className="text-xs text-rose-600">{jsonError}</p>}
      </div>

      <div className="space-y-2">
        <Label htmlFor="allowlist">Tool Allowlist (comma-separated)</Label>
        <input
          id="allowlist"
          value={allowlist}
          onChange={(e) => setAllowlist(e.target.value)}
          placeholder="tool1, tool2, tool3"
          className="w-full rounded-lg border border-zinc-200 bg-white px-3 py-2 text-sm text-zinc-900 focus:border-zinc-400 focus:outline-none focus:ring-1 focus:ring-zinc-400"
        />
        <p className="text-xs text-zinc-400">Leave empty for no restrictions.</p>
      </div>

      {mutation.isError && (
        <div className="rounded-lg border border-rose-200 bg-rose-50 px-3 py-2">
          <p className="text-sm text-rose-700">Failed to update config. It may violate the runtime policy.</p>
        </div>
      )}

      <div className="flex gap-2">
        <button
          type="submit"
          disabled={mutation.isPending}
          className="rounded-lg bg-zinc-900 px-3 py-1.5 text-sm font-medium text-white hover:bg-zinc-800 active:scale-[0.98] disabled:opacity-50"
        >
          {mutation.isPending ? "Saving..." : "Save config"}
        </button>
        <button
          type="button"
          onClick={onDone}
          className="rounded-lg px-3 py-1.5 text-sm text-zinc-500 hover:text-zinc-700"
        >
          Cancel
        </button>
      </div>
    </form>
  )
}
