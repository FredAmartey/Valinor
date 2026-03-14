"use client"

import { useSession } from "next-auth/react"
import { useState } from "react"
import { useRouter } from "next/navigation"
import { AuthCard } from "@/components/auth/auth-card"
import { apiClient } from "@/lib/api-client"

type APIError = {
  body?: {
    error?: string
  }
}

function getErrorMessage(err: unknown): string {
  if (typeof err !== "object" || err === null) return ""
  return ((err as APIError).body?.error ?? "").trim()
}

export default function TeamPage() {
  const { data: session, update } = useSession()
  const router = useRouter()
  const [mode, setMode] = useState<"create" | "join">("create")
  const [teamName, setTeamName] = useState("")
  const [inviteCode, setInviteCode] = useState("")
  const [error, setError] = useState("")
  const [loading, setLoading] = useState(false)

  if (session?.user?.tenantId) {
    router.push("/")
    return null
  }

  async function handleCreateTeam(e: React.FormEvent) {
    e.preventDefault()
    setError("")
    setLoading(true)

    try {
      await apiClient("/api/v1/tenants/self-service", {
        method: "POST",
        body: JSON.stringify({ name: teamName }),
      })

      await update()
      router.push("/")
      router.refresh()
    } catch (err) {
      setLoading(false)
      setError(getErrorMessage(err) || "Failed to create team. Please try again.")
    }
  }

  async function handleJoinTeam(e: React.FormEvent) {
    e.preventDefault()
    setError("")
    setLoading(true)

    try {
      await apiClient("/auth/invite/redeem", {
        method: "POST",
        body: JSON.stringify({ code: inviteCode }),
      })

      await update()
      router.push("/")
      router.refresh()
    } catch (err) {
      setLoading(false)
      const msg = getErrorMessage(err)
      if (msg.includes("expired")) {
        setError("This invite has expired. Ask your admin for a new one.")
      } else if (msg.includes("used")) {
        setError("This invite has already been used.")
      } else {
        setError(msg || "Invalid invite code.")
      }
    }
  }

  return (
    <AuthCard>
      <p className="text-center text-sm text-zinc-500">
        Almost there! Create a new team or join an existing one.
      </p>

      <div className="flex rounded-lg border border-zinc-200 p-1">
        <button
          type="button"
          onClick={() => { setMode("create"); setError("") }}
          className={`flex-1 rounded-md px-3 py-1.5 text-sm font-medium transition-colors ${
            mode === "create"
              ? "bg-zinc-900 text-white"
              : "text-zinc-600 hover:text-zinc-900"
          }`}
        >
          Create team
        </button>
        <button
          type="button"
          onClick={() => { setMode("join"); setError("") }}
          className={`flex-1 rounded-md px-3 py-1.5 text-sm font-medium transition-colors ${
            mode === "join"
              ? "bg-zinc-900 text-white"
              : "text-zinc-600 hover:text-zinc-900"
          }`}
        >
          Join team
        </button>
      </div>

      {mode === "create" && (
        <form onSubmit={handleCreateTeam} className="space-y-4">
          <div className="space-y-2">
            <label htmlFor="teamName" className="text-sm font-medium text-zinc-700">
              Team name
            </label>
            <input
              id="teamName"
              type="text"
              value={teamName}
              onChange={(e) => setTeamName(e.target.value)}
              placeholder="Acme Inc."
              required
              autoFocus
              className="w-full rounded-lg border border-zinc-200 bg-white px-3 py-2 text-sm text-zinc-900 placeholder:text-zinc-400 focus:border-zinc-400 focus:outline-none focus:ring-1 focus:ring-zinc-400"
            />
          </div>
          {error && (
            <div className="rounded-lg border border-rose-200 bg-rose-50 px-3 py-2">
              <p className="text-sm text-rose-700">{error}</p>
            </div>
          )}
          <button
            type="submit"
            disabled={loading || !teamName}
            className="w-full rounded-lg bg-zinc-900 px-4 py-2.5 text-sm font-medium text-white transition-colors hover:bg-zinc-800 active:scale-[0.98] disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {loading ? "Creating..." : "Create team"}
          </button>
        </form>
      )}

      {mode === "join" && (
        <form onSubmit={handleJoinTeam} className="space-y-4">
          <div className="space-y-2">
            <label htmlFor="inviteCode" className="text-sm font-medium text-zinc-700">
              Invite code
            </label>
            <input
              id="inviteCode"
              type="text"
              value={inviteCode}
              onChange={(e) => setInviteCode(e.target.value)}
              placeholder="Paste your invite code"
              required
              autoFocus
              className="w-full rounded-lg border border-zinc-200 bg-white px-3 py-2 text-sm text-zinc-900 placeholder:text-zinc-400 focus:border-zinc-400 focus:outline-none focus:ring-1 focus:ring-zinc-400"
            />
          </div>
          {error && (
            <div className="rounded-lg border border-rose-200 bg-rose-50 px-3 py-2">
              <p className="text-sm text-rose-700">{error}</p>
            </div>
          )}
          <button
            type="submit"
            disabled={loading || !inviteCode}
            className="w-full rounded-lg bg-zinc-900 px-4 py-2.5 text-sm font-medium text-white transition-colors hover:bg-zinc-800 active:scale-[0.98] disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {loading ? "Joining..." : "Join team"}
          </button>
        </form>
      )}
    </AuthCard>
  )
}
