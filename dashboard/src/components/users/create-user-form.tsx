"use client"

import { useState } from "react"
import { useRouter } from "next/navigation"
import { useCreateUserMutation } from "@/lib/queries/users"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"

export function CreateUserForm() {
  const router = useRouter()
  const mutation = useCreateUserMutation()
  const [email, setEmail] = useState("")
  const [displayName, setDisplayName] = useState("")

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    mutation.mutate(
      { email, display_name: displayName || undefined },
      { onSuccess: (user) => router.push(`/users/${user.id}`) },
    )
  }

  return (
    <form onSubmit={handleSubmit} className="max-w-lg space-y-6">
      <div className="space-y-2">
        <Label htmlFor="email">Email</Label>
        <Input
          id="email"
          type="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          placeholder="user@example.com"
          required
        />
      </div>

      <div className="space-y-2">
        <Label htmlFor="displayName">Display Name</Label>
        <Input
          id="displayName"
          value={displayName}
          onChange={(e) => setDisplayName(e.target.value)}
          placeholder="Optional"
        />
        <p className="text-xs text-zinc-400">How this user appears in the dashboard.</p>
      </div>

      {mutation.isError && (
        <div className="rounded-lg border border-rose-200 bg-rose-50 px-3 py-2">
          <p className="text-sm text-rose-700">Failed to create user. The email may already be in use.</p>
        </div>
      )}

      <button
        type="submit"
        disabled={mutation.isPending || !email}
        className="rounded-lg bg-zinc-900 px-4 py-2.5 text-sm font-medium text-white transition-colors hover:bg-zinc-800 active:scale-[0.98] disabled:opacity-50 disabled:cursor-not-allowed"
      >
        {mutation.isPending ? "Creating..." : "Create user"}
      </button>
    </form>
  )
}
