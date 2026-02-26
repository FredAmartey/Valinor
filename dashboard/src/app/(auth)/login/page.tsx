"use client"

import { signIn } from "next-auth/react"
import { useState } from "react"
import { useRouter } from "next/navigation"

const isDevMode = process.env.NEXT_PUBLIC_VALINOR_DEV_MODE === "true"
const isClerkEnabled = !!process.env.NEXT_PUBLIC_AUTH_CLERK_ENABLED

export default function LoginPage() {
  const router = useRouter()
  const [email, setEmail] = useState("")
  const [error, setError] = useState("")
  const [loading, setLoading] = useState(false)

  async function handleDevLogin(e: React.FormEvent) {
    e.preventDefault()
    setError("")
    setLoading(true)

    const result = await signIn("credentials", {
      email,
      redirect: false,
    })

    setLoading(false)

    if (result?.error) {
      setError("Invalid email or user not found.")
      return
    }

    router.push("/")
    router.refresh()
  }

  async function handleClerkLogin() {
    setLoading(true)
    await signIn("clerk", { redirectTo: "/" })
  }

  return (
    <div className="flex min-h-[100dvh] items-center justify-center bg-zinc-50">
      <div className="w-full max-w-sm space-y-6">
        <div className="text-center">
          <h1 className="text-2xl font-semibold tracking-tight text-zinc-900">
            Valinor Dashboard
          </h1>
          <p className="mt-2 text-sm text-zinc-500">
            Sign in to manage your AI agent infrastructure.
          </p>
        </div>

        {isClerkEnabled && (
          <>
            <button
              type="button"
              onClick={handleClerkLogin}
              disabled={loading}
              className="w-full rounded-lg bg-zinc-900 px-4 py-2.5 text-sm font-medium text-white transition-colors hover:bg-zinc-800 active:scale-[0.98] disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading ? "Redirecting..." : "Sign in"}
            </button>
            {isDevMode && (
              <div className="relative">
                <div className="absolute inset-0 flex items-center">
                  <div className="w-full border-t border-zinc-200" />
                </div>
                <div className="relative flex justify-center text-xs">
                  <span className="bg-zinc-50 px-2 text-zinc-400">or</span>
                </div>
              </div>
            )}
          </>
        )}

        {isDevMode && (
          <>
            <form onSubmit={handleDevLogin} className="space-y-4">
              <div className="space-y-2">
                <label
                  htmlFor="email"
                  className="text-sm font-medium text-zinc-700"
                >
                  Email
                </label>
                <input
                  id="email"
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="you@example.com"
                  required
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
                disabled={loading || !email}
                className="w-full rounded-lg border border-zinc-200 bg-white px-4 py-2.5 text-sm font-medium text-zinc-700 transition-colors hover:bg-zinc-50 active:scale-[0.98] disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {loading ? "Signing in..." : "Sign in (Dev Mode)"}
              </button>
            </form>
            <p className="text-center text-xs text-zinc-400">
              Dev mode authentication. Enter any existing user email.
            </p>
          </>
        )}
      </div>
    </div>
  )
}
