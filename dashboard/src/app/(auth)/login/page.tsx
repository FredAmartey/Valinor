"use client"

import { signIn } from "next-auth/react"
import { useState } from "react"
import { useRouter } from "next/navigation"
import { AuthCard } from "@/components/auth/auth-card"
import { SocialButtons } from "@/components/auth/social-buttons"
import { AuthDivider } from "@/components/auth/auth-divider"
import { getClerk } from "@/lib/clerk"
import Link from "next/link"

const isDevMode = process.env.NEXT_PUBLIC_HEIMDALL_DEV_MODE === "true"
const isClerkEnabled = !!process.env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY
const tenantSlug = process.env.NEXT_PUBLIC_TENANT_SLUG

export default function LoginPage() {
  const router = useRouter()
  const [email, setEmail] = useState("")
  const [password, setPassword] = useState("")
  const [devEmail, setDevEmail] = useState("")
  const [error, setError] = useState("")
  const [loading, setLoading] = useState(false)

  async function handleDevLogin(e: React.FormEvent) {
    e.preventDefault()
    setError("")
    setLoading(true)

    const result = await signIn("credentials", { email: devEmail, redirect: false })
    setLoading(false)

    if (result?.error) {
      setError("Invalid email or user not found.")
      return
    }
    router.push("/")
    router.refresh()
  }

  async function handleClerkLogin(e: React.FormEvent) {
    e.preventDefault()
    setError("")
    setLoading(true)

    try {
      const clerk = await getClerk()
      if (!clerk.client) {
        setError("Failed to initialize authentication.")
        setLoading(false)
        return
      }
      const signInAttempt = await clerk.client.signIn.create({
        identifier: email,
        password,
      })

      if (signInAttempt.status !== "complete") {
        setError("Sign-in could not be completed. Try again.")
        setLoading(false)
        return
      }

      await clerk.setActive({ session: signInAttempt.createdSessionId })

      const token = await clerk.session?.getToken()
      if (!token) {
        setError("Failed to get session token.")
        setLoading(false)
        return
      }

      const result = await signIn("clerk-token", {
        token,
        tenantSlug: tenantSlug ?? "",
        emailHint: email,
        redirect: false,
      })

      setLoading(false)
      if (result?.error) {
        setError("Authentication failed. Please try again.")
        return
      }
      router.push("/")
      router.refresh()
    } catch (err: unknown) {
      setLoading(false)
      const message = err instanceof Error ? err.message : "Sign-in failed"
      if (message.includes("identifier") || message.includes("password")) {
        setError("Invalid email or password.")
      } else if (message.includes("rate")) {
        setError("Too many attempts. Try again in a few minutes.")
      } else {
        setError("Sign-in failed. Please try again.")
      }
    }
  }

  async function handleSocialLogin(strategy: "oauth_google" | "oauth_github") {
    setError("")
    setLoading(true)

    try {
      const clerk = await getClerk()
      if (!clerk.client) {
        setError("Failed to initialize authentication.")
        setLoading(false)
        return
      }

      // Clear any stale session
      if (clerk.session) {
        await clerk.signOut()
      }

      const callbackUrl = `${window.location.origin}/sso-callback`

      await clerk.client.signIn.authenticateWithRedirect({
        strategy,
        redirectUrl: callbackUrl,
        redirectUrlComplete: callbackUrl,
      })
    } catch {
      setError("Social sign-in failed. Please try again.")
      setLoading(false)
    }
  }

  return (
    <AuthCard>
      <p className="text-center text-sm text-zinc-500">
        Sign in to manage your AI agent infrastructure.
      </p>

      {isClerkEnabled && (
        <>
          <form onSubmit={handleClerkLogin} className="space-y-4">
            <div className="space-y-2">
              <label htmlFor="email" className="text-sm font-medium text-zinc-700">
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
            <div className="space-y-2">
              <label htmlFor="password" className="text-sm font-medium text-zinc-700">
                Password
              </label>
              <input
                id="password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••"
                required
                className="w-full rounded-lg border border-zinc-200 bg-white px-3 py-2 text-sm text-zinc-900 placeholder:text-zinc-400 focus:border-zinc-400 focus:outline-none focus:ring-1 focus:ring-zinc-400"
              />
            </div>
            {error && !isDevMode && (
              <div className="rounded-lg border border-rose-200 bg-rose-50 px-3 py-2">
                <p className="text-sm text-rose-700">{error}</p>
              </div>
            )}
            <button
              type="submit"
              disabled={loading || !email || !password}
              className="w-full rounded-lg bg-zinc-900 px-4 py-2.5 text-sm font-medium text-white transition-colors hover:bg-zinc-800 active:scale-[0.98] disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading ? "Signing in..." : "Sign in"}
            </button>
          </form>

          <AuthDivider />

          <SocialButtons
            onGoogle={() => handleSocialLogin("oauth_google")}
            onGitHub={() => handleSocialLogin("oauth_github")}
            disabled={loading}
          />

          <p className="text-center text-sm text-zinc-500">
            Don&apos;t have an account?{" "}
            <Link href="/signup" className="font-medium text-zinc-900 hover:underline">
              Sign up
            </Link>
          </p>
        </>
      )}

      {isDevMode && (
        <>
          {isClerkEnabled && <AuthDivider />}
          <form onSubmit={handleDevLogin} className="space-y-4">
            <div className="space-y-2">
              <label htmlFor="dev-email" className="text-sm font-medium text-zinc-700">
                Email {isClerkEnabled && "(Dev Mode)"}
              </label>
              <input
                id="dev-email"
                type="email"
                value={devEmail}
                onChange={(e) => setDevEmail(e.target.value)}
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
              disabled={loading}
              className="w-full rounded-lg border border-zinc-200 bg-white px-4 py-2.5 text-sm font-medium text-zinc-700 transition-colors hover:bg-zinc-50 active:scale-[0.98] disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading ? "Signing in..." : "Sign in (Dev Mode)"}
            </button>
          </form>
          <p className="text-center text-xs text-zinc-400">
            Dev mode — enter any existing user email.
          </p>
        </>
      )}
    </AuthCard>
  )
}
