"use client"

import { signIn } from "next-auth/react"
import { useEffect, useRef, useState } from "react"
import { useRouter } from "next/navigation"
import { AuthCard } from "@/components/auth/auth-card"
import { getClerk } from "@/lib/clerk"

const tenantSlug = process.env.NEXT_PUBLIC_TENANT_SLUG
const SSO_TIMEOUT_MS = 30_000

export default function SSOCallbackPage() {
  const router = useRouter()
  const [error, setError] = useState("")
  const handled = useRef(false)

  useEffect(() => {
    if (handled.current) return
    handled.current = true

    const timeout = setTimeout(() => {
      setError("Sign-in is taking too long. Please try again.")
    }, SSO_TIMEOUT_MS)

    async function handleCallback() {
      try {
        const clerk = await getClerk()

        // Handle the OAuth callback — Clerk processes the URL params.
        // Pass a no-op navigator to prevent Clerk from navigating away
        // before we can exchange the token with our backend.
        await clerk.handleRedirectCallback(
          { afterSignInUrl: "/", afterSignUpUrl: "/signup/team" },
          () => Promise.resolve(),
        )

        // If there's an active session, exchange for Heimdall tokens
        if (clerk.session) {
          const token = await clerk.session.getToken()
          if (!token) {
            setError("Failed to get session token.")
            return
          }

          const email = clerk.user?.primaryEmailAddress?.emailAddress ?? ""

          const signInResult = await signIn("clerk-token", {
            token,
            tenantSlug: tenantSlug ?? "",
            emailHint: email,
            redirect: false,
          })

          if (signInResult?.error) {
            setError("Authentication failed.")
            return
          }

          // Check if this is a new user (no tenant) → go to team page
          // Otherwise go to dashboard
          const response = await fetch("/api/auth/session")
          const session = await response.json()

          if (!session?.user?.tenantId) {
            router.push("/signup/team")
          } else {
            router.push("/")
          }
          router.refresh()
        }
      } catch {
        setError("Social sign-in failed. Please try again.")
      } finally {
        clearTimeout(timeout)
      }
    }

    handleCallback()
  }, [router])

  if (error) {
    return (
      <AuthCard>
        <div className="rounded-lg border border-rose-200 bg-rose-50 px-3 py-2">
          <p className="text-sm text-rose-700">{error}</p>
        </div>
        <a
          href="/login"
          className="block w-full rounded-lg border border-zinc-200 bg-white px-4 py-2.5 text-center text-sm font-medium text-zinc-700 transition-colors hover:bg-zinc-50"
        >
          Back to sign in
        </a>
      </AuthCard>
    )
  }

  return (
    <AuthCard>
      <div className="flex items-center justify-center py-8">
        <div className="h-6 w-6 animate-spin rounded-full border-2 border-zinc-300 border-t-zinc-900" />
        <span className="ml-3 text-sm text-zinc-500">Completing sign-in...</span>
      </div>
    </AuthCard>
  )
}
