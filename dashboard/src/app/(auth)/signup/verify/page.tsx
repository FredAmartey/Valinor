"use client"

import { signIn } from "next-auth/react"
import { useState } from "react"
import { useRouter } from "next/navigation"
import { AuthCard } from "@/components/auth/auth-card"
import { getClerk } from "@/lib/clerk"

const tenantSlug = process.env.NEXT_PUBLIC_TENANT_SLUG

export default function VerifyPage() {
  const router = useRouter()
  const [code, setCode] = useState("")
  const [error, setError] = useState("")
  const [loading, setLoading] = useState(false)

  async function handleVerify(e: React.FormEvent) {
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
      const signUpAttempt = clerk.client.signUp

      const result = await signUpAttempt.attemptEmailAddressVerification({ code })

      if (result.status !== "complete") {
        setError("Verification incomplete. Try again.")
        setLoading(false)
        return
      }

      await clerk.setActive({ session: result.createdSessionId })

      const token = await clerk.session?.getToken()
      if (!token) {
        setError("Failed to get session token.")
        setLoading(false)
        return
      }

      const signInResult = await signIn("clerk-token", {
        token,
        tenantSlug: tenantSlug ?? "",
        redirect: false,
      })

      if (signInResult?.error) {
        setError("Authentication failed.")
        setLoading(false)
        return
      }

      sessionStorage.removeItem("heimdall_signup_pending")

      router.push("/signup/team")
      router.refresh()
    } catch {
      setLoading(false)
      setError("Invalid verification code. Try again.")
    }
  }

  return (
    <AuthCard>
      <p className="text-center text-sm text-zinc-500">
        We sent a verification code to your email. Enter it below.
      </p>

      <form onSubmit={handleVerify} className="space-y-4">
        <div className="space-y-2">
          <label htmlFor="code" className="text-sm font-medium text-zinc-700">
            Verification code
          </label>
          <input
            id="code"
            type="text"
            value={code}
            onChange={(e) => setCode(e.target.value)}
            placeholder="Enter 6-digit code"
            required
            autoFocus
            className="w-full rounded-lg border border-zinc-200 bg-white px-3 py-2 text-center text-sm tracking-widest text-zinc-900 placeholder:text-zinc-400 focus:border-zinc-400 focus:outline-none focus:ring-1 focus:ring-zinc-400"
          />
        </div>
        {error && (
          <div className="rounded-lg border border-rose-200 bg-rose-50 px-3 py-2">
            <p className="text-sm text-rose-700">{error}</p>
          </div>
        )}
        <button
          type="submit"
          disabled={loading || !code}
          className="w-full rounded-lg bg-zinc-900 px-4 py-2.5 text-sm font-medium text-white transition-colors hover:bg-zinc-800 active:scale-[0.98] disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {loading ? "Verifying..." : "Verify email"}
        </button>
      </form>
    </AuthCard>
  )
}
