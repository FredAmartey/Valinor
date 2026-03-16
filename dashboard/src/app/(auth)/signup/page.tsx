"use client"

import { useState } from "react"
import { useRouter } from "next/navigation"
import { AuthCard } from "@/components/auth/auth-card"
import { SocialButtons } from "@/components/auth/social-buttons"
import { AuthDivider } from "@/components/auth/auth-divider"
import { getClerk } from "@/lib/clerk"
import Link from "next/link"

export default function SignUpPage() {
  const router = useRouter()
  const [firstName, setFirstName] = useState("")
  const [lastName, setLastName] = useState("")
  const [email, setEmail] = useState("")
  const [password, setPassword] = useState("")
  const [error, setError] = useState("")
  const [loading, setLoading] = useState(false)

  async function handleSignUp(e: React.FormEvent) {
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
      const signUpAttempt = await clerk.client.signUp.create({
        emailAddress: email,
        password,
        firstName,
        lastName,
      })

      if (signUpAttempt.status === "complete") {
        router.push("/signup/team")
        return
      }

      await signUpAttempt.prepareEmailAddressVerification({ strategy: "email_code" })

      sessionStorage.setItem("heimdall_signup_pending", "true")
      router.push("/signup/verify")
    } catch (err: unknown) {
      setLoading(false)
      const message = err instanceof Error ? err.message : "Sign-up failed"
      if (message.includes("email_address") || message.includes("taken")) {
        setError("Email already in use. Sign in instead?")
      } else if (message.includes("password")) {
        setError("Password must be at least 8 characters.")
      } else {
        setError("Sign-up failed. Please try again.")
      }
    }
  }

  async function handleSocialSignUp(strategy: "oauth_google" | "oauth_github") {
    setError("")
    setLoading(true)

    try {
      const clerk = await getClerk()
      if (!clerk.client) {
        setError("Failed to initialize authentication.")
        setLoading(false)
        return
      }

      if (clerk.session) {
        await clerk.signOut()
      }

      const callbackUrl = `${window.location.origin}/sso-callback`

      await clerk.client.signUp.authenticateWithRedirect({
        strategy,
        redirectUrl: callbackUrl,
        redirectUrlComplete: callbackUrl,
      })
    } catch {
      setError("Social sign-up failed. Please try again.")
      setLoading(false)
    }
  }

  return (
    <AuthCard>
      <p className="text-center text-sm text-zinc-500">
        Create your account to get started.
      </p>

      <form onSubmit={handleSignUp} className="space-y-4">
        <div className="grid grid-cols-2 gap-3">
          <div className="space-y-2">
            <label htmlFor="firstName" className="text-sm font-medium text-zinc-700">
              First name
            </label>
            <input
              id="firstName"
              type="text"
              value={firstName}
              onChange={(e) => setFirstName(e.target.value)}
              placeholder="Jane"
              required
              className="w-full rounded-lg border border-zinc-200 bg-white px-3 py-2 text-sm text-zinc-900 placeholder:text-zinc-400 focus:border-zinc-400 focus:outline-none focus:ring-1 focus:ring-zinc-400"
            />
          </div>
          <div className="space-y-2">
            <label htmlFor="lastName" className="text-sm font-medium text-zinc-700">
              Last name
            </label>
            <input
              id="lastName"
              type="text"
              value={lastName}
              onChange={(e) => setLastName(e.target.value)}
              placeholder="Doe"
              required
              className="w-full rounded-lg border border-zinc-200 bg-white px-3 py-2 text-sm text-zinc-900 placeholder:text-zinc-400 focus:border-zinc-400 focus:outline-none focus:ring-1 focus:ring-zinc-400"
            />
          </div>
        </div>
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
            minLength={8}
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
          disabled={loading || !email || !password || !firstName || !lastName}
          className="w-full rounded-lg bg-zinc-900 px-4 py-2.5 text-sm font-medium text-white transition-colors hover:bg-zinc-800 active:scale-[0.98] disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {loading ? "Creating account..." : "Create account"}
        </button>
      </form>

      <AuthDivider />

      <SocialButtons
        onGoogle={() => handleSocialSignUp("oauth_google")}
        onGitHub={() => handleSocialSignUp("oauth_github")}
        disabled={loading}
      />

      <p className="text-center text-sm text-zinc-500">
        Already have an account?{" "}
        <Link href="/login" className="font-medium text-zinc-900 hover:underline">
          Sign in
        </Link>
      </p>
    </AuthCard>
  )
}
