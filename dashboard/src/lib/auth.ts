import NextAuth from "next-auth"
import Credentials from "next-auth/providers/credentials"
import type { NextAuthConfig } from "next-auth"

// Extend the built-in types
declare module "next-auth" {
  interface Session {
    accessToken: string
    user: {
      id: string
      email: string
      name: string
      tenantId: string | null
      isPlatformAdmin: boolean
    }
  }

  interface User {
    id: string
    email: string
    name: string
    tenantId: string | null
    isPlatformAdmin: boolean
    accessToken: string
    refreshToken: string
  }
}

declare module "@auth/core/jwt" {
  interface JWT {
    accessToken: string
    refreshToken: string
    expiresAt: number
    userId: string
    tenantId: string | null
    isPlatformAdmin: boolean
  }
}

const VALINOR_API_URL = process.env.VALINOR_API_URL ?? "http://localhost:8080"

export const authConfig: NextAuthConfig = {
  providers: [
    Credentials({
      credentials: {
        email: { label: "Email", type: "email" },
      },
      async authorize(credentials) {
        if (!credentials?.email) return null

        const res = await fetch(`${VALINOR_API_URL}/auth/dev/login`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email: credentials.email }),
        })

        if (!res.ok) return null

        const data = await res.json()
        return {
          id: data.user.id,
          email: data.user.email,
          name: data.user.display_name ?? data.user.email,
          tenantId: data.user.tenant_id ?? null,
          isPlatformAdmin: data.user.is_platform_admin ?? false,
          accessToken: data.access_token,
          refreshToken: data.refresh_token,
        }
      },
    }),
  ],
  callbacks: {
    async jwt({ token, user }) {
      // Initial sign-in: persist tokens from authorize response
      if (user) {
        token.accessToken = user.accessToken
        token.refreshToken = user.refreshToken
        token.expiresAt = Math.floor(Date.now() / 1000) + 24 * 60 * 60 // 24h
        token.userId = user.id ?? ""
        token.tenantId = user.tenantId ?? null
        token.isPlatformAdmin = user.isPlatformAdmin ?? false
        return token
      }

      // Token still valid
      if (Date.now() < token.expiresAt * 1000) {
        return token
      }

      // Token expired: refresh via Valinor API
      try {
        const res = await fetch(`${VALINOR_API_URL}/auth/token/refresh`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ refresh_token: token.refreshToken }),
        })
        if (!res.ok) throw new Error("refresh failed")
        const data = await res.json()
        token.accessToken = data.access_token
        token.refreshToken = data.refresh_token ?? token.refreshToken
        token.expiresAt = Math.floor(Date.now() / 1000) + 24 * 60 * 60
        return token
      } catch (err) {
        console.error("Token refresh failed:", err)
        return { ...token, error: "RefreshTokenError" }
      }
    },
    async session({ session, token }) {
      session.accessToken = token.accessToken
      session.user.id = token.userId
      session.user.tenantId = token.tenantId
      session.user.isPlatformAdmin = token.isPlatformAdmin
      return session
    },
  },
  pages: {
    signIn: "/login",
  },
  session: {
    strategy: "jwt",
  },
}

export const { handlers, auth, signIn, signOut } = NextAuth(authConfig)
