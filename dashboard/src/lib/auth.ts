import NextAuth from "next-auth"
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
    {
      id: "valinor",
      name: "Valinor",
      type: "oidc",
      issuer: VALINOR_API_URL,
      clientId: process.env.AUTH_VALINOR_CLIENT_ID ?? "dashboard",
      clientSecret: process.env.AUTH_VALINOR_CLIENT_SECRET ?? "",
      authorization: { url: `${VALINOR_API_URL}/auth/login`, params: { scope: "openid profile email" } },
      token: { url: `${VALINOR_API_URL}/auth/callback` },
      userinfo: { url: `${VALINOR_API_URL}/api/v1/users/me` },
      profile(profile) {
        return {
          id: profile.sub ?? profile.id,
          email: profile.email,
          name: profile.display_name ?? profile.name ?? profile.email,
          tenantId: profile.tenant_id ?? null,
          isPlatformAdmin: profile.is_platform_admin ?? false,
        }
      },
    },
  ],
  callbacks: {
    async jwt({ token, account, profile }) {
      // Initial sign-in: persist tokens from the OIDC flow
      if (account) {
        token.accessToken = account.access_token ?? ""
        token.refreshToken = account.refresh_token ?? ""
        token.expiresAt = account.expires_at ?? 0
        token.userId = String((profile as Record<string, unknown>)?.id ?? "")
        token.tenantId = ((profile as Record<string, unknown>)?.tenant_id as string) ?? null
        token.isPlatformAdmin = Boolean((profile as Record<string, unknown>)?.is_platform_admin)
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
        token.expiresAt = data.expires_at ?? Math.floor(Date.now() / 1000) + 3600
        return token
      } catch {
        // Refresh failed — force re-login
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
}

export const { handlers, auth, signIn, signOut } = NextAuth(authConfig)
