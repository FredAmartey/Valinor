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
      roles: string[]
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
    expiresIn: number
    roles: string[]
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
    roles: string[]
  }
}

function decodeJwtRoles(token: string): string[] {
  try {
    const payload = token.split(".")[1]
    const json = Buffer.from(payload, "base64url").toString("utf8")
    const claims = JSON.parse(json) as { roles?: string[] }
    return Array.isArray(claims.roles) ? claims.roles : []
  } catch (err) {
    console.error("decodeJwtRoles: failed to decode JWT roles", err)
    return []
  }
}

const VALINOR_API_URL = process.env.VALINOR_API_URL ?? "http://localhost:8080"

// Exchange an external OIDC id_token for Valinor platform tokens.
// tenantSlug is passed explicitly because server-side fetches lack a browser
// Origin header, so the backend cannot resolve the tenant from the request alone.
async function exchangeIDToken(idToken: string, tenantSlug?: string): Promise<{
  access_token: string
  refresh_token: string
  expires_in: number
  user: { id: string; email: string; display_name: string; tenant_id: string; is_platform_admin: boolean }
} | null> {
  const res = await fetch(`${VALINOR_API_URL}/auth/exchange`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      id_token: idToken,
      ...(tenantSlug && { tenant_slug: tenantSlug }),
    }),
  })
  if (!res.ok) {
    console.error(`Token exchange failed: ${res.status} ${res.statusText}`)
    return null
  }
  return res.json()
}

export const authConfig: NextAuthConfig = {
  providers: [
    // Dev mode credentials (when VALINOR_DEV_MODE is set)
    ...(process.env.VALINOR_DEV_MODE
      ? [
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

              if (!res.ok) {
                console.error(`Dev login failed: ${res.status} ${res.statusText}`)
                return null
              }

              const data = await res.json()
              const roles = decodeJwtRoles(data.access_token)
              return {
                id: data.user.id,
                email: data.user.email,
                name: data.user.display_name ?? data.user.email,
                tenantId: data.user.tenant_id ?? null,
                isPlatformAdmin: data.user.is_platform_admin ?? false,
                accessToken: data.access_token,
                refreshToken: data.refresh_token,
                expiresIn: data.expires_in ?? 86400,
                roles,
              }
            },
          }),
        ]
      : []),

    // Production OIDC via Clerk (when AUTH_CLERK_ISSUER is set)
    ...(process.env.AUTH_CLERK_ISSUER
      ? [
          {
            id: "clerk",
            name: "Clerk",
            type: "oidc" as const,
            issuer: process.env.AUTH_CLERK_ISSUER,
            clientId: process.env.AUTH_CLERK_ID!,
            clientSecret: process.env.AUTH_CLERK_SECRET!,
          },
        ]
      : []),
  ],
  callbacks: {
    authorized({ auth, request }) {
      const isLoggedIn = !!auth?.user
      const isOnLogin = request.nextUrl.pathname.startsWith("/login")
      if (isOnLogin) return true
      return isLoggedIn
    },
    async jwt({ token, user, account }) {
      // Initial sign-in from credentials (dev mode)
      if (user && account?.provider === "credentials") {
        token.accessToken = user.accessToken
        token.refreshToken = user.refreshToken
        token.expiresAt = Math.floor(Date.now() / 1000) + (user.expiresIn ?? 86400)
        token.userId = user.id ?? ""
        token.tenantId = user.tenantId ?? null
        token.isPlatformAdmin = user.isPlatformAdmin ?? false
        token.roles = user.roles ?? []
        return token
      }

      // Initial sign-in from OIDC (Clerk) — exchange id_token for Valinor tokens
      if (account?.provider === "clerk" && account.id_token) {
        const tenantSlug = process.env.NEXT_PUBLIC_TENANT_SLUG
        const data = await exchangeIDToken(account.id_token, tenantSlug)
        if (!data) {
          throw new Error("Valinor token exchange failed")
        }
        const roles = decodeJwtRoles(data.access_token)
        token.accessToken = data.access_token
        token.refreshToken = data.refresh_token
        token.expiresAt = Math.floor(Date.now() / 1000) + (data.expires_in ?? 3600)
        token.userId = data.user.id
        token.tenantId = data.user.tenant_id ?? null
        token.isPlatformAdmin = data.user.is_platform_admin ?? false
        token.roles = roles
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
        // Roles are not re-decoded from the refreshed token — they are set once at
        // initial sign-in and persist for the lifetime of the session.
        token.accessToken = data.access_token
        token.refreshToken = data.refresh_token ?? token.refreshToken
        token.expiresAt = Math.floor(Date.now() / 1000) + (data.expires_in ?? 3600)
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
      session.user.roles = token.roles
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
