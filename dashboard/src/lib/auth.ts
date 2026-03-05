import NextAuth from "next-auth"
import Credentials from "next-auth/providers/credentials"
import type { NextAuthConfig } from "next-auth"

// Extend the built-in types
declare module "next-auth" {
  interface Session {
    user: {
      id: string
      email: string
      name: string
      tenantId: string | null
      isPlatformAdmin: boolean
      isNewUser: boolean
      roles: string[]
      impersonatingTenantName?: string
    }
  }

  interface User {
    id: string
    email: string
    name: string
    tenantId: string | null
    isPlatformAdmin: boolean
    isNewUser: boolean
    accessToken: string
    refreshToken: string
    expiresIn: number
    roles: string[]
    impersonatingTenantName?: string
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
    isNewUser: boolean
    roles: string[]
    impersonatingTenantName?: string
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

if (
  process.env.NODE_ENV === "production" &&
  process.env.VALINOR_DEV_MODE &&
  process.env.VERCEL_ENV === "production"
) {
  throw new Error("VALINOR_DEV_MODE must not be enabled in production")
}

const VALINOR_API_URL = process.env.VALINOR_API_URL ?? "http://localhost:8080"

// Exchange an external OIDC id_token for Valinor platform tokens.
// tenantSlug is passed explicitly because server-side fetches lack a browser
// Origin header, so the backend cannot resolve the tenant from the request alone.
async function exchangeIDToken(idToken: string, tenantSlug?: string, emailHint?: string): Promise<{
  access_token: string
  refresh_token: string
  expires_in: number
  created: boolean
  user: { id: string; email: string; display_name: string; tenant_id: string; is_platform_admin: boolean }
} | null> {
  const res = await fetch(`${VALINOR_API_URL}/auth/exchange`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      id_token: idToken,
      ...(tenantSlug && { tenant_slug: tenantSlug }),
      ...(emailHint && { email_hint: emailHint }),
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
                isNewUser: false,
                accessToken: data.access_token,
                refreshToken: data.refresh_token,
                expiresIn: data.expires_in ?? 86400,
                roles,
              }
            },
          }),
        ]
      : []),

    // Clerk headless auth (when AUTH_CLERK_ISSUER is set)
    ...(process.env.AUTH_CLERK_ISSUER
      ? [
          Credentials({
            id: "clerk-token",
            credentials: {
              token: { label: "Clerk Session Token", type: "text" },
              tenantSlug: { label: "Tenant Slug", type: "text" },
              emailHint: { label: "Email Hint", type: "text" },
            },
            async authorize(credentials) {
              if (!credentials?.token) return null

              const data = await exchangeIDToken(
                credentials.token as string,
                (credentials.tenantSlug as string) || undefined,
                (credentials.emailHint as string) || undefined,
              )
              if (!data) return null

              const roles = decodeJwtRoles(data.access_token)
              return {
                id: data.user.id,
                email: data.user.email,
                name: data.user.display_name ?? data.user.email,
                tenantId: data.user.tenant_id ?? null,
                isPlatformAdmin: data.user.is_platform_admin ?? false,
                isNewUser: data.created ?? false,
                accessToken: data.access_token,
                refreshToken: data.refresh_token,
                expiresIn: data.expires_in ?? 3600,
                roles,
              }
            },
          }),
        ]
      : []),

    // Impersonation provider — accepts a pre-minted impersonation token
    Credentials({
      id: "impersonate",
      credentials: {
        token: { label: "Impersonation Token", type: "text" },
        tenantName: { label: "Tenant Name", type: "text" },
      },
      async authorize(credentials) {
        if (!credentials?.token) return null

        const token = credentials.token as string
        const tenantName = (credentials.tenantName as string) || ""

        // Decode the impersonation JWT to extract claims
        try {
          const payload = token.split(".")[1]
          const json = Buffer.from(payload, "base64url").toString("utf8")
          const claims = JSON.parse(json) as {
            uid?: string
            tid?: string
            email?: string
            name?: string
            roles?: string[]
            pa?: boolean
            imp?: string
          }
          const roles = Array.isArray(claims.roles) ? claims.roles : []
          return {
            id: claims.uid ?? "",
            email: claims.email ?? "",
            name: claims.name ?? claims.email ?? "",
            tenantId: claims.tid ?? null,
            isPlatformAdmin: claims.pa ?? false,
            isNewUser: false,
            accessToken: token,
            refreshToken: "",
            expiresIn: 1800,
            roles,
            impersonatingTenantName: tenantName,
          }
        } catch {
          console.error("Failed to decode impersonation token")
          return null
        }
      },
    }),
  ],
  callbacks: {
    authorized({ auth, request }) {
      const isLoggedIn = !!auth?.user
      const path = request.nextUrl.pathname
      const isPublicAuth =
        path.startsWith("/login") ||
        path.startsWith("/signup") ||
        path.startsWith("/sso-callback")
      if (isPublicAuth) return true
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
        token.isNewUser = user.isNewUser ?? false
        token.roles = user.roles ?? []
        token.impersonatingTenantName = user.impersonatingTenantName
        return token
      }

      // Impersonation sign-in
      if (user && account?.provider === "impersonate") {
        token.accessToken = user.accessToken
        token.refreshToken = user.refreshToken
        token.expiresAt = Math.floor(Date.now() / 1000) + (user.expiresIn ?? 1800)
        token.userId = user.id ?? ""
        token.tenantId = user.tenantId ?? null
        token.isPlatformAdmin = user.isPlatformAdmin ?? false
        token.isNewUser = false
        token.roles = user.roles ?? []
        token.impersonatingTenantName = user.impersonatingTenantName
        return token
      }

      // Initial sign-in from Clerk headless (clerk-token credentials)
      if (user && account?.provider === "clerk-token") {
        token.accessToken = user.accessToken
        token.refreshToken = user.refreshToken
        token.expiresAt = Math.floor(Date.now() / 1000) + (user.expiresIn ?? 3600)
        token.userId = user.id ?? ""
        token.tenantId = user.tenantId ?? null
        token.isPlatformAdmin = user.isPlatformAdmin ?? false
        token.isNewUser = user.isNewUser ?? false
        token.roles = user.roles ?? []
        token.impersonatingTenantName = user.impersonatingTenantName
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
      session.user.id = token.userId
      session.user.tenantId = token.tenantId
      session.user.isPlatformAdmin = token.isPlatformAdmin
      session.user.isNewUser = token.isNewUser ?? false
      session.user.roles = token.roles
      session.user.impersonatingTenantName = token.impersonatingTenantName
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

/**
 * Read the Valinor access token from the server-side JWT.
 * Use this in route handlers, server actions, and server components
 * that need the raw token (e.g. the BFF proxy).
 */
export async function getAccessToken(): Promise<string | null> {
  const { cookies } = await import("next/headers")
  const { decode } = await import("next-auth/jwt")
  const cookieStore = await cookies()

  // NextAuth v5 uses "authjs.session-token" in dev, "__Secure-authjs.session-token" in prod
  const cookieName =
    process.env.NODE_ENV === "production"
      ? "__Secure-authjs.session-token"
      : "authjs.session-token"

  const sessionToken = cookieStore.get(cookieName)?.value
  if (!sessionToken) return null

  const token = await decode({
    token: sessionToken,
    secret: process.env.AUTH_SECRET!,
    salt: cookieName,
  })
  return (token as { accessToken?: string } | null)?.accessToken ?? null
}
