import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

const nextAuthMock = vi.fn(() => ({
  handlers: { GET: vi.fn(), POST: vi.fn() },
  auth: vi.fn(),
  signIn: vi.fn(),
  signOut: vi.fn(),
}))

const credentialsMock = vi.fn((config: unknown) => config)

vi.mock("next-auth", () => ({
  default: nextAuthMock,
}))

vi.mock("next-auth/providers/credentials", () => ({
  default: credentialsMock,
}))

function expiredToken() {
  return {
    accessToken: "expired-access-token",
    refreshToken: "refresh-token",
    expiresAt: Math.floor(Date.now() / 1000) - 60,
    userId: "user-1",
    tenantId: "tenant-1",
    isPlatformAdmin: false,
    isNewUser: false,
    roles: ["admin"],
  }
}

async function loadJwtCallback() {
  const { authConfig } = await import("./auth")
  return authConfig.callbacks?.jwt as (params: Record<string, unknown>) => Promise<unknown>
}

describe("authConfig.callbacks.jwt", () => {
  beforeEach(() => {
    vi.resetModules()
    vi.clearAllMocks()
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it("clears the session when token refresh throws", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new TypeError("fetch failed")))

    const jwt = await loadJwtCallback()

    const result = await jwt({
      token: expiredToken(),
    })

    expect(result).toBeNull()
  })

  it("updates the token when refresh succeeds", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          access_token: "fresh-access-token",
          refresh_token: "fresh-refresh-token",
          expires_in: 900,
        }),
      }),
    )

    const jwt = await loadJwtCallback()

    const result = (await jwt({
      token: expiredToken(),
    })) as Record<string, unknown>

    expect(result.accessToken).toBe("fresh-access-token")
    expect(result.refreshToken).toBe("fresh-refresh-token")
    expect(result.expiresAt).toEqual(expect.any(Number))
  })
})
