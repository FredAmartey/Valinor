import { describe, it, expect, vi } from "vitest"

// Mock auth module before any imports that reference it
vi.mock("./auth", () => ({
  auth: vi.fn().mockResolvedValue({ accessToken: "test-token" }),
}))

describe("ApiError", () => {
  it("captures status and body", async () => {
    const { ApiError } = await import("./api")
    const err = new ApiError(422, { error: "validation failed", details: { name: "required" } })
    expect(err.status).toBe(422)
    expect(err.body.error).toBe("validation failed")
    expect(err.message).toBe("API error 422: validation failed")
  })
})

describe("buildUrl", () => {
  it("constructs full URL from path", async () => {
    const { buildUrl } = await import("./api")
    const url = buildUrl("/api/v1/tenants")
    expect(url).toContain("/api/v1/tenants")
  })

  it("appends query params", async () => {
    const { buildUrl } = await import("./api")
    const url = buildUrl("/api/v1/tenants", { status: "active", limit: "10" })
    expect(url).toContain("status=active")
    expect(url).toContain("limit=10")
  })
})
