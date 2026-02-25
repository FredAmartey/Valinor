import { describe, it, expect, vi, beforeEach } from "vitest"
import { ApiError } from "./api"

// Mock fetch globally
const mockFetch = vi.fn()
vi.stubGlobal("fetch", mockFetch)

describe("apiClient", () => {
  beforeEach(() => {
    mockFetch.mockReset()
  })

  it("makes GET request with correct URL", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: () => Promise.resolve([{ id: "1", name: "Test Tenant" }]),
    })

    const { apiClient } = await import("./api-client")
    const result = await apiClient("/api/v1/tenants", "test-token")
    expect(mockFetch).toHaveBeenCalledWith(
      expect.stringContaining("/api/v1/tenants"),
      expect.objectContaining({
        headers: expect.objectContaining({
          Authorization: "Bearer test-token",
        }),
      }),
    )
    expect(result).toEqual([{ id: "1", name: "Test Tenant" }])
  })

  it("throws ApiError on non-ok response", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 403,
      statusText: "Forbidden",
      json: () => Promise.resolve({ error: "insufficient permissions" }),
    })

    const { apiClient } = await import("./api-client")
    await expect(apiClient("/api/v1/tenants", "test-token")).rejects.toThrow(ApiError)
  })

  it("sends POST body as JSON", async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 201,
      json: () => Promise.resolve({ id: "2", name: "New Tenant" }),
    })

    const { apiClient } = await import("./api-client")
    await apiClient("/api/v1/tenants", "test-token", {
      method: "POST",
      body: JSON.stringify({ name: "New Tenant", slug: "new-tenant" }),
    })

    expect(mockFetch).toHaveBeenCalledWith(
      expect.any(String),
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({ name: "New Tenant", slug: "new-tenant" }),
      }),
    )
  })
})
