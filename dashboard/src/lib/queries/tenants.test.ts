import { describe, it, expect, vi, beforeEach } from "vitest"

vi.mock("@/lib/api-client", () => ({
  apiClient: vi.fn(),
}))

describe("tenant query functions", () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it("fetchTenants calls correct endpoint", async () => {
    const { apiClient } = await import("@/lib/api-client")
    const mockedClient = vi.mocked(apiClient)
    mockedClient.mockResolvedValueOnce([])

    const { fetchTenants } = await import("./tenants")
    await fetchTenants("test-token")

    expect(mockedClient).toHaveBeenCalledWith(
      "/api/v1/tenants",
      "test-token",
      undefined,
    )
  })

  it("fetchTenant calls correct endpoint with ID", async () => {
    const { apiClient } = await import("@/lib/api-client")
    const mockedClient = vi.mocked(apiClient)
    mockedClient.mockResolvedValueOnce({ id: "t-1", name: "Acme" })

    const { fetchTenant } = await import("./tenants")
    await fetchTenant("test-token", "t-1")

    expect(mockedClient).toHaveBeenCalledWith(
      "/api/v1/tenants/t-1",
      "test-token",
      undefined,
    )
  })

  it("createTenant posts to correct endpoint", async () => {
    const { apiClient } = await import("@/lib/api-client")
    const mockedClient = vi.mocked(apiClient)
    mockedClient.mockResolvedValueOnce({ id: "t-2", name: "New Corp" })

    const { createTenant } = await import("./tenants")
    await createTenant("test-token", { name: "New Corp", slug: "new-corp" })

    expect(mockedClient).toHaveBeenCalledWith(
      "/api/v1/tenants",
      "test-token",
      {
        method: "POST",
        body: JSON.stringify({ name: "New Corp", slug: "new-corp" }),
      },
    )
  })
})
