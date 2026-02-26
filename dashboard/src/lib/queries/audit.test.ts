import { describe, it, expect, vi } from "vitest"

vi.mock("@/lib/api-client", () => ({
  apiClient: vi.fn(),
}))

describe("audit query functions", () => {
  it("fetchAuditEvents calls correct endpoint with no filters", async () => {
    const { apiClient } = await import("@/lib/api-client")
    const mockedClient = vi.mocked(apiClient)
    mockedClient.mockResolvedValueOnce({ events: [], count: 0 })

    const { fetchAuditEvents } = await import("./audit")
    await fetchAuditEvents("test-token")

    expect(mockedClient).toHaveBeenCalledWith(
      "/api/v1/audit/events",
      "test-token",
      { params: {} },
    )
  })

  it("fetchAuditEvents passes filter params", async () => {
    const { apiClient } = await import("@/lib/api-client")
    const mockedClient = vi.mocked(apiClient)
    mockedClient.mockResolvedValueOnce({ events: [], count: 0 })

    const { fetchAuditEvents } = await import("./audit")
    await fetchAuditEvents("test-token", {
      action: "user.created",
      resource_type: "user",
      limit: "25",
    })

    expect(mockedClient).toHaveBeenCalledWith(
      "/api/v1/audit/events",
      "test-token",
      {
        params: {
          action: "user.created",
          resource_type: "user",
          limit: "25",
        },
      },
    )
  })

  it("fetchAuditEvents strips undefined filter values", async () => {
    const { apiClient } = await import("@/lib/api-client")
    const mockedClient = vi.mocked(apiClient)
    mockedClient.mockResolvedValueOnce({ events: [], count: 0 })

    const { fetchAuditEvents } = await import("./audit")
    await fetchAuditEvents("test-token", {
      action: "role.created",
      resource_type: undefined,
    })

    expect(mockedClient).toHaveBeenCalledWith(
      "/api/v1/audit/events",
      "test-token",
      {
        params: {
          action: "role.created",
        },
      },
    )
  })
})
