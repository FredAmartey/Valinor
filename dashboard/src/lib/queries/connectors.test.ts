import { describe, it, expect, vi } from "vitest"

vi.mock("@/lib/api-client", () => ({
  apiClient: vi.fn(),
}))

describe("connector query functions", () => {
  it("fetchConnectors calls correct endpoint", async () => {
    const { apiClient } = await import("@/lib/api-client")
    const mockedClient = vi.mocked(apiClient)
    mockedClient.mockResolvedValueOnce([])

    const { fetchConnectors } = await import("./connectors")
    await fetchConnectors("test-token")

    expect(mockedClient).toHaveBeenCalledWith(
      "/api/v1/connectors",
      "test-token",
      undefined,
    )
  })

  it("createConnector posts to correct endpoint", async () => {
    const { apiClient } = await import("@/lib/api-client")
    const mockedClient = vi.mocked(apiClient)
    mockedClient.mockResolvedValueOnce({ id: "c-1" })

    const { createConnector } = await import("./connectors")
    await createConnector("test-token", {
      name: "test-mcp",
      endpoint: "https://example.com/mcp",
      tools: ["search", "fetch"],
    })

    expect(mockedClient).toHaveBeenCalledWith(
      "/api/v1/connectors",
      "test-token",
      {
        method: "POST",
        body: JSON.stringify({
          name: "test-mcp",
          endpoint: "https://example.com/mcp",
          tools: ["search", "fetch"],
        }),
      },
    )
  })

  it("deleteConnector calls correct endpoint", async () => {
    const { apiClient } = await import("@/lib/api-client")
    const mockedClient = vi.mocked(apiClient)
    mockedClient.mockResolvedValueOnce(undefined)

    const { deleteConnector } = await import("./connectors")
    await deleteConnector("test-token", "c-1")

    expect(mockedClient).toHaveBeenCalledWith(
      "/api/v1/connectors/c-1",
      "test-token",
      { method: "DELETE" },
    )
  })
})
