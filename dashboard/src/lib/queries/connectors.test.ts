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
    await fetchConnectors()

    expect(mockedClient).toHaveBeenCalledWith(
      "/api/v1/connectors",
      undefined,
    )
  })

  it("createConnector posts to correct endpoint", async () => {
    const { apiClient } = await import("@/lib/api-client")
    const mockedClient = vi.mocked(apiClient)
    mockedClient.mockResolvedValueOnce({ id: "c-1" })

    const { createConnector } = await import("./connectors")
    await createConnector({
      name: "test-mcp",
      endpoint: "https://example.com/mcp",
      tools: ["search", "fetch"],
    })

    expect(mockedClient).toHaveBeenCalledWith(
      "/api/v1/connectors",
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
    await deleteConnector("c-1")

    expect(mockedClient).toHaveBeenCalledWith(
      "/api/v1/connectors/c-1",
      { method: "DELETE" },
    )
  })
})
