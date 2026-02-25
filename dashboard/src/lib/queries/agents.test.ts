import { describe, it, expect, vi } from "vitest"

vi.mock("@/lib/api-client", () => ({
  apiClient: vi.fn(),
}))

describe("agent query functions", () => {
  it("fetchAgents calls correct endpoint", async () => {
    const { apiClient } = await import("@/lib/api-client")
    const mockedClient = vi.mocked(apiClient)
    mockedClient.mockResolvedValueOnce({ agents: [] })

    const { fetchAgents } = await import("./agents")
    await fetchAgents("test-token")

    expect(mockedClient).toHaveBeenCalledWith(
      "/api/v1/agents",
      "test-token",
      undefined,
    )
  })

  it("fetchAgent calls correct endpoint with ID", async () => {
    const { apiClient } = await import("@/lib/api-client")
    const mockedClient = vi.mocked(apiClient)
    mockedClient.mockResolvedValueOnce({ id: "a-1", status: "running" })

    const { fetchAgent } = await import("./agents")
    await fetchAgent("test-token", "a-1")

    expect(mockedClient).toHaveBeenCalledWith(
      "/api/v1/agents/a-1",
      "test-token",
      undefined,
    )
  })

  it("provisionAgent posts to correct endpoint", async () => {
    const { apiClient } = await import("@/lib/api-client")
    const mockedClient = vi.mocked(apiClient)
    mockedClient.mockResolvedValueOnce({ id: "a-2", status: "provisioning" })

    const { provisionAgent } = await import("./agents")
    await provisionAgent("test-token", { user_id: "u-1" })

    expect(mockedClient).toHaveBeenCalledWith(
      "/api/v1/agents",
      "test-token",
      {
        method: "POST",
        body: JSON.stringify({ user_id: "u-1" }),
      },
    )
  })

  it("destroyAgent deletes correct endpoint", async () => {
    const { apiClient } = await import("@/lib/api-client")
    const mockedClient = vi.mocked(apiClient)
    mockedClient.mockResolvedValueOnce(undefined)

    const { destroyAgent } = await import("./agents")
    await destroyAgent("test-token", "a-1")

    expect(mockedClient).toHaveBeenCalledWith(
      "/api/v1/agents/a-1",
      "test-token",
      { method: "DELETE" },
    )
  })

  it("configureAgent posts config to correct endpoint", async () => {
    const { apiClient } = await import("@/lib/api-client")
    const mockedClient = vi.mocked(apiClient)
    mockedClient.mockResolvedValueOnce({ id: "a-1", status: "running" })

    const { configureAgent } = await import("./agents")
    await configureAgent("test-token", "a-1", {
      config: { model: "gpt-4" },
      tool_allowlist: ["search", "read"],
    })

    expect(mockedClient).toHaveBeenCalledWith(
      "/api/v1/agents/a-1/configure",
      "test-token",
      {
        method: "POST",
        body: JSON.stringify({
          config: { model: "gpt-4" },
          tool_allowlist: ["search", "read"],
        }),
      },
    )
  })
})
