import { describe, it, expect, vi } from "vitest"

vi.mock("@/lib/api-client", () => ({
  apiClient: vi.fn(),
}))

describe("channel query functions", () => {
  it("fetchChannelLinks calls correct endpoint", async () => {
    const { apiClient } = await import("@/lib/api-client")
    const mockedClient = vi.mocked(apiClient)
    mockedClient.mockResolvedValueOnce([])

    const { fetchChannelLinks } = await import("./channels")
    await fetchChannelLinks()

    expect(mockedClient).toHaveBeenCalledWith(
      "/api/v1/channels/links",
      undefined,
    )
  })

  it("fetchOutbox calls correct endpoint with status filter", async () => {
    const { apiClient } = await import("@/lib/api-client")
    const mockedClient = vi.mocked(apiClient)
    mockedClient.mockResolvedValueOnce([])

    const { fetchOutbox } = await import("./channels")
    await fetchOutbox("dead")

    expect(mockedClient).toHaveBeenCalledWith(
      "/api/v1/channels/outbox",
      { params: { status: "dead", limit: "100" } },
    )
  })

  it("fetchOutbox omits status param when 'all'", async () => {
    const { apiClient } = await import("@/lib/api-client")
    const mockedClient = vi.mocked(apiClient)
    mockedClient.mockResolvedValueOnce([])

    const { fetchOutbox } = await import("./channels")
    await fetchOutbox("all")

    expect(mockedClient).toHaveBeenCalledWith(
      "/api/v1/channels/outbox",
      { params: { limit: "100" } },
    )
  })

  it("fetchProviderCredential calls correct endpoint", async () => {
    const { apiClient } = await import("@/lib/api-client")
    const mockedClient = vi.mocked(apiClient)
    mockedClient.mockResolvedValueOnce({ provider: "slack", has_access_token: true })

    const { fetchProviderCredential } = await import("./channels")
    await fetchProviderCredential("slack")

    expect(mockedClient).toHaveBeenCalledWith(
      "/api/v1/channels/providers/slack/credentials",
      undefined,
    )
  })

  it("createChannelLink posts to correct endpoint", async () => {
    const { apiClient } = await import("@/lib/api-client")
    const mockedClient = vi.mocked(apiClient)
    mockedClient.mockResolvedValueOnce({ id: "link-1" })

    const { createChannelLink } = await import("./channels")
    await createChannelLink({
      user_id: "u-1",
      platform: "slack",
      platform_user_id: "U12345",
    })

    expect(mockedClient).toHaveBeenCalledWith(
      "/api/v1/channels/links",
      {
        method: "POST",
        body: JSON.stringify({
          user_id: "u-1",
          platform: "slack",
          platform_user_id: "U12345",
        }),
      },
    )
  })

  it("deleteChannelLink calls correct endpoint", async () => {
    const { apiClient } = await import("@/lib/api-client")
    const mockedClient = vi.mocked(apiClient)
    mockedClient.mockResolvedValueOnce(undefined)

    const { deleteChannelLink } = await import("./channels")
    await deleteChannelLink("link-1")

    expect(mockedClient).toHaveBeenCalledWith(
      "/api/v1/channels/links/link-1",
      { method: "DELETE" },
    )
  })

  it("requeueOutboxJob posts to correct endpoint", async () => {
    const { apiClient } = await import("@/lib/api-client")
    const mockedClient = vi.mocked(apiClient)
    mockedClient.mockResolvedValueOnce({ status: "requeued" })

    const { requeueOutboxJob } = await import("./channels")
    await requeueOutboxJob("job-1")

    expect(mockedClient).toHaveBeenCalledWith(
      "/api/v1/channels/outbox/job-1/requeue",
      { method: "POST" },
    )
  })

  it("upsertProviderCredential puts to correct endpoint", async () => {
    const { apiClient } = await import("@/lib/api-client")
    const mockedClient = vi.mocked(apiClient)
    mockedClient.mockResolvedValueOnce({ provider: "slack" })

    const { upsertProviderCredential } = await import("./channels")
    await upsertProviderCredential("slack", {
      access_token: "xoxb-test",
      signing_secret: "secret",
    })

    expect(mockedClient).toHaveBeenCalledWith(
      "/api/v1/channels/providers/slack/credentials",
      {
        method: "PUT",
        body: JSON.stringify({
          access_token: "xoxb-test",
          signing_secret: "secret",
        }),
      },
    )
  })

  it("deleteProviderCredential calls correct endpoint", async () => {
    const { apiClient } = await import("@/lib/api-client")
    const mockedClient = vi.mocked(apiClient)
    mockedClient.mockResolvedValueOnce(undefined)

    const { deleteProviderCredential } = await import("./channels")
    await deleteProviderCredential("whatsapp")

    expect(mockedClient).toHaveBeenCalledWith(
      "/api/v1/channels/providers/whatsapp/credentials",
      { method: "DELETE" },
    )
  })
})
