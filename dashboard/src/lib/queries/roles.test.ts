import { describe, it, expect, vi } from "vitest"

vi.mock("@/lib/api-client", () => ({
  apiClient: vi.fn(),
}))

describe("role query functions", () => {
  it("fetchRoles calls correct endpoint", async () => {
    const { apiClient } = await import("@/lib/api-client")
    const mockedClient = vi.mocked(apiClient)
    mockedClient.mockResolvedValueOnce([])

    const { fetchRoles } = await import("./roles")
    await fetchRoles()

    expect(mockedClient).toHaveBeenCalledWith(
      "/api/v1/roles",
      undefined,
    )
  })

  it("fetchUserRoles calls correct endpoint", async () => {
    const { apiClient } = await import("@/lib/api-client")
    const mockedClient = vi.mocked(apiClient)
    mockedClient.mockResolvedValueOnce([])

    const { fetchUserRoles } = await import("./roles")
    await fetchUserRoles("u-1")

    expect(mockedClient).toHaveBeenCalledWith(
      "/api/v1/users/u-1/roles",
      undefined,
    )
  })

  it("assignRole posts to correct endpoint", async () => {
    const { apiClient } = await import("@/lib/api-client")
    const mockedClient = vi.mocked(apiClient)
    mockedClient.mockResolvedValueOnce({ status: "ok" })

    const { assignRole } = await import("./roles")
    await assignRole("u-1", {
      role_id: "r-1",
      scope_type: "org",
      scope_id: "t-1",
    })

    expect(mockedClient).toHaveBeenCalledWith(
      "/api/v1/users/u-1/roles",
      {
        method: "POST",
        body: JSON.stringify({ role_id: "r-1", scope_type: "org", scope_id: "t-1" }),
      },
    )
  })

  it("removeRole deletes with correct body", async () => {
    const { apiClient } = await import("@/lib/api-client")
    const mockedClient = vi.mocked(apiClient)
    mockedClient.mockResolvedValueOnce({ status: "ok" })

    const { removeRole } = await import("./roles")
    await removeRole("u-1", {
      role_id: "r-1",
      scope_type: "department",
      scope_id: "d-1",
    })

    expect(mockedClient).toHaveBeenCalledWith(
      "/api/v1/users/u-1/roles",
      {
        method: "DELETE",
        body: JSON.stringify({ role_id: "r-1", scope_type: "department", scope_id: "d-1" }),
      },
    )
  })
})
