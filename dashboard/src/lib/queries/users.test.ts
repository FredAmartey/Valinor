import { describe, it, expect, vi } from "vitest"

vi.mock("@/lib/api-client", () => ({
  apiClient: vi.fn(),
}))

describe("user query functions", () => {
  it("fetchUsers calls correct endpoint", async () => {
    const { apiClient } = await import("@/lib/api-client")
    const mockedClient = vi.mocked(apiClient)
    mockedClient.mockResolvedValueOnce([])

    const { fetchUsers } = await import("./users")
    await fetchUsers("test-token")

    expect(mockedClient).toHaveBeenCalledWith(
      "/api/v1/users",
      "test-token",
      undefined,
    )
  })

  it("fetchUser calls correct endpoint with ID", async () => {
    const { apiClient } = await import("@/lib/api-client")
    const mockedClient = vi.mocked(apiClient)
    mockedClient.mockResolvedValueOnce({ id: "u-1", email: "a@b.com" })

    const { fetchUser } = await import("./users")
    await fetchUser("test-token", "u-1")

    expect(mockedClient).toHaveBeenCalledWith(
      "/api/v1/users/u-1",
      "test-token",
      undefined,
    )
  })

  it("createUser posts to correct endpoint", async () => {
    const { apiClient } = await import("@/lib/api-client")
    const mockedClient = vi.mocked(apiClient)
    mockedClient.mockResolvedValueOnce({ id: "u-2", email: "new@b.com" })

    const { createUser } = await import("./users")
    await createUser("test-token", { email: "new@b.com", display_name: "New User" })

    expect(mockedClient).toHaveBeenCalledWith(
      "/api/v1/users",
      "test-token",
      {
        method: "POST",
        body: JSON.stringify({ email: "new@b.com", display_name: "New User" }),
      },
    )
  })

  it("addUserToDepartment posts to correct endpoint", async () => {
    const { apiClient } = await import("@/lib/api-client")
    const mockedClient = vi.mocked(apiClient)
    mockedClient.mockResolvedValueOnce({ status: "ok" })

    const { addUserToDepartment } = await import("./users")
    await addUserToDepartment("test-token", "u-1", "d-1")

    expect(mockedClient).toHaveBeenCalledWith(
      "/api/v1/users/u-1/departments",
      "test-token",
      {
        method: "POST",
        body: JSON.stringify({ department_id: "d-1" }),
      },
    )
  })

  it("removeUserFromDepartment deletes correct endpoint", async () => {
    const { apiClient } = await import("@/lib/api-client")
    const mockedClient = vi.mocked(apiClient)
    mockedClient.mockResolvedValueOnce({ status: "ok" })

    const { removeUserFromDepartment } = await import("./users")
    await removeUserFromDepartment("test-token", "u-1", "d-1")

    expect(mockedClient).toHaveBeenCalledWith(
      "/api/v1/users/u-1/departments/d-1",
      "test-token",
      { method: "DELETE" },
    )
  })
})
