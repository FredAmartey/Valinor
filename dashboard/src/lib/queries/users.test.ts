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
    await fetchUsers()

    expect(mockedClient).toHaveBeenCalledWith(
      "/api/v1/users",
      undefined,
    )
  })

  it("fetchUser calls correct endpoint with ID", async () => {
    const { apiClient } = await import("@/lib/api-client")
    const mockedClient = vi.mocked(apiClient)
    mockedClient.mockResolvedValueOnce({ id: "u-1", email: "a@b.com" })

    const { fetchUser } = await import("./users")
    await fetchUser("u-1")

    expect(mockedClient).toHaveBeenCalledWith(
      "/api/v1/users/u-1",
      undefined,
    )
  })

  it("createUser posts to correct endpoint", async () => {
    const { apiClient } = await import("@/lib/api-client")
    const mockedClient = vi.mocked(apiClient)
    mockedClient.mockResolvedValueOnce({ id: "u-2", email: "new@b.com" })

    const { createUser } = await import("./users")
    await createUser({ email: "new@b.com", display_name: "New User" })

    expect(mockedClient).toHaveBeenCalledWith(
      "/api/v1/users",
      {
        method: "POST",
        body: JSON.stringify({ email: "new@b.com", display_name: "New User" }),
      },
    )
  })

  it("fetchUserDepartments calls correct endpoint", async () => {
    const { apiClient } = await import("@/lib/api-client")
    const mockedClient = vi.mocked(apiClient)
    mockedClient.mockResolvedValueOnce([{ id: "d-1", name: "Engineering" }])

    const { fetchUserDepartments } = await import("./users")
    await fetchUserDepartments("u-1")

    expect(mockedClient).toHaveBeenCalledWith(
      "/api/v1/users/u-1/departments",
      undefined,
    )
  })

  it("addUserToDepartment posts to correct endpoint", async () => {
    const { apiClient } = await import("@/lib/api-client")
    const mockedClient = vi.mocked(apiClient)
    mockedClient.mockResolvedValueOnce({ status: "ok" })

    const { addUserToDepartment } = await import("./users")
    await addUserToDepartment("u-1", "d-1")

    expect(mockedClient).toHaveBeenCalledWith(
      "/api/v1/users/u-1/departments",
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
    await removeUserFromDepartment("u-1", "d-1")

    expect(mockedClient).toHaveBeenCalledWith(
      "/api/v1/users/u-1/departments/d-1",
      { method: "DELETE" },
    )
  })
})
