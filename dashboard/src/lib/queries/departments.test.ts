import { describe, it, expect, vi } from "vitest"

vi.mock("@/lib/api-client", () => ({
  apiClient: vi.fn(),
}))

describe("department query functions", () => {
  it("fetchDepartments calls correct endpoint", async () => {
    const { apiClient } = await import("@/lib/api-client")
    const mockedClient = vi.mocked(apiClient)
    mockedClient.mockResolvedValueOnce([])

    const { fetchDepartments } = await import("./departments")
    await fetchDepartments()

    expect(mockedClient).toHaveBeenCalledWith(
      "/api/v1/departments",
      undefined,
    )
  })

  it("fetchDepartment calls correct endpoint with ID", async () => {
    const { apiClient } = await import("@/lib/api-client")
    const mockedClient = vi.mocked(apiClient)
    mockedClient.mockResolvedValueOnce({ id: "d-1", name: "Engineering" })

    const { fetchDepartment } = await import("./departments")
    await fetchDepartment("d-1")

    expect(mockedClient).toHaveBeenCalledWith(
      "/api/v1/departments/d-1",
      undefined,
    )
  })

  it("createDepartment posts to correct endpoint", async () => {
    const { apiClient } = await import("@/lib/api-client")
    const mockedClient = vi.mocked(apiClient)
    mockedClient.mockResolvedValueOnce({ id: "d-2", name: "Scouting" })

    const { createDepartment } = await import("./departments")
    await createDepartment({ name: "Scouting", parent_id: "d-1" })

    expect(mockedClient).toHaveBeenCalledWith(
      "/api/v1/departments",
      {
        method: "POST",
        body: JSON.stringify({ name: "Scouting", parent_id: "d-1" }),
      },
    )
  })
})
