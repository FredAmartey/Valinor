import { describe, it, expect } from "vitest"

describe("buildHierarchy", () => {
  it("sorts departments into tree order with depth", async () => {
    const { buildHierarchy } = await import("./department-table")

    const departments = [
      { id: "d-3", tenant_id: "t-1", name: "Sub-Scouting", parent_id: "d-1", created_at: "" },
      { id: "d-1", tenant_id: "t-1", name: "Scouting", parent_id: null, created_at: "" },
      { id: "d-2", tenant_id: "t-1", name: "First Team", parent_id: null, created_at: "" },
    ]

    const result = buildHierarchy(departments)

    expect(result).toEqual([
      { department: departments[1], depth: 0 },  // Scouting (top-level)
      { department: departments[0], depth: 1 },  // Sub-Scouting (child of Scouting)
      { department: departments[2], depth: 0 },  // First Team (top-level)
    ])
  })

  it("returns empty for empty input", async () => {
    const { buildHierarchy } = await import("./department-table")
    expect(buildHierarchy([])).toEqual([])
  })
})
