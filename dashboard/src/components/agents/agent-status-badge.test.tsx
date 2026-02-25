import { describe, it, expect } from "vitest"
import { render, screen } from "@testing-library/react"

describe("AgentStatusBadge", () => {
  it("renders running status with correct styling", async () => {
    const { AgentStatusBadge } = await import("./agent-status-badge")
    render(<AgentStatusBadge status="running" />)
    const badge = screen.getByText("running")
    expect(badge).toBeDefined()
    expect(badge.className).toContain("emerald")
  })

  it("renders unhealthy status with rose styling", async () => {
    const { AgentStatusBadge } = await import("./agent-status-badge")
    render(<AgentStatusBadge status="unhealthy" />)
    const badge = screen.getByText("unhealthy")
    expect(badge.className).toContain("rose")
  })

  it("renders provisioning status with amber styling", async () => {
    const { AgentStatusBadge } = await import("./agent-status-badge")
    render(<AgentStatusBadge status="provisioning" />)
    const badge = screen.getByText("provisioning")
    expect(badge.className).toContain("amber")
  })
})
