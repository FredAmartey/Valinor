import { describe, it, expect } from "vitest"
import { render, screen } from "@testing-library/react"

import { ThemeProvider } from "@/components/landing/theme"

describe("ArchitectureDiagram", () => {
  it("renders the trust layers and runtime tiers", async () => {
    const { ArchitectureDiagram } = await import("./architecture-diagram")

    render(
      <ThemeProvider>
        <ArchitectureDiagram />
      </ThemeProvider>,
    )

    expect(screen.getByText("Users and operators")).toBeDefined()
    expect(screen.getByText("Valinor control plane")).toBeDefined()
    expect(screen.getByText("Policy and approvals")).toBeDefined()
    expect(screen.getByText("Activity and audit")).toBeDefined()
    expect(screen.getByText("Teams runtime")).toBeDefined()
    expect(screen.getByText("Enterprise runtime")).toBeDefined()
    expect(screen.getByText("OpenClaw runtime")).toBeDefined()
    expect(screen.getByText("Channels and integrations")).toBeDefined()
  })
})
