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

    expect(screen.getByText("Users and operators")).toBeInTheDocument()
    expect(screen.getByText("Heimdall control plane")).toBeInTheDocument()
    expect(screen.getByText("Policy and approvals")).toBeInTheDocument()
    expect(screen.getByText("Activity and audit")).toBeInTheDocument()
    expect(screen.getByText("Teams runtime")).toBeInTheDocument()
    expect(screen.getByText("Enterprise runtime")).toBeInTheDocument()
    expect(screen.getByText("OpenClaw runtime")).toBeInTheDocument()
    expect(screen.getByText("Channels and integrations")).toBeInTheDocument()
  })
})
