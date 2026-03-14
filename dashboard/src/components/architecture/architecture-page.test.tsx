import { describe, it, expect } from "vitest"
import { render, screen } from "@testing-library/react"

import { ThemeProvider } from "@/components/landing/theme"

describe("ArchitecturePage", () => {
  it("renders the key architecture sections", async () => {
    const { ArchitecturePage } = await import("./architecture-page")

    render(
      <ThemeProvider>
        <ArchitecturePage />
      </ThemeProvider>,
    )

    expect(screen.getByText("Architecture built for broad-access AI agents")).toBeDefined()
    expect(screen.getByText("Trust boundaries")).toBeDefined()
    expect(screen.getByText("Lifecycle security")).toBeDefined()
    expect(screen.getByText("Product tiers")).toBeDefined()
    expect(screen.getByText("Channels and integrations")).toBeDefined()
    expect(screen.getByRole("link", { name: /read the technical architecture/i })).toBeDefined()
  })
})
