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

    expect(screen.getByText("Architecture built for broad-access AI agents")).toBeInTheDocument()
    expect(screen.getByText("Trust boundaries")).toBeInTheDocument()
    expect(screen.getByText("Lifecycle security")).toBeInTheDocument()
    expect(screen.getByText("Product tiers")).toBeInTheDocument()
    expect(screen.getAllByText("Channels and integrations")).toHaveLength(2)
    expect(screen.getByRole("link", { name: /read the technical architecture/i })).toBeInTheDocument()
  })
})
