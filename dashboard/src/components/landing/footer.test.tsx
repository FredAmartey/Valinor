import { describe, it, expect } from "vitest"
import { render, screen } from "@testing-library/react"

import { ThemeProvider } from "./theme"

describe("FooterCta", () => {
  it("links to architecture and docs", async () => {
    const { FooterCta } = await import("./footer")

    render(
      <ThemeProvider>
        <FooterCta />
      </ThemeProvider>,
    )

    expect(screen.getByRole("link", { name: "Architecture" })).toHaveAttribute("href", "/architecture")
    expect(screen.getByRole("link", { name: "Docs" })).toHaveAttribute(
      "href",
      expect.stringContaining("/docs/architecture.md"),
    )
  })
})
