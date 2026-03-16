import { describe, expect, it } from "vitest"
import { render, screen } from "@testing-library/react"

import { AuthCard } from "./auth-card"

describe("AuthCard", () => {
  it("renders Heimdall branding", () => {
    render(
      <AuthCard>
        <p>Child content</p>
      </AuthCard>,
    )

    expect(screen.getByRole("heading", { name: "Heimdall" })).toBeInTheDocument()
  })
})
