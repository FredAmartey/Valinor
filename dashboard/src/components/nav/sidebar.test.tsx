import { describe, it, expect, vi, beforeEach } from "vitest"
import { render, screen, cleanup } from "@testing-library/react"

// Mock next-auth
vi.mock("next-auth/react", () => ({
  useSession: vi.fn().mockReturnValue({
    data: {
      user: {
        id: "user-1",
        name: "Test Admin",
        email: "admin@test.com",
        isPlatformAdmin: true,
        tenantId: null,
      },
    },
    status: "authenticated",
  }),
}))

// Mock next/navigation
vi.mock("next/navigation", () => ({
  usePathname: vi.fn().mockReturnValue("/"),
}))

describe("Sidebar", () => {
  beforeEach(() => {
    cleanup()
  })

  it("renders Overview link for all users", async () => {
    const { Sidebar } = await import("./sidebar")
    render(<Sidebar />)
    expect(screen.getByText("Overview")).toBeDefined()
  })

  it("renders Tenants link for platform admin", async () => {
    const { Sidebar } = await import("./sidebar")
    render(<Sidebar />)
    expect(screen.getByText("Tenants")).toBeDefined()
  })
})
