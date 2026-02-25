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

// Mock permission provider — grant all permissions by default
vi.mock("@/components/providers/permission-provider", () => ({
  useCan: vi.fn().mockReturnValue(true),
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

  it("renders tenant admin nav items and hides Tenants link", async () => {
    const { useSession } = await import("next-auth/react")
    vi.mocked(useSession).mockReturnValue({
      data: {
        user: {
          id: "user-2",
          name: "Tenant Admin",
          email: "tenant@test.com",
          isPlatformAdmin: false,
          tenantId: "t-1",
        },
      },
      status: "authenticated",
    } as ReturnType<typeof useSession>)

    const { Sidebar } = await import("./sidebar")
    render(<Sidebar />)

    // Tenant admin nav items should be present
    expect(screen.getByText("Users")).toBeDefined()
    expect(screen.getByText("Departments")).toBeDefined()
    expect(screen.getByText("Agents")).toBeDefined()

    // Tenants link should NOT be present for tenant admins
    expect(screen.queryByText("Tenants")).toBeNull()
  })
})
