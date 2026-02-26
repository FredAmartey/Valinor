import { describe, it, expect, vi } from "vitest"
import { render, screen, fireEvent } from "@testing-library/react"

// Mock next-auth
vi.mock("next-auth/react", () => ({
  useSession: () => ({
    data: { accessToken: "test-token", user: { isPlatformAdmin: false, roles: [] } },
  }),
}))

// Mock TanStack Query
const mockUseAuditEventsQuery = vi.fn()
vi.mock("@/lib/queries/audit", () => ({
  useAuditEventsQuery: (...args: unknown[]) => mockUseAuditEventsQuery(...args),
}))

import { AuditLog } from "./audit-log"

describe("AuditLog", () => {
  it("shows loading skeletons when loading", () => {
    mockUseAuditEventsQuery.mockReturnValue({
      data: undefined,
      isLoading: true,
      isError: false,
      refetch: vi.fn(),
    })

    render(<AuditLog />)
    const skeletons = document.querySelectorAll('[class*="animate-pulse"]')
    expect(skeletons.length).toBeGreaterThan(0)
  })

  it("shows error state with retry button on failure", () => {
    const mockRefetch = vi.fn()
    mockUseAuditEventsQuery.mockReturnValue({
      data: undefined,
      isLoading: false,
      isError: true,
      refetch: mockRefetch,
    })

    render(<AuditLog />)
    expect(screen.getByText("Failed to load audit events.")).toBeTruthy()

    const retryBtn = screen.getByText("Retry")
    expect(retryBtn).toBeTruthy()
    fireEvent.click(retryBtn)
    expect(mockRefetch).toHaveBeenCalled()
  })

  it("shows empty state when no events", () => {
    mockUseAuditEventsQuery.mockReturnValue({
      data: { events: [], count: 0 },
      isLoading: false,
      isError: false,
      refetch: vi.fn(),
    })

    render(<AuditLog />)
    expect(screen.getByText("No events recorded yet")).toBeTruthy()
  })

  it("renders events in table with ARIA roles", () => {
    mockUseAuditEventsQuery.mockReturnValue({
      data: {
        events: [
          {
            id: "evt-1",
            tenant_id: "t-1",
            user_id: "u-1",
            action: "user.created",
            resource_type: "user",
            resource_id: "u-2",
            metadata: { email: "test@example.com" },
            source: "api",
            created_at: new Date().toISOString(),
          },
        ],
        count: 1,
      },
      isLoading: false,
      isError: false,
      refetch: vi.fn(),
    })

    render(<AuditLog />)
    expect(screen.getByText("User Created")).toBeTruthy()
    expect(screen.getByRole("table")).toBeTruthy()
    expect(screen.getByText("1 event")).toBeTruthy()
  })

  it("expands row to show details with ARIA attributes", () => {
    mockUseAuditEventsQuery.mockReturnValue({
      data: {
        events: [
          {
            id: "evt-1",
            tenant_id: "t-1",
            user_id: null,
            action: "tenant.created",
            resource_type: "tenant",
            resource_id: "t-2",
            metadata: { name: "Gondolin FC" },
            source: "api",
            created_at: new Date().toISOString(),
          },
        ],
        count: 1,
      },
      isLoading: false,
      isError: false,
      refetch: vi.fn(),
    })

    render(<AuditLog />)
    const toggleBtn = screen.getByText("Tenant Created").closest("button")!
    expect(toggleBtn.getAttribute("aria-expanded")).toBe("false")

    fireEvent.click(toggleBtn)
    expect(toggleBtn.getAttribute("aria-expanded")).toBe("true")
    expect(screen.getByRole("region")).toBeTruthy()
    expect(screen.getByText("name:")).toBeTruthy()
    expect(screen.getByText("Gondolin FC")).toBeTruthy()
  })

  it("renders action, resource, source, and date filters", () => {
    mockUseAuditEventsQuery.mockReturnValue({
      data: { events: [], count: 0 },
      isLoading: false,
      isError: false,
      refetch: vi.fn(),
    })

    const { container } = render(<AuditLog />)
    // 3 select dropdowns (action, resource, source)
    const selects = container.querySelectorAll("select")
    expect(selects.length).toBe(3)
    // 2 date inputs
    const dateInputs = container.querySelectorAll('input[type="date"]')
    expect(dateInputs.length).toBe(2)
    // Search input exists
    const searchInputs = container.querySelectorAll('input[placeholder="Search by ID..."]')
    expect(searchInputs.length).toBeGreaterThan(0)
  })
})
