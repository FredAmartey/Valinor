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
    })

    render(<AuditLog />)
    const skeletons = document.querySelectorAll('[class*="animate-pulse"]')
    expect(skeletons.length).toBeGreaterThan(0)
  })

  it("shows error state on failure", () => {
    mockUseAuditEventsQuery.mockReturnValue({
      data: undefined,
      isLoading: false,
      isError: true,
    })

    render(<AuditLog />)
    expect(screen.getByText("Failed to load audit events.")).toBeTruthy()
  })

  it("shows empty state when no events", () => {
    mockUseAuditEventsQuery.mockReturnValue({
      data: { events: [], count: 0 },
      isLoading: false,
      isError: false,
    })

    render(<AuditLog />)
    expect(screen.getByText("No events recorded yet")).toBeTruthy()
  })

  it("renders events in table", () => {
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
    })

    render(<AuditLog />)
    expect(screen.getByText("User Created")).toBeTruthy()
    expect(screen.getAllByText("API").length).toBeGreaterThan(0)
    expect(screen.getByText("1 event")).toBeTruthy()
  })

  it("expands row to show details on click", () => {
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
    })

    render(<AuditLog />)
    fireEvent.click(screen.getByText("Tenant Created"))
    expect(screen.getByText("name:")).toBeTruthy()
    expect(screen.getByText("Gondolin FC")).toBeTruthy()
  })
})
