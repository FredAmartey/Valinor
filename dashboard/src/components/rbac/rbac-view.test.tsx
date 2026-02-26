import { render, screen, cleanup } from "@testing-library/react"
import { describe, it, expect, vi, afterEach } from "vitest"
import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { SessionProvider } from "next-auth/react"

vi.mock("@/lib/queries/roles", () => ({
  useRolesQuery: () => ({
    data: [
      { id: "1", name: "org_admin", permissions: ["*"], is_system: true, tenant_id: "t1", created_at: "2025-01-01" },
      { id: "2", name: "custom", permissions: ["agents:read"], is_system: false, tenant_id: "t1", created_at: "2025-01-01" },
    ],
    isLoading: false,
  }),
  useCreateRoleMutation: () => ({ mutate: vi.fn(), isPending: false, isError: false }),
  useUpdateRoleMutation: () => ({ mutate: vi.fn(), isPending: false, isError: false }),
  useDeleteRoleMutation: () => ({ mutate: vi.fn(), isPending: false, isError: false }),
  roleKeys: { list: () => ["roles", "list"] },
}))

import { RBACView } from "./rbac-view"

afterEach(() => cleanup())

function wrapper({ children }: { children: React.ReactNode }) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return (
    <SessionProvider session={{ user: { name: "test" }, expires: "2099-01-01" } as any}>
      <QueryClientProvider client={qc}>{children}</QueryClientProvider>
    </SessionProvider>
  )
}

describe("RBACView", () => {
  it("renders role list with system and custom roles", () => {
    render(<RBACView />, { wrapper })
    expect(screen.getByText("org_admin")).toBeDefined()
    expect(screen.getByText("custom")).toBeDefined()
    expect(screen.getByText("System")).toBeDefined()
  })

  it("shows placeholder when no role selected", () => {
    render(<RBACView />, { wrapper })
    expect(screen.getByText("Select a role to view permissions.")).toBeDefined()
  })
})
