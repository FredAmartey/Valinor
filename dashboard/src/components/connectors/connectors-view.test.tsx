import { describe, it, expect, vi, beforeEach, afterEach } from "vitest"
import { render, screen, cleanup } from "@testing-library/react"

vi.mock("@/lib/api-error", () => ({
  ApiError: class MockApiError extends Error {
    status: number
    constructor(status: number) {
      super(`API error ${status}`)
      this.name = "ApiError"
      this.status = status
    }
  },
}))

vi.mock("next-auth/react", () => ({
  useSession: vi.fn().mockReturnValue({
    data: { accessToken: "test-token", user: { id: "u-1", isPlatformAdmin: false, tenantId: "t-1" } },
    status: "authenticated",
  }),
}))

vi.mock("@tanstack/react-query", () => ({
  useQuery: vi.fn().mockReturnValue({ data: [], isLoading: false, isError: false }),
  useMutation: vi.fn().mockReturnValue({ mutate: vi.fn(), isPending: false, isError: false }),
  useQueryClient: vi.fn().mockReturnValue({ invalidateQueries: vi.fn() }),
}))

const mockUseConnectorsQuery = vi.fn()
const mockUseCreateConnectorMutation = vi.fn()
const mockUseDeleteConnectorMutation = vi.fn()

vi.mock("@/lib/queries/connectors", () => ({
  useConnectorsQuery: (...args: unknown[]) => mockUseConnectorsQuery(...args),
  useCreateConnectorMutation: (...args: unknown[]) => mockUseCreateConnectorMutation(...args),
  useDeleteConnectorMutation: (...args: unknown[]) => mockUseDeleteConnectorMutation(...args),
  connectorKeys: {
    all: ["connectors"],
    list: () => ["connectors", "list"],
  },
}))

const defaultMutationReturn = { mutate: vi.fn(), isPending: false, isError: false }

afterEach(() => {
  cleanup()
})

beforeEach(() => {
  vi.clearAllMocks()
  mockUseCreateConnectorMutation.mockReturnValue(defaultMutationReturn)
  mockUseDeleteConnectorMutation.mockReturnValue(defaultMutationReturn)
})

describe("ConnectorsView", () => {
  it("shows loading skeleton", async () => {
    mockUseConnectorsQuery.mockReturnValue({ data: undefined, isLoading: true, isError: false })
    const { ConnectorsView } = await import("./connectors-view")
    const { container } = render(<ConnectorsView canWrite={true} />)
    expect(container.querySelectorAll("[class*='skeleton'], [class*='animate']").length).toBeGreaterThan(0)
  })

  it("shows error state with retry", async () => {
    const refetch = vi.fn()
    mockUseConnectorsQuery.mockReturnValue({ data: undefined, isLoading: false, isError: true, refetch })
    const { ConnectorsView } = await import("./connectors-view")
    render(<ConnectorsView canWrite={true} />)
    expect(screen.getByText("Failed to load connectors.")).toBeDefined()
  })

  it("shows empty state", async () => {
    mockUseConnectorsQuery.mockReturnValue({ data: [], isLoading: false, isError: false })
    const { ConnectorsView } = await import("./connectors-view")
    render(<ConnectorsView canWrite={true} />)
    expect(screen.getByText("No connectors registered")).toBeDefined()
  })

  it("renders connector rows with status pills", async () => {
    mockUseConnectorsQuery.mockReturnValue({
      data: [
        { id: "c-1", tenant_id: "t-1", name: "scout-mcp", connector_type: "mcp", endpoint: "https://api.example.com/mcp", resources: [], tools: ["search", "fetch"], status: "active", created_at: "2026-01-01T00:00:00Z" },
        { id: "c-2", tenant_id: "t-1", name: "legal-mcp", connector_type: "mcp", endpoint: "https://legal.ai/mcp", resources: [], tools: [], status: "inactive", created_at: "2026-01-02T00:00:00Z" },
      ],
      isLoading: false,
      isError: false,
    })
    const { ConnectorsView } = await import("./connectors-view")
    render(<ConnectorsView canWrite={true} />)
    expect(screen.getByText("scout-mcp")).toBeDefined()
    expect(screen.getByText("legal-mcp")).toBeDefined()
    const activePill = screen.getByText("active")
    expect(activePill.className).toContain("emerald")
    const inactivePill = screen.getByText("inactive")
    expect(inactivePill.className).toContain("zinc")
  })

  it("hides register button and delete buttons when canWrite is false", async () => {
    mockUseConnectorsQuery.mockReturnValue({
      data: [
        { id: "c-1", tenant_id: "t-1", name: "scout-mcp", connector_type: "mcp", endpoint: "https://api.example.com/mcp", resources: [], tools: [], status: "active", created_at: "2026-01-01T00:00:00Z" },
      ],
      isLoading: false,
      isError: false,
    })
    const { ConnectorsView } = await import("./connectors-view")
    render(<ConnectorsView canWrite={false} />)
    expect(screen.queryByText("Register connector")).toBeNull()
    expect(screen.queryByTitle("Delete connector")).toBeNull()
  })

  it("shows delete error when mutation fails", async () => {
    mockUseConnectorsQuery.mockReturnValue({
      data: [
        { id: "c-1", tenant_id: "t-1", name: "scout-mcp", connector_type: "mcp", endpoint: "https://api.example.com/mcp", resources: [], tools: [], status: "active", created_at: "2026-01-01T00:00:00Z" },
      ],
      isLoading: false,
      isError: false,
    })
    mockUseDeleteConnectorMutation.mockReturnValue({
      mutate: vi.fn(),
      isPending: false,
      isError: true,
      error: new Error("network failure"),
    })
    const { ConnectorsView } = await import("./connectors-view")
    render(<ConnectorsView canWrite={true} />)
    expect(screen.getByText("Failed to delete connector.")).toBeDefined()
  })
})
