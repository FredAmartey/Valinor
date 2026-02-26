import { describe, it, expect, vi, beforeEach, afterEach } from "vitest"
import { render, screen, fireEvent, cleanup } from "@testing-library/react"

// --- Mock ApiError class (matches the real shape) ---

class MockApiError extends Error {
  status: number
  constructor(status: number) {
    super(`API error ${status}`)
    this.name = "ApiError"
    this.status = status
  }
}

vi.mock("@/lib/api-error", () => ({
  ApiError: MockApiError,
}))

// --- Shared mocks ---

vi.mock("next-auth/react", () => ({
  useSession: vi.fn().mockReturnValue({
    data: { accessToken: "test-token", user: { id: "u-1", isPlatformAdmin: false, tenantId: "t-1" } },
    status: "authenticated",
  }),
}))

vi.mock("next/navigation", () => ({
  useRouter: vi.fn().mockReturnValue({ push: vi.fn() }),
}))

vi.mock("@tanstack/react-query", () => ({
  useQuery: vi.fn().mockReturnValue({ data: [], isLoading: false, isError: false }),
  useMutation: vi.fn().mockReturnValue({ mutate: vi.fn(), isPending: false, isError: false }),
  useQueryClient: vi.fn().mockReturnValue({ invalidateQueries: vi.fn() }),
  keepPreviousData: Symbol("keepPreviousData"),
}))

// Mock the query hooks module so we can control return values per test
const mockUseChannelLinksQuery = vi.fn()
const mockUseOutboxQuery = vi.fn()
const mockUseProviderCredentialQuery = vi.fn()
const mockUseCreateChannelLinkMutation = vi.fn()
const mockUseDeleteChannelLinkMutation = vi.fn()
const mockUseRequeueOutboxMutation = vi.fn()
const mockUseUpsertProviderCredentialMutation = vi.fn()
const mockUseDeleteProviderCredentialMutation = vi.fn()

vi.mock("@/lib/queries/channels", () => ({
  useChannelLinksQuery: (...args: unknown[]) => mockUseChannelLinksQuery(...args),
  useOutboxQuery: (...args: unknown[]) => mockUseOutboxQuery(...args),
  useProviderCredentialQuery: (...args: unknown[]) => mockUseProviderCredentialQuery(...args),
  useCreateChannelLinkMutation: (...args: unknown[]) => mockUseCreateChannelLinkMutation(...args),
  useDeleteChannelLinkMutation: (...args: unknown[]) => mockUseDeleteChannelLinkMutation(...args),
  useRequeueOutboxMutation: (...args: unknown[]) => mockUseRequeueOutboxMutation(...args),
  useUpsertProviderCredentialMutation: (...args: unknown[]) => mockUseUpsertProviderCredentialMutation(...args),
  useDeleteProviderCredentialMutation: (...args: unknown[]) => mockUseDeleteProviderCredentialMutation(...args),
  channelKeys: {
    all: ["channels"],
    links: () => ["channels", "links"],
    outbox: () => ["channels", "outbox"],
    provider: (n: string) => ["channels", "provider", n],
  },
}))

const defaultMutationReturn = { mutate: vi.fn(), isPending: false, isError: false }

afterEach(() => {
  cleanup()
})

beforeEach(() => {
  vi.clearAllMocks()
  mockUseCreateChannelLinkMutation.mockReturnValue(defaultMutationReturn)
  mockUseDeleteChannelLinkMutation.mockReturnValue(defaultMutationReturn)
  mockUseRequeueOutboxMutation.mockReturnValue(defaultMutationReturn)
  mockUseUpsertProviderCredentialMutation.mockReturnValue(defaultMutationReturn)
  mockUseDeleteProviderCredentialMutation.mockReturnValue(defaultMutationReturn)
})

// ─── ChannelsView: Tab switching ─────────────────────────────────

describe("ChannelsView", () => {
  beforeEach(() => {
    mockUseChannelLinksQuery.mockReturnValue({ data: [], isLoading: false, isError: false })
    mockUseOutboxQuery.mockReturnValue({ data: [], isLoading: false, isError: false })
    mockUseProviderCredentialQuery.mockReturnValue({
      data: null,
      isLoading: false,
      isError: true,
      error: new MockApiError(404),
    })
  })

  it("renders links tab by default", async () => {
    const { ChannelsView } = await import("./channels-view")
    render(<ChannelsView />)
    expect(screen.getByText("No channel links")).toBeDefined()
  })

  it("switches to providers tab", async () => {
    const { ChannelsView } = await import("./channels-view")
    render(<ChannelsView />)
    fireEvent.click(screen.getByText("Providers"))
    expect(screen.getByText("Slack")).toBeDefined()
    expect(screen.getByText("WhatsApp")).toBeDefined()
    expect(screen.getByText("Telegram")).toBeDefined()
  })

  it("switches to outbox tab", async () => {
    const { ChannelsView } = await import("./channels-view")
    render(<ChannelsView />)
    fireEvent.click(screen.getByText("Outbox"))
    expect(screen.getByText("No outbox jobs")).toBeDefined()
  })
})

// ─── LinksTab ────────────────────────────────────────────────────

describe("LinksTab", () => {
  it("shows loading skeleton", async () => {
    mockUseChannelLinksQuery.mockReturnValue({ data: undefined, isLoading: true, isError: false })
    const { LinksTab } = await import("./links-tab")
    const { container } = render(<LinksTab />)
    expect(container.querySelectorAll("[class*='skeleton'], [class*='animate']").length).toBeGreaterThan(0)
  })

  it("shows error state with retry", async () => {
    const refetch = vi.fn()
    mockUseChannelLinksQuery.mockReturnValue({ data: undefined, isLoading: false, isError: true, refetch })
    const { LinksTab } = await import("./links-tab")
    render(<LinksTab />)
    expect(screen.getByText("Failed to load channel links.")).toBeDefined()
    fireEvent.click(screen.getByText("Retry"))
    expect(refetch).toHaveBeenCalled()
  })

  it("shows empty state", async () => {
    mockUseChannelLinksQuery.mockReturnValue({ data: [], isLoading: false, isError: false })
    const { LinksTab } = await import("./links-tab")
    render(<LinksTab />)
    expect(screen.getByText("No channel links")).toBeDefined()
  })

  it("renders populated table with correct pill colors", async () => {
    mockUseChannelLinksQuery.mockReturnValue({
      data: [
        { id: "l-1", tenant_id: "t-1", user_id: "u-1", platform: "slack", platform_user_id: "U123", status: "verified", created_at: "2026-01-01T00:00:00Z" },
        { id: "l-2", tenant_id: "t-1", user_id: "u-2", platform: "whatsapp", platform_user_id: "+1234", status: "pending_verification", created_at: "2026-01-02T00:00:00Z" },
      ],
      isLoading: false,
      isError: false,
    })
    const { LinksTab } = await import("./links-tab")
    render(<LinksTab />)
    // "verified" appears in both filter dropdown and pill — find the pill by its class
    const verifiedPill = screen.getAllByText("verified").find((el) => el.className.includes("rounded-full"))!
    expect(verifiedPill).toBeDefined()
    expect(verifiedPill.className).toContain("emerald")
    const pendingPill = screen.getAllByText("pending verification").find((el) => el.className.includes("rounded-full"))!
    expect(pendingPill).toBeDefined()
    expect(pendingPill.className).toContain("amber")
  })
})

// ─── ProvidersTab ────────────────────────────────────────────────

describe("ProvidersTab", () => {
  it("renders 3 provider cards in not-configured state", async () => {
    mockUseProviderCredentialQuery.mockReturnValue({
      data: null,
      isLoading: false,
      isError: true,
      error: new MockApiError(404),
    })
    const { ProvidersTab } = await import("./providers-tab")
    render(<ProvidersTab />)
    expect(screen.getByText("Slack")).toBeDefined()
    expect(screen.getByText("WhatsApp")).toBeDefined()
    expect(screen.getByText("Telegram")).toBeDefined()
    expect(screen.getAllByText("Not configured").length).toBe(3)
  })

  it("shows configured provider with secret indicators", async () => {
    mockUseProviderCredentialQuery.mockImplementation((provider: string) => {
      if (provider === "slack") {
        return {
          data: {
            provider: "slack",
            has_access_token: true,
            has_signing_secret: false,
            has_secret_token: false,
            api_base_url: "",
            api_version: "",
            phone_number_id: "",
            updated_at: "2026-01-15T00:00:00Z",
          },
          isLoading: false,
          isError: false,
        }
      }
      return { data: null, isLoading: false, isError: true, error: new MockApiError(404) }
    })
    const { ProvidersTab } = await import("./providers-tab")
    render(<ProvidersTab />)
    expect(screen.getByText("Bot Token")).toBeDefined()
    expect(screen.getByText("Signing Secret")).toBeDefined()
  })
})

// ─── OutboxTab ───────────────────────────────────────────────────

describe("OutboxTab", () => {
  it("shows loading skeleton", async () => {
    mockUseOutboxQuery.mockReturnValue({ data: undefined, isLoading: true, isError: false })
    const { OutboxTab } = await import("./outbox-tab")
    const { container } = render(<OutboxTab />)
    expect(container.querySelectorAll("[class*='skeleton'], [class*='animate']").length).toBeGreaterThan(0)
  })

  it("shows empty state", async () => {
    mockUseOutboxQuery.mockReturnValue({ data: [], isLoading: false, isError: false })
    const { OutboxTab } = await import("./outbox-tab")
    render(<OutboxTab />)
    expect(screen.getByText("No outbox jobs")).toBeDefined()
  })

  it("renders data with requeue button only on dead jobs", async () => {
    mockUseOutboxQuery.mockReturnValue({
      data: [
        { id: "j-1", tenant_id: "t-1", channel_message_id: "m-1", provider: "slack", recipient_id: "r-1", payload: {}, status: "sent", attempt_count: 1, max_attempts: 5, next_attempt_at: "2026-01-01T00:00:00Z", last_error: null, locked_at: null, sent_at: "2026-01-01T00:00:00Z", created_at: "2026-01-01T00:00:00Z", updated_at: "2026-01-01T00:00:00Z" },
        { id: "j-2", tenant_id: "t-1", channel_message_id: "m-2", provider: "whatsapp", recipient_id: "r-2", payload: {}, status: "dead", attempt_count: 5, max_attempts: 5, next_attempt_at: "2026-01-01T00:00:00Z", last_error: "timeout", locked_at: null, sent_at: null, created_at: "2026-01-01T00:00:00Z", updated_at: "2026-01-01T00:00:00Z" },
      ],
      isLoading: false,
      isError: false,
    })
    const { OutboxTab } = await import("./outbox-tab")
    render(<OutboxTab />)
    expect(screen.getByText("sent")).toBeDefined()
    expect(screen.getByText("dead")).toBeDefined()
    const requeueButtons = screen.getAllByTitle("Requeue job")
    expect(requeueButtons.length).toBe(1)
  })
})
