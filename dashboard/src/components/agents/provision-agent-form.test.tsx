import { describe, it, expect, vi } from "vitest"
import { render, screen } from "@testing-library/react"

vi.mock("next-auth/react", () => ({
  useSession: vi.fn().mockReturnValue({
    data: { accessToken: "test", user: { id: "u-1", isPlatformAdmin: false, tenantId: "t-1" } },
    status: "authenticated",
  }),
}))

vi.mock("@tanstack/react-query", () => ({
  useMutation: vi.fn().mockReturnValue({
    mutate: vi.fn(),
    isPending: false,
    isError: false,
  }),
  useQuery: vi.fn().mockReturnValue({
    data: [],
    isLoading: false,
  }),
  useQueryClient: vi.fn().mockReturnValue({}),
}))

vi.mock("next/navigation", () => ({
  useRouter: vi.fn().mockReturnValue({ push: vi.fn() }),
}))

describe("ProvisionAgentForm", () => {
  it("renders submit button", async () => {
    const { ProvisionAgentForm } = await import("./provision-agent-form")
    render(<ProvisionAgentForm />)
    expect(screen.getByRole("button", { name: /provision agent/i })).toBeDefined()
  })
})
