import { describe, it, expect, vi, beforeEach } from "vitest"
import { render, screen, fireEvent, cleanup } from "@testing-library/react"

// Mock dependencies
vi.mock("next-auth/react", () => ({
  useSession: vi.fn().mockReturnValue({
    data: { accessToken: "test", user: { isPlatformAdmin: true } },
    status: "authenticated",
  }),
}))

vi.mock("@tanstack/react-query", () => ({
  useMutation: vi.fn().mockReturnValue({
    mutate: vi.fn(),
    isPending: false,
    isError: false,
  }),
  useQueryClient: vi.fn().mockReturnValue({}),
}))

vi.mock("next/navigation", () => ({
  useRouter: vi.fn().mockReturnValue({ push: vi.fn() }),
}))

describe("CreateTenantForm", () => {
  beforeEach(() => {
    cleanup()
  })

  it("auto-generates slug from name", async () => {
    const { CreateTenantForm } = await import("./create-tenant-form")
    render(<CreateTenantForm />)

    const nameInput = screen.getByLabelText("Name")
    fireEvent.change(nameInput, { target: { value: "Acme Corporation" } })

    const slugInput = screen.getByLabelText("Slug") as HTMLInputElement
    expect(slugInput.value).toBe("acme-corporation")
  })

  it("renders submit button", async () => {
    const { CreateTenantForm } = await import("./create-tenant-form")
    render(<CreateTenantForm />)
    expect(screen.getByRole("button", { name: /create tenant/i })).toBeDefined()
  })
})
