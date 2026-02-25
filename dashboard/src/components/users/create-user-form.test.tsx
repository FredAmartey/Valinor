import { describe, it, expect, vi, beforeEach } from "vitest"
import { render, screen, cleanup } from "@testing-library/react"

vi.mock("next-auth/react", () => ({
  useSession: vi.fn().mockReturnValue({
    data: { accessToken: "test", user: { isPlatformAdmin: false, tenantId: "t-1" } },
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

describe("CreateUserForm", () => {
  beforeEach(() => {
    cleanup()
  })

  it("renders email and display name fields", async () => {
    const { CreateUserForm } = await import("./create-user-form")
    render(<CreateUserForm />)
    expect(screen.getByLabelText("Email")).toBeDefined()
    expect(screen.getByLabelText("Display Name")).toBeDefined()
  })

  it("renders submit button", async () => {
    const { CreateUserForm } = await import("./create-user-form")
    render(<CreateUserForm />)
    expect(screen.getByRole("button", { name: /create user/i })).toBeDefined()
  })
})
