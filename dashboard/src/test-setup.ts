import { vi } from "vitest"

// Mock next/server which next-auth tries to import in jsdom environment
vi.mock("next/server", () => ({
  NextRequest: vi.fn(),
  NextResponse: {
    json: vi.fn(),
    redirect: vi.fn(),
    next: vi.fn(),
  },
}))
