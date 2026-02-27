import { describe, it, expect } from "vitest"

describe("useAgentWebSocket", () => {
  it("exports the hook", async () => {
    const mod = await import("./use-agent-websocket")
    expect(typeof mod.useAgentWebSocket).toBe("function")
  })
})
