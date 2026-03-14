import fs from "node:fs"
import path from "node:path"
import { describe, expect, it } from "vitest"

const root = path.resolve(import.meta.dirname)

describe("Next.js routing entrypoints", () => {
  it("uses the proxy convention instead of the deprecated middleware convention", () => {
    expect(fs.existsSync(path.join(root, "proxy.ts"))).toBe(true)
    expect(fs.existsSync(path.join(root, "middleware.ts"))).toBe(false)
  })
})
