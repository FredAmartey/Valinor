import { describe, it, expect } from "vitest"
import { hasPermission } from "./permissions"

describe("hasPermission", () => {
  it("allows org_admin wildcard for any permission", () => {
    expect(hasPermission(false, ["org_admin"], "agents:write")).toBe(true)
    expect(hasPermission(false, ["org_admin"], "departments:write")).toBe(true)
  })

  it("platform admin bypasses all checks", () => {
    expect(hasPermission(true, [], "anything:write")).toBe(true)
    expect(hasPermission(true, ["read_only"], "agents:write")).toBe(true)
  })

  it("allows dept_head agents:write", () => {
    expect(hasPermission(false, ["dept_head"], "agents:write")).toBe(true)
  })

  it("denies dept_head departments:write", () => {
    expect(hasPermission(false, ["dept_head"], "departments:write")).toBe(false)
  })

  it("allows standard_user agents:read", () => {
    expect(hasPermission(false, ["standard_user"], "agents:read")).toBe(true)
  })

  it("denies standard_user agents:write", () => {
    expect(hasPermission(false, ["standard_user"], "agents:write")).toBe(false)
  })

  it("denies read_only agents:write", () => {
    expect(hasPermission(false, ["read_only"], "agents:write")).toBe(false)
  })

  it("returns false for empty roles", () => {
    expect(hasPermission(false, [], "agents:read")).toBe(false)
  })

  it("returns false for unknown role", () => {
    expect(hasPermission(false, ["ghost"], "agents:read")).toBe(false)
  })

  it("union: allows when any role grants the permission", () => {
    expect(hasPermission(false, ["read_only", "dept_head"], "agents:write")).toBe(true)
  })
})
