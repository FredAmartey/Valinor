import { render, screen, fireEvent, cleanup } from "@testing-library/react"
import { describe, it, expect, vi, afterEach } from "vitest"
import { PermissionMatrix, PERMISSION_GRID } from "./permission-matrix"

afterEach(() => cleanup())

describe("PermissionMatrix", () => {
  it("renders resource rows", () => {
    render(<PermissionMatrix permissions={[]} readonly={false} onChange={vi.fn()} />)
    for (const row of PERMISSION_GRID) {
      expect(screen.getByText(row.resource)).toBeDefined()
    }
  })

  it("checks boxes matching current permissions", () => {
    render(<PermissionMatrix permissions={["agents:read", "users:write"]} readonly={false} onChange={vi.fn()} />)
    const agentsRead = screen.getByTestId("perm-agents:read") as HTMLInputElement
    expect(agentsRead.checked).toBe(true)
    const usersWrite = screen.getByTestId("perm-users:write") as HTMLInputElement
    expect(usersWrite.checked).toBe(true)
    const agentsWrite = screen.getByTestId("perm-agents:write") as HTMLInputElement
    expect(agentsWrite.checked).toBe(false)
  })

  it("disables all checkboxes when readonly", () => {
    render(<PermissionMatrix permissions={["agents:read"]} readonly={true} onChange={vi.fn()} />)
    const checkbox = screen.getByTestId("perm-agents:read") as HTMLInputElement
    expect(checkbox.disabled).toBe(true)
  })

  it("calls onChange with toggled permission", () => {
    const onChange = vi.fn()
    render(<PermissionMatrix permissions={["agents:read"]} readonly={false} onChange={onChange} />)
    fireEvent.click(screen.getByTestId("perm-agents:write"))
    expect(onChange).toHaveBeenCalledWith(["agents:read", "agents:write"])
  })

  it("calls onChange removing unchecked permission", () => {
    const onChange = vi.fn()
    render(<PermissionMatrix permissions={["agents:read", "agents:write"]} readonly={false} onChange={onChange} />)
    fireEvent.click(screen.getByTestId("perm-agents:read"))
    expect(onChange).toHaveBeenCalledWith(["agents:write"])
  })
})
