"use client"

import { createContext, useContext } from "react"
import { hasPermission } from "@/lib/permissions"

interface PermissionContextValue {
  can: (permission: string) => boolean
}

const PermissionContext = createContext<PermissionContextValue>({
  can: () => false,
})

interface PermissionProviderProps {
  isPlatformAdmin: boolean
  roles: string[]
  children: React.ReactNode
}

export function PermissionProvider({
  isPlatformAdmin,
  roles,
  children,
}: PermissionProviderProps) {
  function can(permission: string): boolean {
    return hasPermission(isPlatformAdmin, roles, permission)
  }

  return (
    <PermissionContext.Provider value={{ can }}>
      {children}
    </PermissionContext.Provider>
  )
}

/**
 * Use in any client component inside the dashboard layout.
 * Returns false while session data is unavailable (safe deny default).
 */
export function useCan(permission: string): boolean {
  const { can } = useContext(PermissionContext)
  return can(permission)
}
