"use client"

import { createContext, useContext, useMemo } from "react"
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
  const value = useMemo(
    () => ({ can: (p: string) => hasPermission(isPlatformAdmin, roles, p) }),
    [isPlatformAdmin, roles],
  )

  return (
    <PermissionContext.Provider value={value}>
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
