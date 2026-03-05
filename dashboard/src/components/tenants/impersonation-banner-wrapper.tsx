"use client"

import { useSession } from "next-auth/react"
import { ImpersonationBanner } from "./impersonation-banner"

export function ImpersonationBannerWrapper() {
  const { data: session } = useSession()

  const tenantName = session?.user?.impersonatingTenantName
  if (!tenantName) return null

  const handleExit = async () => {
    const { signOut } = await import("next-auth/react")
    await signOut({ redirectTo: "/login" })
  }

  return <ImpersonationBanner tenantName={tenantName} onExit={handleExit} />
}
