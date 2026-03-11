import type { Metadata } from "next"

export const metadata: Metadata = {
  title: "Valinor — Enterprise AI Agent Infrastructure",
  description: "Deploy isolated AI agent instances per customer with multi-tenancy, RBAC, audit, and multi-channel messaging.",
}

export default function MarketingLayout({ children }: { children: React.ReactNode }) {
  return <>{children}</>
}
