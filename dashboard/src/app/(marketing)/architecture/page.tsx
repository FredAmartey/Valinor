import type { Metadata } from "next"

import { ArchitecturePage } from "@/components/architecture/architecture-page"
import { ThemeProvider } from "@/components/landing/theme"

export const metadata: Metadata = {
  title: "Valinor Architecture — Trust boundaries for broad-access AI agents",
  description:
    "See how Valinor isolates customers, governs risky actions, and secures AI agents across ingress, execution, and egress.",
}

export default function ArchitectureRoute() {
  return (
    <ThemeProvider>
      <ArchitecturePage />
    </ThemeProvider>
  )
}
