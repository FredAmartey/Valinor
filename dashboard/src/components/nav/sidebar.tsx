"use client"

import { useSession } from "next-auth/react"
import { useCan } from "@/components/providers/permission-provider"
import { SidebarItem } from "./sidebar-item"
import {
  ChartBar,
  Buildings,
  Users,
  TreeStructure,
  Robot,
  ShieldCheck,
  ChatCircle,
  Plugs,
  ClockCounterClockwise,
} from "@phosphor-icons/react"

export function Sidebar() {
  const { data: session } = useSession()
  const isPlatformAdmin = session?.user?.isPlatformAdmin ?? false
  const hasTenant = !!session?.user?.tenantId

  const canReadUsers = useCan("users:read")
  const canReadAgents = useCan("agents:read")
  const canReadConnectors = useCan("connectors:read")
  const canReadAudit = useCan("audit:read")

  const platformItems = [
    { href: "/", icon: <ChartBar size={20} />, label: "Overview" },
    ...(isPlatformAdmin
      ? [{ href: "/tenants", icon: <Buildings size={20} />, label: "Tenants" }]
      : []),
  ]

  const tenantItems = hasTenant
    ? [
        ...(canReadUsers
          ? [
              { href: "/users", icon: <Users size={20} />, label: "Users" },
              { href: "/departments", icon: <TreeStructure size={20} />, label: "Departments" },
              { href: "/rbac", icon: <ShieldCheck size={20} />, label: "RBAC" },
            ]
          : []),
        ...(canReadAgents
          ? [{ href: "/agents", icon: <Robot size={20} />, label: "Agents" }]
          : []),
        ...(canReadConnectors
          ? [
              { href: "/channels", icon: <ChatCircle size={20} />, label: "Channels" },
              { href: "/connectors", icon: <Plugs size={20} />, label: "Connectors" },
            ]
          : []),
        ...(canReadAudit
          ? [{ href: "/audit", icon: <ClockCounterClockwise size={20} />, label: "Audit Log" }]
          : []),
      ]
    : []

  return (
    <aside className="flex h-full w-60 flex-col border-r border-zinc-200 bg-white">
      <div className="flex h-14 items-center border-b border-zinc-200 px-4">
        <span className="text-lg font-semibold tracking-tight text-zinc-900">Valinor</span>
      </div>
      <nav className="flex flex-1 flex-col p-3">
        <div className="flex flex-col gap-1">
          {platformItems.map((item) => (
            <SidebarItem key={item.href} {...item} />
          ))}
        </div>
        {tenantItems.length > 0 && (
          <>
            <hr className="my-2 border-zinc-200" />
            <div className="flex flex-col gap-1">
              {tenantItems.map((item) => (
                <SidebarItem key={item.href} {...item} />
              ))}
            </div>
          </>
        )}
      </nav>
    </aside>
  )
}
