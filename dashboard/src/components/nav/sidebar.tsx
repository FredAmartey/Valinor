"use client"

import { useSession } from "next-auth/react"
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

const platformAdminNav = [
  { href: "/", icon: <ChartBar size={20} />, label: "Overview" },
  { href: "/tenants", icon: <Buildings size={20} />, label: "Tenants" },
]

const tenantAdminNav = [
  { href: "/", icon: <ChartBar size={20} />, label: "Overview" },
  { href: "/users", icon: <Users size={20} />, label: "Users" },
  { href: "/departments", icon: <TreeStructure size={20} />, label: "Departments" },
  { href: "/agents", icon: <Robot size={20} />, label: "Agents" },
  { href: "/rbac", icon: <ShieldCheck size={20} />, label: "RBAC" },
  { href: "/channels", icon: <ChatCircle size={20} />, label: "Channels" },
  { href: "/connectors", icon: <Plugs size={20} />, label: "Connectors" },
  { href: "/audit", icon: <ClockCounterClockwise size={20} />, label: "Audit Log" },
]

export function Sidebar() {
  const { data: session } = useSession()
  const isPlatformAdmin = session?.user?.isPlatformAdmin ?? false
  const navItems = isPlatformAdmin ? platformAdminNav : tenantAdminNav

  return (
    <aside className="flex h-full w-60 flex-col border-r border-zinc-200 bg-white">
      <div className="flex h-14 items-center border-b border-zinc-200 px-4">
        <span className="text-lg font-semibold tracking-tight text-zinc-900">Valinor</span>
      </div>
      <nav className="flex flex-1 flex-col gap-1 p-3">
        {navItems.map((item) => (
          <SidebarItem key={item.href} {...item} />
        ))}
      </nav>
    </aside>
  )
}
