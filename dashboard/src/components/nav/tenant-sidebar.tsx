"use client";

import Link from "next/link";
import { SidebarItem } from "./sidebar-item";
import {
  ArrowLeft,
  Users,
  TreeStructure,
  ShieldCheck,
  Robot,
  ChatCircle,
  Plugs,
  ClockCounterClockwise,
  HandPalm,
  ShieldWarning,
} from "@phosphor-icons/react";

interface TenantSidebarProps {
  tenantId: string;
  tenantName: string;
}

export function TenantSidebar({ tenantId, tenantName }: TenantSidebarProps) {
  const base = `/tenants/${tenantId}`;

  const items = [
    { href: `${base}/users`, icon: <Users size={20} />, label: "Users" },
    {
      href: `${base}/departments`,
      icon: <TreeStructure size={20} />,
      label: "Departments",
    },
    { href: `${base}/rbac`, icon: <ShieldCheck size={20} />, label: "RBAC" },
    { href: `${base}/agents`, icon: <Robot size={20} />, label: "Agents" },
    {
      href: `${base}/channels`,
      icon: <ChatCircle size={20} />,
      label: "Channels",
    },
    {
      href: `${base}/connectors`,
      icon: <Plugs size={20} />,
      label: "Connectors",
    },
    {
      href: `${base}/security`,
      icon: <ShieldWarning size={20} />,
      label: "Security Center",
    },
    {
      href: `${base}/approvals`,
      icon: <HandPalm size={20} />,
      label: "Approvals",
    },
    {
      href: `${base}/audit`,
      icon: <ClockCounterClockwise size={20} />,
      label: "Audit Log",
    },
  ];

  return (
    <aside className="flex h-full w-60 flex-col border-r border-zinc-200 bg-white">
      <div className="flex h-14 items-center border-b border-zinc-200 px-4">
        <span className="text-lg font-semibold tracking-tight text-zinc-900">
          Valinor
        </span>
      </div>
      <nav className="flex flex-1 flex-col p-3">
        <Link
          href="/tenants"
          className="mb-2 flex items-center gap-2 rounded-lg px-3 py-2 text-sm text-zinc-500 transition-colors hover:bg-zinc-100 hover:text-zinc-900"
        >
          <ArrowLeft size={16} />
          Back to Tenants
        </Link>
        <div className="mb-2 px-3">
          <p className="truncate text-xs font-medium uppercase tracking-wider text-zinc-400">
            {tenantName}
          </p>
        </div>
        <div className="flex flex-col gap-1">
          {items.map((item) => (
            <SidebarItem key={item.href} {...item} />
          ))}
        </div>
      </nav>
    </aside>
  );
}
