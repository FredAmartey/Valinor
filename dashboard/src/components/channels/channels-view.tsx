"use client"

import { useState } from "react"
import { LinksTab } from "./links-tab"
import { ProvidersTab } from "./providers-tab"
import { OutboxTab } from "./outbox-tab"

export interface ChannelPermissions {
  canWriteLinks: boolean
  canReadProviders: boolean
  canWriteProviders: boolean
  canReadOutbox: boolean
  canWriteOutbox: boolean
}

const ALL_TABS = [
  { id: "links", label: "Links" },
  { id: "providers", label: "Providers" },
  { id: "outbox", label: "Outbox" },
] as const

type TabId = (typeof ALL_TABS)[number]["id"]

export function ChannelsView({ permissions }: { permissions: ChannelPermissions }) {
  const tabs = ALL_TABS.filter((tab) => {
    if (tab.id === "providers" && !permissions.canReadProviders) return false
    if (tab.id === "outbox" && !permissions.canReadOutbox) return false
    return true
  })

  const [activeTab, setActiveTab] = useState<TabId>(tabs[0]?.id ?? "links")

  return (
    <div className="space-y-6">
      <div role="tablist" className="flex gap-1 border-b border-zinc-200">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            role="tab"
            aria-selected={activeTab === tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`px-4 py-2 text-sm font-medium transition-colors ${
              activeTab === tab.id
                ? "border-b-2 border-zinc-900 text-zinc-900"
                : "text-zinc-500 hover:text-zinc-700"
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>
      <div role="tabpanel">
        {activeTab === "links" && <LinksTab canWrite={permissions.canWriteLinks} />}
        {activeTab === "providers" && <ProvidersTab canWrite={permissions.canWriteProviders} />}
        {activeTab === "outbox" && <OutboxTab canWrite={permissions.canWriteOutbox} />}
      </div>
    </div>
  )
}
