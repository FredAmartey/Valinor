"use client"

import { useState } from "react"
import { LinksTab } from "./links-tab"
import { ProvidersTab } from "./providers-tab"
import { OutboxTab } from "./outbox-tab"

const TABS = [
  { id: "links", label: "Links" },
  { id: "providers", label: "Providers" },
  { id: "outbox", label: "Outbox" },
] as const

type TabId = (typeof TABS)[number]["id"]

export function ChannelsView() {
  const [activeTab, setActiveTab] = useState<TabId>("links")

  return (
    <div className="space-y-6">
      <div className="flex gap-1 border-b border-zinc-200">
        {TABS.map((tab) => (
          <button
            key={tab.id}
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
      {activeTab === "links" && <LinksTab />}
      {activeTab === "providers" && <ProvidersTab />}
      {activeTab === "outbox" && <OutboxTab />}
    </div>
  )
}
