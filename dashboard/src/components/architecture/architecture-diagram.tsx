"use client"

import { useTheme, palette } from "@/components/landing/theme"

type LayerProps = {
  title: string
  detail: string
  accent?: boolean
}

function Layer({ title, detail, accent = false }: LayerProps) {
  const { dark } = useTheme()
  const c = palette(dark)

  return (
    <div
      className="rounded-[22px] border p-4 md:p-5"
      style={{
        background: accent ? c.plate : c.glassBg,
        borderColor: c.glassBdr,
        boxShadow: c.glassShadow,
        transition: "background 0.4s ease, border-color 0.4s ease, box-shadow 0.4s ease",
      }}
    >
      <div
        className="text-sm font-semibold tracking-tight md:text-base"
        style={{ color: c.textPri, transition: "color 0.4s ease" }}
      >
        {title}
      </div>
      <p
        className="mt-2 text-sm leading-relaxed"
        style={{ color: c.textSec, transition: "color 0.4s ease" }}
      >
        {detail}
      </p>
    </div>
  )
}

function ConnectorLine() {
  const { dark } = useTheme()
  const c = palette(dark)

  return (
    <div className="flex justify-center py-2">
      <div
        className="h-6 w-px"
        style={{ background: c.divider, transition: "background 0.4s ease" }}
      />
    </div>
  )
}

export function ArchitectureDiagram() {
  const { dark } = useTheme()
  const c = palette(dark)

  return (
    <section
      aria-label="Heimdall architecture diagram"
      className="rounded-[28px] border px-5 py-6 md:px-8 md:py-8"
      style={{
        background: c.glassBg,
        borderColor: c.glassBdr,
        boxShadow: c.glassShadow,
        backdropFilter: "blur(18px)",
        WebkitBackdropFilter: "blur(18px)",
        transition: "background 0.4s ease, border-color 0.4s ease, box-shadow 0.4s ease",
      }}
    >
      <div className="mx-auto max-w-5xl">
        <div className="grid gap-4 md:grid-cols-2">
          <Layer
            title="Users and operators"
            detail="Admins, operators, and end users interact with agents through governed interfaces."
            accent
          />
          <Layer
            title="Channels and integrations"
            detail="Slack, WhatsApp, Telegram, connectors, and external systems are part of the trust boundary."
            accent
          />
        </div>

        <ConnectorLine />

        <Layer
          title="Heimdall control plane"
          detail="The control plane manages tenancy, policy, approvals, delivery, orchestration, and governance."
          accent
        />

        <div className="grid gap-4 pt-4 md:grid-cols-2">
          <Layer
            title="Policy and approvals"
            detail="Risk-class policies, human review, and permission boundaries govern sensitive actions."
          />
          <Layer
            title="Activity and audit"
            detail="Operator activity and compliance audit ledgers preserve both understanding and proof."
          />
        </div>

        <ConnectorLine />

        <div className="grid gap-4 md:grid-cols-2">
          <Layer
            title="Teams runtime"
            detail="Docker containers provide the Teams tier with container-level isolation."
          />
          <Layer
            title="Enterprise runtime"
            detail="Firecracker microVMs provide hardware-virtualized isolation with a separate kernel per agent."
          />
        </div>

        <ConnectorLine />

        <Layer
          title="OpenClaw runtime"
          detail="Heimdall is OpenClaw-first today, with trust surfaces that sit above the runtime instead of replacing it."
          accent
        />
      </div>
    </section>
  )
}
