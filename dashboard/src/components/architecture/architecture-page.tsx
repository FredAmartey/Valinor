"use client"

import { ArchitectureDiagram } from "@/components/architecture/architecture-diagram"
import { CONTACT_SECTION_URL, TECHNICAL_ARCHITECTURE_URL } from "@/lib/site-links"
import { GRAIN_URL, palette, useTheme } from "@/components/landing/theme"

const TRUST_BOUNDARIES = [
  {
    title: "Tenant isolation",
    detail:
      "Separate customers should not be able to observe or influence one another through shared agent state, credentials, or delivery paths.",
  },
  {
    title: "Department and user scope",
    detail:
      "Departments and individual users can have their own agent boundaries, access controls, and approval paths without collapsing into one flat workspace.",
  },
  {
    title: "Layered memory",
    detail:
      "Personal, department, tenant, and approved shared memory scopes keep context useful without turning it into a blind data pool.",
  },
]

const SECURITY_STAGES = [
  {
    title: "Before execution",
    detail:
      "Messages are checked before they reach the runtime, including prompt-injection and instruction-override defenses.",
  },
  {
    title: "During execution",
    detail:
      "Tools, network access, policies, and human review govern what the agent is allowed to do while it is running.",
  },
  {
    title: "Before external effects",
    detail:
      "Outbound actions can be reviewed, blocked, or audited before they reach users or connected systems.",
  },
]

const PRODUCT_TIERS = [
  {
    tier: "Teams",
    runtime: "Docker containers",
    coldStart: "2-5 seconds",
    isolation: "Container-level",
    target: "Dev teams, small orgs",
  },
  {
    tier: "Enterprise",
    runtime: "Firecracker MicroVMs (separate kernel per agent)",
    coldStart: "~125 milliseconds",
    isolation: "Hardware-virtualized",
    target: "Regulated industries, high-trust environments",
  },
]

const DELIVERY_PILLARS = [
  {
    title: "Governed channels",
    detail:
      "Slack, WhatsApp, Telegram, and related delivery paths stay inside the trust model instead of becoming one-off integrations.",
  },
  {
    title: "Scoped credentials",
    detail:
      "Tenant-scoped provider credentials and connector access keep external systems from becoming a shared weak point.",
  },
  {
    title: "Reviewable actions",
    detail:
      "Approvals and auditability make sensitive outbound behavior understandable and accountable.",
  },
]

function SectionHeading({
  eyebrow,
  title,
  description,
}: {
  eyebrow: string
  title: string
  description: string
}) {
  const { dark } = useTheme()
  const c = palette(dark)

  return (
    <div className="max-w-3xl">
      <p
        className="text-xs font-semibold uppercase tracking-[0.24em]"
        style={{ color: c.gold, transition: "color 0.4s ease" }}
      >
        {eyebrow}
      </p>
      <h2
        className="mt-3 text-3xl font-semibold tracking-tight md:text-4xl"
        style={{ color: c.textPri, transition: "color 0.4s ease" }}
      >
        {title}
      </h2>
      <p
        className="mt-4 max-w-[62ch] text-base leading-relaxed md:text-lg"
        style={{ color: c.textSec, transition: "color 0.4s ease" }}
      >
        {description}
      </p>
    </div>
  )
}

function GlassCard({
  title,
  detail,
}: {
  title: string
  detail: string
}) {
  const { dark } = useTheme()
  const c = palette(dark)

  return (
    <div
      className="rounded-[24px] border p-5"
      style={{
        background: c.glassBg,
        borderColor: c.glassBdr,
        boxShadow: c.glassShadow,
        backdropFilter: "blur(18px)",
        WebkitBackdropFilter: "blur(18px)",
        transition: "background 0.4s ease, border-color 0.4s ease, box-shadow 0.4s ease",
      }}
    >
      <h3
        className="text-lg font-semibold tracking-tight"
        style={{ color: c.textPri, transition: "color 0.4s ease" }}
      >
        {title}
      </h3>
      <p
        className="mt-3 text-sm leading-relaxed md:text-base"
        style={{ color: c.textSec, transition: "color 0.4s ease" }}
      >
        {detail}
      </p>
    </div>
  )
}

export function ArchitecturePage() {
  const { dark } = useTheme()
  const c = palette(dark)

  return (
    <div
      className="relative min-h-[100dvh] overflow-hidden"
      style={{ background: c.bg, transition: "background 0.6s ease" }}
    >
      <div
        className="fixed inset-0 pointer-events-none"
        style={{
          background: `radial-gradient(ellipse 900px 420px at 50% -10%, rgba(232,175,72,${c.glowA}) 0%, transparent 70%)`,
          transition: "background 0.6s ease",
        }}
      />
      <div
        className="fixed inset-0 pointer-events-none"
        style={{
          opacity: c.grainA,
          mixBlendMode: "overlay",
          backgroundImage: GRAIN_URL,
          backgroundRepeat: "repeat",
          backgroundSize: "256px 256px",
          transition: "opacity 0.6s ease",
        }}
      />

      <main className="relative z-10 mx-auto flex w-full max-w-[1240px] flex-col gap-24 px-6 py-20 md:py-24">
        <section className="grid gap-12 lg:grid-cols-[1.1fr_0.9fr] lg:items-end">
          <div className="max-w-3xl">
            <p
              className="text-xs font-semibold uppercase tracking-[0.24em]"
              style={{ color: c.gold, transition: "color 0.4s ease" }}
            >
              Security architecture
            </p>
            <h1
              className="mt-4 text-4xl font-bold tracking-tight md:text-5xl lg:text-6xl"
              style={{ color: c.textPri, transition: "color 0.4s ease" }}
            >
              Architecture built for broad-access AI agents
            </h1>
            <p
              className="mt-6 max-w-[60ch] text-base leading-relaxed md:text-lg"
              style={{ color: c.textSec, transition: "color 0.4s ease" }}
            >
              Valinor is designed to keep high-access agents observable, isolated,
              governable, and auditable across the full action lifecycle. This is
              the system shape behind that promise.
            </p>
            <div className="mt-8 flex flex-wrap gap-4">
              <a
                href={TECHNICAL_ARCHITECTURE_URL}
                className="rounded-xl border px-5 py-3 text-sm font-semibold no-underline"
                target="_blank"
                rel="noreferrer"
                style={{
                  borderColor: c.glassBdr,
                  color: c.textPri,
                  background: c.glassBg,
                  transition: "background 0.4s ease, color 0.4s ease, border-color 0.4s ease",
                }}
              >
                Read the technical architecture
              </a>
              <a
                href={CONTACT_SECTION_URL}
                className="rounded-xl px-5 py-3 text-sm font-semibold no-underline"
                style={{
                  background: c.gold,
                  color: "#1a1306",
                  transition: "transform 0.2s ease",
                }}
              >
                Talk to Valinor
              </a>
            </div>
          </div>

          <div
            className="rounded-[28px] border p-5 md:p-6"
            style={{
              background: c.glassBg,
              borderColor: c.glassBdr,
              boxShadow: c.glassShadow,
              transition: "background 0.4s ease, border-color 0.4s ease, box-shadow 0.4s ease",
            }}
          >
            <div className="grid gap-4 sm:grid-cols-2">
              <GlassCard
                title="Isolation"
                detail="Tenant, department, user, credential, and runtime boundaries work together instead of relying on one control."
              />
              <GlassCard
                title="Governance"
                detail="Policies, approvals, and RBAC keep sensitive actions inside explicit organizational rules."
              />
              <GlassCard
                title="Observability"
                detail="Activity and audit records capture what agents did and what organizations need to prove happened."
              />
              <GlassCard
                title="Lifecycle controls"
                detail="Valinor secures what agents receive, what they do, and what they send before risky behavior becomes real damage."
              />
            </div>
          </div>
        </section>

        <section className="space-y-8">
          <SectionHeading
            eyebrow="System"
            title="A layered trust model, not a single checkpoint"
            description="Valinor's control plane, policy surfaces, activity ledger, audit ledger, channels, and runtime tiers work together to make broad-access agents safer to trust."
          />
          <ArchitectureDiagram />
        </section>

        <section className="space-y-8">
          <SectionHeading
            eyebrow="Trust boundaries"
            title="Boundaries that map to how organizations actually work"
            description="The architecture is designed to isolate customers from each other, teams from one another, and sensitive memory or credentials from the wrong scope."
          />
          <div className="grid gap-5 lg:grid-cols-3">
            {TRUST_BOUNDARIES.map((item) => (
              <GlassCard key={item.title} title={item.title} detail={item.detail} />
            ))}
          </div>
        </section>

        <section className="space-y-8">
          <SectionHeading
            eyebrow="Lifecycle security"
            title="Security before, during, and after agent execution"
            description="Valinor does not treat security as a single gate around the runtime. It applies checks and controls across ingress, execution, and egress."
          />
          <div className="grid gap-5 lg:grid-cols-3">
            {SECURITY_STAGES.map((item) => (
              <GlassCard key={item.title} title={item.title} detail={item.detail} />
            ))}
          </div>
        </section>

        <section className="space-y-8">
          <SectionHeading
            eyebrow="Product tiers"
            title="One trust model, two runtime tiers"
            description="Teams and Enterprise share the same governance, visibility, audit, channel, and connector model. The runtime layer changes to match the required isolation profile."
          />
          <div
            className="overflow-hidden rounded-[28px] border"
            style={{
              borderColor: c.glassBdr,
              boxShadow: c.glassShadow,
              background: c.glassBg,
              transition: "background 0.4s ease, border-color 0.4s ease, box-shadow 0.4s ease",
            }}
          >
            <div className="grid grid-cols-[1fr_1fr_1fr] gap-px" style={{ background: c.divider }}>
              <div className="p-4" style={{ background: c.plate }} />
              {PRODUCT_TIERS.map((tier) => (
                <div key={tier.tier} className="p-4" style={{ background: c.plate }}>
                  <div className="text-sm font-semibold" style={{ color: c.textPri }}>
                    {tier.tier}
                  </div>
                </div>
              ))}

              {[
                { label: "Runtime", key: "runtime" as const },
                { label: "Cold start", key: "coldStart" as const },
                { label: "Isolation", key: "isolation" as const },
                { label: "Target", key: "target" as const },
              ].map((row) => (
                <div key={row.label} className="contents">
                  <div className="p-4" style={{ background: c.plate }}>
                    <div className="text-sm font-medium" style={{ color: c.textPri }}>
                      {row.label}
                    </div>
                  </div>
                  {PRODUCT_TIERS.map((tier) => (
                    <div key={`${row.label}-${tier.tier}`} className="p-4" style={{ background: c.glassBg }}>
                      <div className="text-sm leading-relaxed" style={{ color: c.textSec }}>
                        {tier[row.key]}
                      </div>
                    </div>
                  ))}
                </div>
              ))}
            </div>
          </div>
        </section>

        <section className="space-y-8">
          <SectionHeading
            eyebrow="Channels and integrations"
            title="Real workflows without giving up governance"
            description="Channels and external systems are where agents produce real effects. Valinor keeps those paths observable, scoped, and reviewable."
          />
          <div className="grid gap-5 lg:grid-cols-3">
            {DELIVERY_PILLARS.map((item) => (
              <GlassCard key={item.title} title={item.title} detail={item.detail} />
            ))}
          </div>
        </section>

        <section
          className="rounded-[32px] border px-6 py-10 text-center md:px-10"
          style={{
            background: c.glassBg,
            borderColor: c.glassBdr,
            boxShadow: c.glassShadow,
            transition: "background 0.4s ease, border-color 0.4s ease, box-shadow 0.4s ease",
          }}
        >
          <p
            className="text-xs font-semibold uppercase tracking-[0.24em]"
            style={{ color: c.gold, transition: "color 0.4s ease" }}
          >
            Next step
          </p>
          <h2
            className="mt-4 text-3xl font-semibold tracking-tight md:text-4xl"
            style={{ color: c.textPri, transition: "color 0.4s ease" }}
          >
            See the technical reference behind the trust model
          </h2>
          <p
            className="mx-auto mt-4 max-w-[54ch] text-base leading-relaxed"
            style={{ color: c.textSec, transition: "color 0.4s ease" }}
          >
            The marketing view explains why the system matters. The technical
            architecture explains how the control plane, runtime, policy, and
            ledger model fit together.
          </p>
          <div className="mt-8 flex flex-wrap justify-center gap-4">
            <a
              href={TECHNICAL_ARCHITECTURE_URL}
              className="rounded-xl border px-5 py-3 text-sm font-semibold no-underline"
              target="_blank"
              rel="noreferrer"
              style={{
                borderColor: c.glassBdr,
                color: c.textPri,
                background: c.plate,
              }}
            >
              Read the reference docs
            </a>
            <a
              href={CONTACT_SECTION_URL}
              className="rounded-xl px-5 py-3 text-sm font-semibold no-underline"
              style={{ background: c.gold, color: "#1a1306" }}
            >
              Request a demo
            </a>
          </div>
        </section>
      </main>
    </div>
  )
}
