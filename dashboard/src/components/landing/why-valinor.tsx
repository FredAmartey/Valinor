"use client";

import { useTheme, palette } from "./theme";

function ShieldCheckIcon({ color }: { color: string }) {
  return (
    <svg
      width={28}
      height={28}
      viewBox="0 0 24 24"
      fill="none"
      stroke={color}
      strokeWidth={1.5}
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M12 2l7 4v5c0 5.25-3.5 9.74-7 11-3.5-1.26-7-5.75-7-11V6l7-4z" />
      <path d="M9 12l2 2 4-4" />
    </svg>
  );
}

function QuadrantsIcon({ color }: { color: string }) {
  return (
    <svg
      width={28}
      height={28}
      viewBox="0 0 24 24"
      fill="none"
      stroke={color}
      strokeWidth={1.5}
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <rect x="3" y="3" width="18" height="18" rx="2" />
      <line x1="12" y1="3" x2="12" y2="21" />
      <line x1="3" y1="12" x2="21" y2="12" />
    </svg>
  );
}

function LightningIcon({ color }: { color: string }) {
  return (
    <svg
      width={28}
      height={28}
      viewBox="0 0 24 24"
      fill="none"
      stroke={color}
      strokeWidth={1.5}
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M13 2L4 14h7l-1 8 9-12h-7l1-8z" />
    </svg>
  );
}

const cards = [
  {
    title: "Tenant Isolation",
    description:
      "Every customer gets their own sandboxed runtime. Docker containers or Firecracker microVMs — hardware-level isolation that keeps workloads completely separated.",
    Icon: QuadrantsIcon,
  },
  {
    title: "Compliance Built In",
    description:
      "Deny-by-default RBAC, full audit trails on every action, prompt injection defense, and tool allow-listing. Security is the foundation, not an afterthought.",
    Icon: ShieldCheckIcon,
  },
  {
    title: "Ship in Days, Not Months",
    description:
      "Pre-built agent orchestration, credential management, and multi-channel messaging. One API call replaces weeks of infrastructure work.",
    Icon: LightningIcon,
  },
];

export function WhyValinor() {
  const { dark } = useTheme();
  const c = palette(dark);

  return (
    <section
      id="why"
      className="py-32 transition-colors duration-500"
      style={{ background: c.bgAlt }}
    >
      <div className="mx-auto max-w-[1200px] px-6">
        <p
          className="mb-3 text-sm font-semibold uppercase tracking-widest"
          style={{ color: c.gold }}
        >
          Why Valinor
        </p>
        <h2
          className="mb-12 max-w-2xl text-3xl font-bold leading-tight md:text-4xl"
          style={{ color: c.textPri }}
        >
          Infrastructure you&apos;d build yourself — already built, secured, and
          battle-tested.
        </h2>

        <div className="grid grid-cols-1 gap-6 md:grid-cols-3">
          {cards.map(({ title, description, Icon }) => (
            <div
              key={title}
              className="rounded-[20px] p-7 transition-colors duration-500"
              style={{
                background: c.glassBg,
                border: `1px solid ${c.glassBdr}`,
                boxShadow: c.glassShadow,
                backdropFilter: "blur(16px)",
                WebkitBackdropFilter: "blur(16px)",
              }}
            >
              <div className="mb-4">
                <Icon color={c.gold} />
              </div>
              <h3
                className="mb-2 text-lg font-semibold"
                style={{ color: c.textPri }}
              >
                {title}
              </h3>
              <p
                className="text-sm leading-relaxed"
                style={{ color: c.textSec }}
              >
                {description}
              </p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
