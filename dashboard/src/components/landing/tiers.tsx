"use client";

import { useTheme, palette, RING_GRADIENT } from "./theme";

const CHECK_ICON = (
  <svg
    width={18}
    height={18}
    viewBox="0 0 24 24"
    fill="none"
    stroke="#059669"
    strokeWidth={2.5}
    strokeLinecap="round"
    strokeLinejoin="round"
    className="shrink-0"
  >
    <polyline points="20 6 9 17 4 12" />
  </svg>
);

interface TierSpec {
  label: string;
  value: string;
}

interface TierData {
  name: string;
  description: string;
  specs: TierSpec[];
  features: string[];
  cta: string;
  recommended?: boolean;
}

const tiers: TierData[] = [
  {
    name: "Teams",
    description: "For dev teams and startups shipping AI-powered products.",
    specs: [
      { label: "Runtime", value: "Docker containers" },
      { label: "Cold start", value: "2–5 seconds" },
      { label: "Isolation", value: "Container-level" },
    ],
    features: [
      "Multi-tenancy",
      "RBAC + audit logs",
      "Multi-channel messaging",
      "MCP connectors",
      "Community support",
    ],
    cta: "Get Started",
  },
  {
    name: "Enterprise",
    description:
      "For regulated industries that demand hardware-level isolation.",
    specs: [
      { label: "Runtime", value: "Firecracker microVMs" },
      { label: "Cold start", value: "~125ms" },
      { label: "Isolation", value: "Hardware-virtualized" },
    ],
    features: [
      "Everything in Teams",
      "Firecracker microVMs",
      "Sub-200ms cold start",
      "SSO + SCIM provisioning",
      "Dedicated support + SLA",
    ],
    cta: "Contact Sales",
    recommended: true,
  },
];

export function Tiers() {
  const { dark } = useTheme();
  const c = palette(dark);

  return (
    <section
      id="tiers"
      className="relative py-32 transition-colors duration-500"
      style={{ backgroundColor: c.bgAlt }}
    >
      <div className="mx-auto max-w-[1200px] px-6">
        {/* ── Header ── */}
        <div className="mb-16 text-center">
          <p
            className="mb-3 text-sm font-semibold uppercase tracking-widest transition-colors duration-500"
            style={{ color: c.gold }}
          >
            Pricing
          </p>
          <h2
            className="text-4xl font-bold tracking-tight sm:text-5xl transition-colors duration-500"
            style={{ color: c.textPri }}
          >
            Choose the trust boundary that fits your team.
          </h2>
        </div>

        {/* ── Cards ── */}
        <div className="grid grid-cols-1 gap-6 md:grid-cols-2">
          {tiers.map((tier) => {
            const isEnterprise = tier.recommended;

            return (
              <div
                key={tier.name}
                className="relative rounded-[20px] p-8 backdrop-blur transition-all duration-500"
                style={{
                  backgroundColor: c.glassBg,
                  border: `1px solid ${
                    isEnterprise ? "rgba(232,175,72,0.25)" : c.glassBdr
                  }`,
                  boxShadow: isEnterprise
                    ? `${c.glassShadow}, 0 0 40px rgba(232,175,72,0.06)`
                    : c.glassShadow,
                }}
              >
                {/* ── Recommended badge ── */}
                {isEnterprise && (
                  <div
                    className="absolute -top-3 left-8 rounded-full px-[1px] py-[1px]"
                    style={{ background: RING_GRADIENT }}
                  >
                    <div
                      className="rounded-full px-4 py-1 text-xs font-semibold tracking-wide transition-colors duration-500"
                      style={{
                        backgroundColor: c.bgAlt,
                        color: c.gold,
                      }}
                    >
                      Recommended
                    </div>
                  </div>
                )}

                {/* ── Title + description ── */}
                <h3
                  className="mb-2 text-2xl font-bold transition-colors duration-500"
                  style={{ color: c.textPri }}
                >
                  {tier.name}
                </h3>
                <p
                  className="mb-6 text-[15px] leading-relaxed transition-colors duration-500"
                  style={{ color: c.textSec }}
                >
                  {tier.description}
                </p>

                {/* ── Specs ── */}
                <div className="mb-6 space-y-3">
                  {tier.specs.map((spec) => (
                    <div
                      key={spec.label}
                      className="flex items-center justify-between"
                    >
                      <span
                        className="text-sm transition-colors duration-500"
                        style={{ color: c.textSec }}
                      >
                        {spec.label}
                      </span>
                      <span
                        className="font-mono text-sm transition-colors duration-500"
                        style={{ color: c.textPri }}
                      >
                        {spec.value}
                      </span>
                    </div>
                  ))}
                </div>

                {/* ── Divider ── */}
                <div
                  className="mb-6 h-px transition-colors duration-500"
                  style={{ backgroundColor: c.divider }}
                />

                {/* ── Features ── */}
                <ul className="mb-8 space-y-3">
                  {tier.features.map((feature) => (
                    <li key={feature} className="flex items-center gap-3">
                      {CHECK_ICON}
                      <span
                        className="text-sm transition-colors duration-500"
                        style={{ color: c.textSec }}
                      >
                        {feature}
                      </span>
                    </li>
                  ))}
                </ul>

                {/* ── CTA ── */}
                {isEnterprise ? (
                  <button
                    className="w-full rounded-full py-3 text-sm font-semibold tracking-wide transition-all duration-300 hover:brightness-110"
                    style={{
                      backgroundColor: c.gold,
                      color: "#0c0c0e",
                    }}
                  >
                    {tier.cta}
                  </button>
                ) : (
                  <button
                    className="w-full rounded-full py-3 text-sm font-semibold tracking-wide transition-all duration-300 hover:brightness-125"
                    style={{
                      backgroundColor: "transparent",
                      border: `1px solid ${c.glassBdr}`,
                      color: c.textPri,
                    }}
                  >
                    {tier.cta}
                  </button>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </section>
  );
}
