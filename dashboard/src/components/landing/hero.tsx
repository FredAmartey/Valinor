"use client";

import { useTheme, palette, RING_GRADIENT } from "./theme";

const AGENTS = [
  { name: "support-agent-01", status: "running" as const },
  { name: "onboarding-flow", status: "running" as const },
  { name: "data-analyst-v3", status: "idle" as const },
];

const STATS = [
  { label: "Protected Agents", value: "24" },
  { label: "Isolated Tenants", value: "8" },
  { label: "Audit Coverage", value: "100%" },
];

export function Hero() {
  const { dark } = useTheme();
  const c = palette(dark);

  return (
    <section
      id="hero"
      className="min-h-[100dvh] flex items-center justify-center px-6 py-24"
      style={{ transition: "background 0.4s, color 0.4s" }}
    >
      <div className="w-full max-w-[1200px] grid grid-cols-1 lg:grid-cols-2 gap-16 items-center">
        {/* ── Left column ── */}
        <div className="flex flex-col gap-6">
          <span
            className="text-xs font-semibold uppercase tracking-widest"
            style={{ color: c.gold, transition: "color 0.4s" }}
          >
            Security, observability, and governance for broad-access AI agents
          </span>

          <h1
            className="text-4xl md:text-5xl lg:text-6xl font-bold tracking-tighter leading-[1.08]"
            style={{ color: c.textPri, transition: "color 0.4s" }}
          >
            Trust AI&nbsp;agents with real&nbsp;access
          </h1>

          <p
            className="text-base md:text-lg leading-relaxed max-w-[520px]"
            style={{ color: c.textSec, transition: "color 0.4s" }}
          >
            Heimdall gives teams and enterprises the visibility, isolation,
            governance, and auditability needed to use AI agents securely and
            with confidence.
          </p>

          <p
            className="max-w-[520px] text-sm font-medium"
            style={{ color: c.gold, transition: "color 0.4s" }}
          >
            Built to make agents like OpenClaw safe for real teams and
            enterprises.
          </p>

          {/* CTA button with spinning gold ring border */}
          <div className="mt-2">
            <button
              className="relative overflow-hidden rounded-xl p-[2px]"
              style={{
                background: RING_GRADIENT,
                animation: "spin 4s linear infinite",
              }}
            >
              <span
                className="block rounded-[10px] px-7 py-3 text-sm font-semibold tracking-wide cursor-pointer"
                style={{
                  background: c.plate,
                  color: c.gold,
                  transition: "background 0.4s, color 0.4s",
                }}
              >
                Request a Demo
              </span>
            </button>
          </div>

          {/* keyframes injected inline */}
          <style>{`
            @keyframes spin { to { rotate: 360deg; } }
          `}</style>
        </div>

        {/* ── Right column — mock dashboard card ── */}
        <div className="hidden lg:block">
          <div
            className="rounded-2xl border p-6"
            style={{
              background: c.glassBg,
              borderColor: c.glassBdr,
              boxShadow: c.glassShadow,
              backdropFilter: "blur(24px)",
              WebkitBackdropFilter: "blur(24px)",
              transition: "background 0.4s, border-color 0.4s, box-shadow 0.4s",
            }}
          >
            {/* Card header */}
            <div className="flex items-center justify-between mb-5">
              <span
                className="text-sm font-semibold"
                style={{ color: c.textPri, transition: "color 0.4s" }}
              >
                Security posture
              </span>
              <span
                className="text-xs font-mono"
                style={{ color: c.textMuted, transition: "color 0.4s" }}
              >
                gondolin-fc
              </span>
            </div>

            {/* Stat cards */}
            <div className="grid grid-cols-3 gap-3 mb-5">
              {STATS.map((s) => (
                <div
                  key={s.label}
                  className="rounded-lg px-4 py-3"
                  style={{
                    background: c.plate,
                    transition: "background 0.4s",
                  }}
                >
                  <div
                    className="text-[11px] uppercase tracking-wider mb-1"
                    style={{ color: c.textMuted, transition: "color 0.4s" }}
                  >
                    {s.label}
                  </div>
                  <div
                    className="text-xl font-bold tabular-nums"
                    style={{ color: c.textPri, transition: "color 0.4s" }}
                  >
                    {s.value}
                  </div>
                </div>
              ))}
            </div>

            {/* Divider */}
            <div
              className="h-px mb-4"
              style={{ background: c.divider, transition: "background 0.4s" }}
            />

            {/* Agent rows */}
            <div className="flex flex-col gap-2.5">
              {AGENTS.map((a) => (
                <div
                  key={a.name}
                  className="flex items-center justify-between rounded-lg px-4 py-2.5"
                  style={{
                    background: c.plate,
                    transition: "background 0.4s",
                  }}
                >
                  <span
                    className="text-sm font-mono"
                    style={{ color: c.textPri, transition: "color 0.4s" }}
                  >
                    {a.name}
                  </span>
                  <div className="flex items-center gap-2">
                    <span
                      className="text-[11px] font-medium uppercase tracking-wider rounded-full px-2.5 py-0.5"
                      style={{
                        background:
                          a.status === "running"
                            ? "rgba(16,185,129,0.15)"
                            : dark
                              ? "rgba(255,255,255,0.06)"
                              : "rgba(0,0,0,0.05)",
                        color: a.status === "running" ? "#34d399" : c.textMuted,
                        transition: "background 0.4s, color 0.4s",
                      }}
                    >
                      {a.status}
                    </span>
                    <span
                      className="rounded-full px-2 py-0.5 text-[11px] uppercase tracking-wider"
                      style={{
                        background: c.plate,
                        color: c.textMuted,
                        transition: "background 0.4s, color 0.4s",
                      }}
                    >
                      observed
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
