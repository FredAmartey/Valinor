"use client";

import { useTheme, palette } from "./theme";

const features = [
  {
    tag: "Isolation",
    title: "Multi-Tenant Sandboxing",
    desc: "Each tenant runs in its own isolated runtime — Docker containers for Teams, Firecracker microVMs for Enterprise. Row-level security in the database. No cross-tenant data leaks, ever.",
    visual: "tenants",
  },
  {
    tag: "Security",
    title: "RBAC + Full Audit Trail",
    desc: "Hierarchical roles with resource-level policies. Deny-by-default permissions. Every API call, agent action, and admin operation is logged with tamper-evident audit trails.",
    visual: "roles",
  },
  {
    tag: "Channels",
    title: "Multi-Channel Messaging",
    desc: "Connect agents to Slack, WhatsApp, and Telegram with managed webhooks. Conversation continuity across channels. Credential encryption at rest.",
    visual: "channels",
  },
] as const;

function TenantGrid({ c }: { c: ReturnType<typeof palette> }) {
  const tenants = [
    { name: "Tenant A", color: "#059669" },
    { name: "Tenant B", color: c.gold },
    { name: "Tenant C", color: "#3b82f6" },
    { name: "Tenant D", color: "#a855f7" },
  ];

  return (
    <div className="grid grid-cols-2 gap-3">
      {tenants.map((t) => (
        <div
          key={t.name}
          className="rounded-xl px-4 py-3 flex items-center gap-3"
          style={{ backgroundColor: c.bgAlt, border: `1px solid ${c.divider}` }}
        >
          <span
            className="block h-2.5 w-2.5 rounded-full shrink-0"
            style={{ backgroundColor: t.color }}
          />
          <span
            className="text-sm font-medium"
            style={{ color: c.textPri }}
          >
            {t.name}
          </span>
        </div>
      ))}
    </div>
  );
}

function RolesList({ c }: { c: ReturnType<typeof palette> }) {
  const roles = [
    { name: "org_admin", perms: 12 },
    { name: "dept_head", perms: 8 },
    { name: "standard_user", perms: 5 },
    { name: "read_only", perms: 2 },
  ];

  return (
    <div className="flex flex-col gap-2">
      {roles.map((r) => (
        <div
          key={r.name}
          className="rounded-xl px-4 py-3 flex items-center justify-between"
          style={{ backgroundColor: c.bgAlt, border: `1px solid ${c.divider}` }}
        >
          <span
            className="text-sm font-mono"
            style={{ color: c.textPri }}
          >
            {r.name}
          </span>
          <span
            className="text-xs font-mono"
            style={{ color: c.textMuted }}
          >
            {r.perms} perms
          </span>
        </div>
      ))}
    </div>
  );
}

function ChannelsList({ c }: { c: ReturnType<typeof palette> }) {
  const channels = ["Slack", "WhatsApp", "Telegram"];

  return (
    <div className="flex flex-col gap-2">
      {channels.map((ch) => (
        <div
          key={ch}
          className="rounded-xl px-4 py-3 flex items-center justify-between"
          style={{ backgroundColor: c.bgAlt, border: `1px solid ${c.divider}` }}
        >
          <span
            className="text-sm font-medium"
            style={{ color: c.textPri }}
          >
            {ch}
          </span>
          <span className="flex items-center gap-2">
            <span
              className="block h-2.5 w-2.5 rounded-full"
              style={{ backgroundColor: "#059669" }}
            />
            <span
              className="text-xs"
              style={{ color: c.textMuted }}
            >
              connected
            </span>
          </span>
        </div>
      ))}
    </div>
  );
}

export function Features() {
  const { dark } = useTheme();
  const c = palette(dark);

  return (
    <section id="features" className="py-32">
      <div className="mx-auto max-w-[1200px] flex flex-col gap-28 px-6">
        {features.map((f, i) => {
          const isOdd = i % 2 !== 0;

          return (
            <div
              key={f.title}
              className="grid grid-cols-1 lg:grid-cols-2 gap-12 items-center"
            >
              {/* Text side */}
              <div
                className={`flex flex-col gap-5 ${isOdd ? "lg:order-2" : "lg:order-1"}`}
              >
                <span
                  className="text-xs font-semibold uppercase tracking-widest w-fit rounded-full px-3 py-1"
                  style={{
                    color: c.gold,
                    backgroundColor: `${c.gold}15`,
                    border: `1px solid ${c.gold}30`,
                  }}
                >
                  {f.tag}
                </span>
                <h3
                  className="text-2xl md:text-3xl font-bold"
                  style={{ color: c.textPri }}
                >
                  {f.title}
                </h3>
                <p
                  className="text-base leading-relaxed"
                  style={{ color: c.textSec }}
                >
                  {f.desc}
                </p>
              </div>

              {/* Visual side */}
              <div
                className={`rounded-[20px] p-6 backdrop-blur ${isOdd ? "lg:order-1" : "lg:order-2"}`}
                style={{
                  backgroundColor: c.glassBg,
                  border: `1px solid ${c.glassBdr}`,
                  boxShadow: c.glassShadow,
                }}
              >
                {f.visual === "tenants" && <TenantGrid c={c} />}
                {f.visual === "roles" && <RolesList c={c} />}
                {f.visual === "channels" && <ChannelsList c={c} />}
              </div>
            </div>
          );
        })}
      </div>
    </section>
  );
}
