# Landing Page Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a lead-generation landing page for Valinor with dark/light mode, glassmorphism design, gold accents, and the floating toolbar as page navigation.

**Architecture:** New `(marketing)` route group with its own layout (no sidebar). Theme state lives in a React context shared by all sections and the toolbar. Each section is an isolated component. The toolbar is adapted from `floating-toolbar.tsx` with landing-page-specific nav items and scroll-spy.

**Tech Stack:** Next.js 16 (App Router), TypeScript, Tailwind CSS v4, Phosphor Icons (`/dist/ssr` for SSR page, regular for client components)

**Design doc:** `docs/plans/2026-03-11-landing-page-design.md`

**Reference component:** `dashboard/src/components/floating-toolbar.tsx` — all glassmorphism, gold ring, film grain, and color patterns come from here.

---

### Task 1: Theme Context + Shared Design Tokens

**Files:**
- Create: `dashboard/src/components/landing/theme.tsx`

**Step 1: Create theme context**

```tsx
"use client"

import { createContext, useContext, useState, useCallback, type ReactNode } from "react"

type Theme = "dark" | "light"

interface ThemeCtx {
  dark: boolean
  toggle: () => void
}

const Ctx = createContext<ThemeCtx>({ dark: true, toggle: () => {} })

export function useTheme() {
  return useContext(Ctx)
}

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [theme, setTheme] = useState<Theme>("dark")
  const toggle = useCallback(() => setTheme((t) => (t === "dark" ? "light" : "dark")), [])
  return <Ctx value={{ dark: theme === "dark", toggle }}>{children}</Ctx>
}

/* ── Shared design tokens ── */

export const RING_GRADIENT = `conic-gradient(
  from 0deg,
  #533517 0%,   #7a4f1e 8%,   #c49746 16%,  #e8af48 22%,
  #feeaa5 28%,  #ffc0cb 29.5%, #87ceeb 31%,
  #ffffff 32%,  #ffffff 35%,
  #feeaa5 36%,  #e8af48 40%,  #c49746 44%,  #7a4f1e 48%,
  #533517 50%,  #7a4f1e 58%,  #c49746 66%,  #e8af48 72%,
  #feeaa5 78%,  #ffc0cb 79.5%, #87ceeb 81%,
  #ffffff 82%,  #ffffff 85%,
  #feeaa5 86%,  #e8af48 90%,  #c49746 94%,  #7a4f1e 98%,
  #533517 100%
)`

export const GRAIN_URL = `url("data:image/svg+xml,%3Csvg viewBox='0 0 256 256' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='g'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.8' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23g)'/%3E%3C/svg%3E")`

export function palette(dark: boolean) {
  return {
    bg:        dark ? "#0c0c0e" : "#e4e4e8",
    bgAlt:     dark ? "#111114" : "#dddde0",
    glassBg:   dark ? "rgba(28,28,32,0.92)" : "rgba(250,250,250,0.88)",
    glassBdr:  dark ? "rgba(255,255,255,0.08)" : "rgba(0,0,0,0.06)",
    plate:     dark ? "#1e1e22" : "#efeff1",
    divider:   dark ? "rgba(255,255,255,0.06)" : "rgba(0,0,0,0.05)",
    textPri:   dark ? "rgba(255,255,255,0.95)" : "rgba(0,0,0,0.90)",
    textSec:   dark ? "rgba(255,255,255,0.55)" : "rgba(0,0,0,0.50)",
    textMuted: dark ? "rgba(255,255,255,0.35)" : "rgba(0,0,0,0.30)",
    iconOff:   dark ? "rgba(255,255,255,0.40)" : "rgba(0,0,0,0.35)",
    iconOn:    dark ? "rgba(255,255,255,0.95)" : "rgba(0,0,0,0.90)",
    toggleClr: dark ? "rgba(255,255,255,0.85)" : "rgba(0,0,0,0.75)",
    gold:      "#e8af48",
    glowA:     dark ? 0.07 : 0.04,
    grainA:    dark ? 0.30 : 0.12,
    glassShadow: [
      dark ? "0 10px 40px rgba(0,0,0,0.55)" : "0 10px 40px rgba(0,0,0,0.10)",
      dark ? "inset 0 1px 0 rgba(255,255,255,0.06)" : "inset 0 1px 0 rgba(255,255,255,0.65)",
      dark ? "inset 0 -1px 0 rgba(0,0,0,0.15)" : "inset 0 -1px 0 rgba(0,0,0,0.03)",
    ].join(","),
  }
}
```

**Step 2: Verify build**

Run: `cd dashboard && npx tsc --noEmit 2>&1 | grep "landing/theme"`
Expected: no output (no errors)

**Step 3: Commit**

```bash
git add dashboard/src/components/landing/theme.tsx
git commit -m "feat(landing): add theme context and shared design tokens"
```

---

### Task 2: Landing Toolbar

**Files:**
- Create: `dashboard/src/components/landing/landing-toolbar.tsx`

This is an adapted version of `floating-toolbar.tsx` that:
- Accepts `navItems` as props (section labels + ids)
- Accepts `activeIdx` from scroll-spy (controlled from parent)
- Calls `onNavigate(sectionId)` on click instead of managing own state
- Uses theme context instead of internal dark/light state
- Does NOT render page background/grain/glow (parent layout handles that)

**Step 1: Create landing toolbar**

```tsx
"use client"

import { useState } from "react"
import { useTheme, RING_GRADIENT, palette } from "./theme"

/* ── SVG Icons ── */

function IconOverview({ active }: { active: boolean }) {
  return (
    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth={active ? 2.0 : 1.5} strokeLinecap="round" strokeLinejoin="round">
      <path d="M3 9.5L12 3l9 6.5V20a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V9.5z" />
      <path d="M9 21V13h6v8" />
    </svg>
  )
}

function IconFeatures({ active }: { active: boolean }) {
  return (
    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth={active ? 2.0 : 1.5} strokeLinecap="round" strokeLinejoin="round">
      <rect x="3" y="3" width="7" height="7" rx="1" />
      <rect x="14" y="3" width="7" height="7" rx="1" />
      <rect x="3" y="14" width="7" height="7" rx="1" />
      <rect x="14" y="14" width="7" height="7" rx="1" />
    </svg>
  )
}

function IconPricing({ active }: { active: boolean }) {
  return (
    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth={active ? 2.0 : 1.5} strokeLinecap="round" strokeLinejoin="round">
      <path d="M20.59 13.41l-7.17 7.17a2 2 0 01-2.83 0L2 12V2h10l8.59 8.59a2 2 0 010 2.82z" />
      <circle cx="7" cy="7" r="1" fill="currentColor" stroke="none" />
    </svg>
  )
}

function IconContact({ active }: { active: boolean }) {
  return (
    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth={active ? 2.0 : 1.5} strokeLinecap="round" strokeLinejoin="round">
      <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z" />
      <polyline points="22,6 12,13 2,6" />
    </svg>
  )
}

function IconSun() {
  return (
    <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="5" />
      <path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42" />
    </svg>
  )
}

function IconMoon() {
  return (
    <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">
      <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" />
    </svg>
  )
}

/* ── Config ── */

export const LANDING_NAV = [
  { id: "hero", label: "Overview", Icon: IconOverview },
  { id: "features", label: "Features", Icon: IconFeatures },
  { id: "tiers", label: "Pricing", Icon: IconPricing },
  { id: "contact", label: "Contact", Icon: IconContact },
] as const

const S = 64
const P = 10
const G = 24
const STRIDE = S + G

/* ── Component ── */

export function LandingToolbar({
  activeIdx,
  onNavigate,
}: {
  activeIdx: number
  onNavigate: (sectionId: string) => void
}) {
  const { dark, toggle } = useTheme()
  const [bouncing, setBouncing] = useState(false)
  const c = palette(dark)

  const handleThemeToggle = () => {
    toggle()
    setBouncing(true)
  }

  const Divider = () => (
    <div
      style={{
        width: 1,
        height: 24,
        background: c.divider,
        marginInline: (G - 1) / 2,
        transition: "background 0.5s ease",
      }}
    />
  )

  return (
    <div
      className="fixed bottom-12 left-1/2 -translate-x-1/2 flex items-center"
      style={{
        padding: P,
        borderRadius: 34,
        background: c.glassBg,
        backdropFilter: "blur(24px) saturate(1.3)",
        WebkitBackdropFilter: "blur(24px) saturate(1.3)",
        border: `1px solid ${c.glassBdr}`,
        boxShadow: c.glassShadow,
        zIndex: 40,
        transition: "background 0.5s ease, border-color 0.5s ease, box-shadow 0.5s ease",
      }}
    >
      {/* Golden indicator ring */}
      <div
        className="absolute pointer-events-none"
        style={{
          top: P, left: P, width: S, height: S,
          transform: `translateX(${activeIdx * STRIDE}px)`,
          transition: "transform 0.5s cubic-bezier(0.34, 1.2, 0.64, 1)",
          zIndex: 1,
        }}
      >
        <div className="absolute rounded-[26px]" style={{ inset: -6, background: "#e8af48", opacity: 0.15, filter: "blur(14px)" }} />
        <div className="absolute inset-0 rounded-[22px] overflow-hidden">
          <div className="absolute animate-[spin-ring_10s_linear_infinite]" style={{ width: "200%", height: "200%", top: "-50%", left: "-50%", background: RING_GRADIENT, willChange: "transform" }} />
        </div>
        <div className="absolute rounded-[19px]" style={{ inset: 3, background: c.plate, transition: "background 0.5s ease" }} />
      </div>

      {/* Nav buttons */}
      {LANDING_NAV.map((item, i) => (
        <div key={item.id} className="flex items-center">
          <button
            onClick={() => onNavigate(item.id)}
            aria-label={item.label}
            className="relative flex items-center justify-center border-none bg-transparent cursor-pointer rounded-[20px] p-0 active:scale-95"
            style={{
              width: S, height: S,
              color: i === activeIdx ? c.iconOn : c.iconOff,
              zIndex: 2,
              transition: "color 0.3s ease, transform 0.15s ease",
            }}
          >
            <item.Icon active={i === activeIdx} />
          </button>
          {i < LANDING_NAV.length - 1 && <Divider />}
        </div>
      ))}

      <Divider />

      {/* Theme toggle */}
      <button
        onClick={handleThemeToggle}
        onAnimationEnd={() => setBouncing(false)}
        aria-label={dark ? "Switch to light mode" : "Switch to dark mode"}
        className="relative flex items-center justify-center border-none bg-transparent cursor-pointer rounded-[20px] p-0 active:scale-90"
        style={{
          width: S, height: S, color: c.toggleClr, zIndex: 2,
          animation: bouncing ? "theme-bounce 0.5s cubic-bezier(0.34,1.56,0.64,1)" : "none",
          transition: "color 0.3s ease",
        }}
      >
        <div className="relative" style={{ width: 22, height: 22 }}>
          <div className="absolute inset-0 flex items-center justify-center" style={{ opacity: dark ? 0 : 1, transform: dark ? "rotate(-90deg) scale(0.5)" : "rotate(0deg) scale(1)", transition: "opacity 0.4s ease, transform 0.4s cubic-bezier(0.34,1.2,0.64,1)" }}>
            <IconSun />
          </div>
          <div className="absolute inset-0 flex items-center justify-center" style={{ opacity: dark ? 1 : 0, transform: dark ? "rotate(0deg) scale(1)" : "rotate(90deg) scale(0.5)", transition: "opacity 0.4s ease, transform 0.4s cubic-bezier(0.34,1.2,0.64,1)" }}>
            <IconMoon />
          </div>
        </div>
      </button>

      <style>{`
        @keyframes spin-ring { to { transform: rotate(360deg); } }
        @keyframes theme-bounce { 0% { transform: scale(1); } 35% { transform: scale(1.25); } 100% { transform: scale(1); } }
      `}</style>
    </div>
  )
}
```

**Step 2: Verify build**

Run: `cd dashboard && npx tsc --noEmit 2>&1 | grep "landing/"`
Expected: no output

**Step 3: Commit**

```bash
git add dashboard/src/components/landing/landing-toolbar.tsx
git commit -m "feat(landing): add landing page toolbar with scroll nav"
```

---

### Task 3: Marketing Layout

**Files:**
- Create: `dashboard/src/app/(marketing)/layout.tsx`

This layout has no sidebar, no auth — just a bare shell with the theme provider, film grain, and ambient glow.

**Step 1: Create layout**

```tsx
import type { Metadata } from "next"

export const metadata: Metadata = {
  title: "Valinor — Enterprise AI Agent Infrastructure",
  description: "Deploy isolated AI agent instances per customer with multi-tenancy, RBAC, audit, and multi-channel messaging.",
}

export default function MarketingLayout({ children }: { children: React.ReactNode }) {
  return <>{children}</>
}
```

**Step 2: Verify build**

Run: `cd dashboard && npx next build 2>&1 | grep -E "marketing|error"`
Expected: no errors

**Step 3: Commit**

```bash
git add dashboard/src/app/\(marketing\)/layout.tsx
git commit -m "feat(landing): add marketing route group layout"
```

---

### Task 4: Hero Section

**Files:**
- Create: `dashboard/src/components/landing/hero.tsx`

**Step 1: Create hero component**

Left-aligned headline + subtext + gold-bordered CTA. Right side: a glassmorphism card with mock agent stats.

```tsx
"use client"

import { useTheme, palette, RING_GRADIENT } from "./theme"

export function Hero() {
  const { dark } = useTheme()
  const c = palette(dark)

  return (
    <section
      id="hero"
      className="relative min-h-[100dvh] flex items-center"
      style={{ transition: "background 0.6s ease" }}
    >
      <div className="mx-auto w-full max-w-[1200px] px-6 grid grid-cols-1 lg:grid-cols-2 gap-16 items-center">
        {/* Left — copy */}
        <div className="flex flex-col gap-6">
          <p
            className="text-sm font-medium tracking-widest uppercase"
            style={{ color: c.gold, transition: "color 0.5s ease" }}
          >
            AI Agent Infrastructure
          </p>
          <h1
            className="text-4xl md:text-5xl lg:text-6xl font-semibold tracking-tighter leading-[1.08]"
            style={{ color: c.textPri, transition: "color 0.5s ease" }}
          >
            Deploy AI Agents
            <br />
            at Enterprise Scale
          </h1>
          <p
            className="text-lg leading-relaxed max-w-[50ch]"
            style={{ color: c.textSec, transition: "color 0.5s ease" }}
          >
            Secure multi-tenant infrastructure for AI agents. Isolation, RBAC,
            audit trails, and multi-channel messaging — so you ship agents, not
            infrastructure.
          </p>
          {/* Gold-bordered CTA */}
          <div className="mt-2">
            <button
              className="relative cursor-pointer border-none bg-transparent p-0 group"
              style={{ borderRadius: 16 }}
            >
              {/* Gold border ring (static version of toolbar ring) */}
              <div
                className="absolute inset-0 rounded-[16px] overflow-hidden"
                style={{ opacity: 0.9 }}
              >
                <div
                  className="absolute animate-[spin-ring_10s_linear_infinite]"
                  style={{
                    width: "200%", height: "200%", top: "-50%", left: "-50%",
                    background: RING_GRADIENT, willChange: "transform",
                  }}
                />
              </div>
              <div
                className="relative rounded-[14px] px-8 py-3.5 text-base font-medium tracking-tight"
                style={{
                  background: c.plate,
                  color: c.textPri,
                  transition: "background 0.5s ease, color 0.5s ease",
                  margin: 2,
                }}
              >
                Request a Demo
              </div>
            </button>
          </div>
        </div>

        {/* Right — glassmorphism dashboard mockup */}
        <div className="hidden lg:block">
          <div
            className="rounded-[24px] p-6"
            style={{
              background: c.glassBg,
              border: `1px solid ${c.glassBdr}`,
              boxShadow: c.glassShadow,
              backdropFilter: "blur(20px)",
              WebkitBackdropFilter: "blur(20px)",
              transition: "background 0.5s ease, border-color 0.5s ease, box-shadow 0.5s ease",
            }}
          >
            {/* Mock header */}
            <div className="flex items-center justify-between mb-5">
              <span className="text-sm font-medium" style={{ color: c.textPri }}>Agent Fleet</span>
              <span className="text-xs font-mono" style={{ color: c.textMuted }}>gondolin-fc</span>
            </div>
            {/* Mock stat row */}
            <div className="grid grid-cols-3 gap-4 mb-5">
              {[
                { label: "Active Agents", value: "24" },
                { label: "Tenants", value: "8" },
                { label: "Uptime", value: "99.97%" },
              ].map((s) => (
                <div
                  key={s.label}
                  className="rounded-[14px] p-4"
                  style={{
                    background: dark ? "rgba(255,255,255,0.03)" : "rgba(0,0,0,0.03)",
                    border: `1px solid ${c.glassBdr}`,
                    transition: "background 0.5s ease, border-color 0.5s ease",
                  }}
                >
                  <div className="text-xs mb-1" style={{ color: c.textMuted }}>{s.label}</div>
                  <div className="text-xl font-semibold font-mono" style={{ color: c.textPri }}>{s.value}</div>
                </div>
              ))}
            </div>
            {/* Mock agent list */}
            <div className="flex flex-col gap-2">
              {[
                { name: "support-agent-01", status: "running" },
                { name: "onboarding-flow", status: "running" },
                { name: "data-analyst-v3", status: "idle" },
              ].map((a) => (
                <div
                  key={a.name}
                  className="flex items-center justify-between rounded-[10px] px-4 py-2.5"
                  style={{
                    background: dark ? "rgba(255,255,255,0.02)" : "rgba(0,0,0,0.02)",
                    transition: "background 0.5s ease",
                  }}
                >
                  <span className="text-sm font-mono" style={{ color: c.textSec }}>{a.name}</span>
                  <span
                    className="text-xs font-medium px-2 py-0.5 rounded-full"
                    style={{
                      background: a.status === "running"
                        ? dark ? "rgba(5,150,105,0.15)" : "rgba(5,150,105,0.1)"
                        : dark ? "rgba(255,255,255,0.05)" : "rgba(0,0,0,0.05)",
                      color: a.status === "running" ? "#059669" : c.textMuted,
                    }}
                  >
                    {a.status}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </section>
  )
}
```

**Step 2: Verify build**

Run: `cd dashboard && npx tsc --noEmit 2>&1 | grep "landing/hero"`
Expected: no output

**Step 3: Commit**

```bash
git add dashboard/src/components/landing/hero.tsx
git commit -m "feat(landing): add hero section with glassmorphism dashboard mockup"
```

---

### Task 5: Why Valinor Section

**Files:**
- Create: `dashboard/src/components/landing/why-valinor.tsx`

3 glassmorphism pain-point cards on a slightly lighter background.

**Step 1: Create component**

```tsx
"use client"

import { useTheme, palette } from "./theme"

const CARDS = [
  {
    title: "Tenant Isolation",
    desc: "Every customer gets their own sandboxed runtime. Docker containers or Firecracker microVMs — hardware-level isolation that keeps workloads completely separated.",
    icon: (
      <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
        <rect x="2" y="6" width="20" height="12" rx="2" />
        <path d="M12 6v12M2 12h20" />
      </svg>
    ),
  },
  {
    title: "Compliance Built In",
    desc: "Deny-by-default RBAC, full audit trails on every action, prompt injection defense, and tool allow-listing. Security is the foundation, not an afterthought.",
    icon: (
      <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
        <path d="M9 12l2 2 4-4" />
      </svg>
    ),
  },
  {
    title: "Ship in Days, Not Months",
    desc: "Pre-built agent orchestration, credential management, and multi-channel messaging. One API call replaces weeks of infrastructure work.",
    icon: (
      <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
        <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2" />
      </svg>
    ),
  },
]

export function WhyValinor() {
  const { dark } = useTheme()
  const c = palette(dark)

  return (
    <section
      id="why"
      className="relative py-32"
      style={{ background: c.bgAlt, transition: "background 0.6s ease" }}
    >
      <div className="mx-auto max-w-[1200px] px-6">
        <p
          className="text-sm font-medium tracking-widest uppercase mb-3"
          style={{ color: c.gold }}
        >
          Why Valinor
        </p>
        <h2
          className="text-3xl md:text-4xl font-semibold tracking-tight mb-16"
          style={{ color: c.textPri, transition: "color 0.5s ease" }}
        >
          Infrastructure you&apos;d build yourself —<br className="hidden md:block" />
          already built, secured, and battle-tested.
        </h2>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {CARDS.map((card) => (
            <div
              key={card.title}
              className="rounded-[20px] p-7 flex flex-col gap-4"
              style={{
                background: c.glassBg,
                border: `1px solid ${c.glassBdr}`,
                boxShadow: c.glassShadow,
                backdropFilter: "blur(16px)",
                WebkitBackdropFilter: "blur(16px)",
                transition: "background 0.5s ease, border-color 0.5s ease, box-shadow 0.5s ease",
              }}
            >
              <div style={{ color: c.gold }}>{card.icon}</div>
              <h3
                className="text-lg font-semibold"
                style={{ color: c.textPri, transition: "color 0.5s ease" }}
              >
                {card.title}
              </h3>
              <p
                className="text-sm leading-relaxed"
                style={{ color: c.textSec, transition: "color 0.5s ease" }}
              >
                {card.desc}
              </p>
            </div>
          ))}
        </div>
      </div>
    </section>
  )
}
```

**Step 2: Verify build, commit**

```bash
cd dashboard && npx tsc --noEmit 2>&1 | grep "landing/why"
git add dashboard/src/components/landing/why-valinor.tsx
git commit -m "feat(landing): add why-valinor section with glass cards"
```

---

### Task 6: Features Section (Zigzag)

**Files:**
- Create: `dashboard/src/components/landing/features.tsx`

3 features in alternating text-left/visual-right layout.

**Step 1: Create component**

```tsx
"use client"

import { useTheme, palette } from "./theme"

const FEATURES = [
  {
    tag: "Isolation",
    title: "Multi-Tenant Sandboxing",
    desc: "Each tenant runs in its own isolated runtime — Docker containers for Teams, Firecracker microVMs for Enterprise. Row-level security in the database. No cross-tenant data leaks, ever.",
    visual: MultiTenantVisual,
  },
  {
    tag: "Security",
    title: "RBAC + Full Audit Trail",
    desc: "Hierarchical roles with resource-level policies. Deny-by-default permissions. Every API call, agent action, and admin operation is logged with tamper-evident audit trails.",
    visual: RbacVisual,
  },
  {
    tag: "Channels",
    title: "Multi-Channel Messaging",
    desc: "Connect agents to Slack, WhatsApp, and Telegram with managed webhooks. Conversation continuity across channels. Credential encryption at rest.",
    visual: ChannelsVisual,
  },
]

function MultiTenantVisual({ dark, c }: { dark: boolean; c: ReturnType<typeof palette> }) {
  return (
    <div className="grid grid-cols-2 gap-3">
      {["Tenant A", "Tenant B", "Tenant C", "Tenant D"].map((t) => (
        <div
          key={t}
          className="rounded-[14px] p-4 flex flex-col gap-1"
          style={{
            background: dark ? "rgba(255,255,255,0.03)" : "rgba(0,0,0,0.03)",
            border: `1px solid ${c.glassBdr}`,
          }}
        >
          <span className="text-xs font-mono" style={{ color: c.textMuted }}>{t}</span>
          <div className="flex gap-1 mt-2">
            <div className="w-2 h-2 rounded-full" style={{ background: "#059669" }} />
            <div className="w-2 h-2 rounded-full" style={{ background: "#059669" }} />
            <div className="w-2 h-2 rounded-full" style={{ background: c.divider }} />
          </div>
        </div>
      ))}
    </div>
  )
}

function RbacVisual({ dark, c }: { dark: boolean; c: ReturnType<typeof palette> }) {
  const roles = [
    { name: "org_admin", perms: 12 },
    { name: "dept_head", perms: 8 },
    { name: "standard_user", perms: 5 },
    { name: "read_only", perms: 2 },
  ]
  return (
    <div className="flex flex-col gap-2">
      {roles.map((r) => (
        <div
          key={r.name}
          className="flex items-center justify-between rounded-[10px] px-4 py-2.5"
          style={{ background: dark ? "rgba(255,255,255,0.03)" : "rgba(0,0,0,0.03)" }}
        >
          <span className="text-sm font-mono" style={{ color: c.textSec }}>{r.name}</span>
          <span className="text-xs font-mono" style={{ color: c.textMuted }}>{r.perms} permissions</span>
        </div>
      ))}
    </div>
  )
}

function ChannelsVisual({ dark, c }: { dark: boolean; c: ReturnType<typeof palette> }) {
  const channels = ["Slack", "WhatsApp", "Telegram"]
  return (
    <div className="flex flex-col gap-3">
      {channels.map((ch) => (
        <div
          key={ch}
          className="flex items-center gap-3 rounded-[10px] px-4 py-3"
          style={{
            background: dark ? "rgba(255,255,255,0.03)" : "rgba(0,0,0,0.03)",
            border: `1px solid ${c.glassBdr}`,
          }}
        >
          <div className="w-2 h-2 rounded-full" style={{ background: "#059669" }} />
          <span className="text-sm font-medium" style={{ color: c.textSec }}>{ch}</span>
          <span className="text-xs font-mono ml-auto" style={{ color: c.textMuted }}>connected</span>
        </div>
      ))}
    </div>
  )
}

export function Features() {
  const { dark } = useTheme()
  const c = palette(dark)

  return (
    <section id="features" className="relative py-32" style={{ transition: "background 0.6s ease" }}>
      <div className="mx-auto max-w-[1200px] px-6 flex flex-col gap-28">
        {FEATURES.map((feat, i) => {
          const reversed = i % 2 === 1
          return (
            <div
              key={feat.tag}
              className={`grid grid-cols-1 lg:grid-cols-2 gap-12 items-center ${reversed ? "lg:direction-rtl" : ""}`}
              style={{ direction: "ltr" }}
            >
              <div className={`flex flex-col gap-4 ${reversed ? "lg:order-2" : ""}`}>
                <p className="text-sm font-medium tracking-widest uppercase" style={{ color: c.gold }}>
                  {feat.tag}
                </p>
                <h3 className="text-2xl md:text-3xl font-semibold tracking-tight" style={{ color: c.textPri, transition: "color 0.5s ease" }}>
                  {feat.title}
                </h3>
                <p className="text-base leading-relaxed max-w-[50ch]" style={{ color: c.textSec, transition: "color 0.5s ease" }}>
                  {feat.desc}
                </p>
              </div>
              <div className={`${reversed ? "lg:order-1" : ""}`}>
                <div
                  className="rounded-[20px] p-6"
                  style={{
                    background: c.glassBg,
                    border: `1px solid ${c.glassBdr}`,
                    boxShadow: c.glassShadow,
                    backdropFilter: "blur(16px)",
                    WebkitBackdropFilter: "blur(16px)",
                    transition: "background 0.5s ease, border-color 0.5s ease",
                  }}
                >
                  <feat.visual dark={dark} c={c} />
                </div>
              </div>
            </div>
          )
        })}
      </div>
    </section>
  )
}
```

**Step 2: Verify build, commit**

```bash
cd dashboard && npx tsc --noEmit 2>&1 | grep "landing/features"
git add dashboard/src/components/landing/features.tsx
git commit -m "feat(landing): add features zigzag section with mock visuals"
```

---

### Task 7: Tiers Section

**Files:**
- Create: `dashboard/src/components/landing/tiers.tsx`

Two side-by-side cards. Enterprise gets a gold gradient badge.

**Step 1: Create component**

```tsx
"use client"

import { useTheme, palette, RING_GRADIENT } from "./theme"

const PLANS = [
  {
    name: "Teams",
    desc: "For dev teams and startups shipping AI-powered products.",
    runtime: "Docker containers",
    coldStart: "2–5 seconds",
    isolation: "Container-level",
    features: ["Multi-tenancy", "RBAC + audit logs", "Multi-channel messaging", "MCP connectors", "Community support"],
    cta: "Get Started",
    gold: false,
  },
  {
    name: "Enterprise",
    desc: "For regulated industries that demand hardware-level isolation.",
    runtime: "Firecracker microVMs",
    coldStart: "~125ms",
    isolation: "Hardware-virtualized",
    features: ["Everything in Teams", "Firecracker microVMs", "Sub-200ms cold start", "SSO + SCIM provisioning", "Dedicated support + SLA"],
    cta: "Contact Sales",
    gold: true,
  },
]

export function Tiers() {
  const { dark } = useTheme()
  const c = palette(dark)

  return (
    <section
      id="tiers"
      className="relative py-32"
      style={{ background: c.bgAlt, transition: "background 0.6s ease" }}
    >
      <div className="mx-auto max-w-[1200px] px-6">
        <p className="text-sm font-medium tracking-widest uppercase mb-3" style={{ color: c.gold }}>
          Pricing
        </p>
        <h2
          className="text-3xl md:text-4xl font-semibold tracking-tight mb-16"
          style={{ color: c.textPri, transition: "color 0.5s ease" }}
        >
          Choose your isolation level.
        </h2>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {PLANS.map((plan) => (
            <div
              key={plan.name}
              className="relative rounded-[20px] p-8 flex flex-col gap-6"
              style={{
                background: c.glassBg,
                border: `1px solid ${plan.gold ? "rgba(232,175,72,0.25)" : c.glassBdr}`,
                boxShadow: plan.gold
                  ? `${c.glassShadow}, 0 0 40px rgba(232,175,72,0.06)`
                  : c.glassShadow,
                backdropFilter: "blur(16px)",
                WebkitBackdropFilter: "blur(16px)",
                transition: "background 0.5s ease, border-color 0.5s ease, box-shadow 0.5s ease",
              }}
            >
              {/* Gold badge for Enterprise */}
              {plan.gold && (
                <div className="absolute -top-3 left-8 rounded-full overflow-hidden" style={{ height: 26 }}>
                  <div className="absolute inset-0" style={{ background: RING_GRADIENT }} />
                  <div
                    className="relative px-4 py-1 text-xs font-semibold tracking-wide uppercase rounded-full"
                    style={{ background: c.plate, color: c.gold, margin: 1.5 }}
                  >
                    Recommended
                  </div>
                </div>
              )}

              <div>
                <h3 className="text-2xl font-semibold mb-2" style={{ color: c.textPri }}>{plan.name}</h3>
                <p className="text-sm" style={{ color: c.textSec }}>{plan.desc}</p>
              </div>

              {/* Specs */}
              <div className="flex flex-col gap-2">
                {[
                  { label: "Runtime", value: plan.runtime },
                  { label: "Cold start", value: plan.coldStart },
                  { label: "Isolation", value: plan.isolation },
                ].map((spec) => (
                  <div key={spec.label} className="flex items-center justify-between text-sm">
                    <span style={{ color: c.textMuted }}>{spec.label}</span>
                    <span className="font-mono" style={{ color: c.textSec }}>{spec.value}</span>
                  </div>
                ))}
              </div>

              {/* Divider */}
              <div style={{ height: 1, background: c.divider }} />

              {/* Features */}
              <ul className="flex flex-col gap-2.5">
                {plan.features.map((f) => (
                  <li key={f} className="flex items-center gap-2.5 text-sm" style={{ color: c.textSec }}>
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#059669" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <polyline points="20 6 9 17 4 12" />
                    </svg>
                    {f}
                  </li>
                ))}
              </ul>

              {/* CTA */}
              <button
                className="mt-auto cursor-pointer border-none rounded-[14px] px-6 py-3 text-sm font-medium tracking-tight active:scale-[0.97]"
                style={{
                  background: plan.gold ? c.gold : "transparent",
                  color: plan.gold
                    ? "#0c0c0e"
                    : c.textPri,
                  border: plan.gold ? "none" : `1px solid ${c.glassBdr}`,
                  transition: "background 0.3s ease, color 0.3s ease, border-color 0.3s ease, transform 0.15s ease",
                }}
              >
                {plan.cta}
              </button>
            </div>
          ))}
        </div>
      </div>
    </section>
  )
}
```

**Step 2: Verify build, commit**

```bash
cd dashboard && npx tsc --noEmit 2>&1 | grep "landing/tiers"
git add dashboard/src/components/landing/tiers.tsx
git commit -m "feat(landing): add tiers section with gold enterprise badge"
```

---

### Task 8: Footer CTA + Footer

**Files:**
- Create: `dashboard/src/components/landing/footer.tsx`

**Step 1: Create component**

```tsx
"use client"

import { useTheme, palette, RING_GRADIENT } from "./theme"

export function FooterCta() {
  const { dark } = useTheme()
  const c = palette(dark)

  return (
    <>
      {/* CTA band */}
      <section
        id="contact"
        className="relative py-32 flex flex-col items-center text-center"
        style={{ transition: "background 0.6s ease" }}
      >
        <h2
          className="text-3xl md:text-4xl font-semibold tracking-tight mb-4"
          style={{ color: c.textPri, transition: "color 0.5s ease" }}
        >
          Ready to deploy your agent fleet?
        </h2>
        <p className="text-base mb-10 max-w-[48ch]" style={{ color: c.textSec }}>
          Get started with Valinor and ship enterprise-grade AI agents in days, not months.
        </p>
        <button
          className="relative cursor-pointer border-none bg-transparent p-0"
          style={{ borderRadius: 16 }}
        >
          <div className="absolute inset-0 rounded-[16px] overflow-hidden" style={{ opacity: 0.9 }}>
            <div
              className="absolute animate-[spin-ring_10s_linear_infinite]"
              style={{ width: "200%", height: "200%", top: "-50%", left: "-50%", background: RING_GRADIENT, willChange: "transform" }}
            />
          </div>
          <div
            className="relative rounded-[14px] px-10 py-4 text-base font-medium tracking-tight"
            style={{ background: c.plate, color: c.textPri, margin: 2, transition: "background 0.5s ease, color 0.5s ease" }}
          >
            Request a Demo
          </div>
        </button>
      </section>

      {/* Footer */}
      <footer className="py-10 px-6">
        <div className="mx-auto max-w-[1200px] flex flex-col md:flex-row items-center justify-between gap-4">
          <span className="text-sm font-semibold" style={{ color: c.textSec }}>Valinor</span>
          <div className="flex gap-6">
            {["Docs", "GitHub", "Contact"].map((link) => (
              <a
                key={link}
                href="#"
                className="text-sm no-underline hover:underline"
                style={{ color: c.textMuted, transition: "color 0.3s ease" }}
              >
                {link}
              </a>
            ))}
          </div>
          <span className="text-xs" style={{ color: c.textMuted }}>
            &copy; {new Date().getFullYear()} Valinor. All rights reserved.
          </span>
        </div>
      </footer>
    </>
  )
}
```

**Step 2: Verify build, commit**

```bash
cd dashboard && npx tsc --noEmit 2>&1 | grep "landing/footer"
git add dashboard/src/components/landing/footer.tsx
git commit -m "feat(landing): add footer CTA and footer"
```

---

### Task 9: Landing Page Assembly + Scroll Spy

**Files:**
- Create: `dashboard/src/app/(marketing)/page.tsx`

This is the main page that:
- Wraps everything in `ThemeProvider`
- Renders all sections
- Manages scroll-spy to update toolbar active index
- Renders film grain + ambient glow as page-level overlays
- Handles `onNavigate` to smooth-scroll to sections

**Step 1: Create landing page**

```tsx
"use client"

import { useState, useEffect, useCallback } from "react"
import { ThemeProvider, useTheme, palette, GRAIN_URL } from "@/components/landing/theme"
import { LandingToolbar, LANDING_NAV } from "@/components/landing/landing-toolbar"
import { Hero } from "@/components/landing/hero"
import { WhyValinor } from "@/components/landing/why-valinor"
import { Features } from "@/components/landing/features"
import { Tiers } from "@/components/landing/tiers"
import { FooterCta } from "@/components/landing/footer"

function LandingContent() {
  const { dark } = useTheme()
  const c = palette(dark)
  const [activeIdx, setActiveIdx] = useState(0)

  /* Scroll spy — track which section is in view */
  useEffect(() => {
    const sectionIds = LANDING_NAV.map((n) => n.id)

    const onScroll = () => {
      const scrollY = window.scrollY + window.innerHeight / 3

      for (let i = sectionIds.length - 1; i >= 0; i--) {
        const el = document.getElementById(sectionIds[i])
        if (el && el.offsetTop <= scrollY) {
          setActiveIdx(i)
          break
        }
      }
    }

    window.addEventListener("scroll", onScroll, { passive: true })
    onScroll()
    return () => window.removeEventListener("scroll", onScroll)
  }, [])

  const handleNavigate = useCallback((sectionId: string) => {
    const el = document.getElementById(sectionId)
    if (el) {
      el.scrollIntoView({ behavior: "smooth" })
    }
  }, [])

  return (
    <div
      className="relative min-h-[100dvh] font-sans"
      style={{ background: c.bg, transition: "background 0.6s ease" }}
    >
      {/* Ambient radial glow */}
      <div
        className="fixed inset-0 pointer-events-none"
        style={{
          background: `radial-gradient(ellipse 700px 350px at 50% 100%, rgba(232,175,72,${c.glowA}) 0%, transparent 70%)`,
          transition: "background 0.6s ease",
        }}
      />

      {/* Film grain */}
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

      {/* Page content */}
      <Hero />
      <WhyValinor />
      <Features />
      <Tiers />
      <FooterCta />

      {/* Toolbar */}
      <LandingToolbar activeIdx={activeIdx} onNavigate={handleNavigate} />
    </div>
  )
}

export default function LandingPage() {
  return (
    <ThemeProvider>
      <LandingContent />
    </ThemeProvider>
  )
}
```

**Step 2: Verify full build**

Run: `cd dashboard && npx next build 2>&1 | grep -E "marketing|error|✓ Compiled"`
Expected: `✓ Compiled successfully`, route `/(marketing)` listed

**Step 3: Commit**

```bash
git add dashboard/src/app/\(marketing\)/page.tsx
git commit -m "feat(landing): assemble landing page with scroll spy and toolbar nav"
```

---

### Task 10: Final Build + Visual Check

**Step 1: Full build**

Run: `cd dashboard && npx next build`
Expected: clean build, no errors

**Step 2: Dev server check**

Run: `cd dashboard && npm run dev`
Navigate to `http://localhost:3000` — should show the landing page

**Step 3: Verify checklist**
- [ ] All 5 sections render
- [ ] Toolbar appears fixed at bottom, gold ring tracks scroll position
- [ ] Clicking toolbar nav scrolls to sections
- [ ] Dark/light toggle works across all sections
- [ ] Film grain and ambient glow visible
- [ ] Gold-bordered CTA buttons render with spinning gradient
- [ ] Enterprise card has gold badge
- [ ] Mobile: single column layout, toolbar still works

**Step 4: Final commit**

```bash
git add -A
git commit -m "feat(landing): complete Valinor landing page with dark/light mode"
```

---

## File Summary

| File | Purpose |
|------|---------|
| `dashboard/src/components/landing/theme.tsx` | Theme context + shared palette + design tokens |
| `dashboard/src/components/landing/landing-toolbar.tsx` | Adapted floating toolbar for landing nav |
| `dashboard/src/components/landing/hero.tsx` | Hero section with dashboard mockup |
| `dashboard/src/components/landing/why-valinor.tsx` | 3 pain-point glass cards |
| `dashboard/src/components/landing/features.tsx` | Zigzag feature rows with mock visuals |
| `dashboard/src/components/landing/tiers.tsx` | Teams vs Enterprise tier cards |
| `dashboard/src/components/landing/footer.tsx` | Footer CTA + footer links |
| `dashboard/src/app/(marketing)/layout.tsx` | Marketing route layout (no sidebar) |
| `dashboard/src/app/(marketing)/page.tsx` | Landing page assembly + scroll spy |

## Parallelization

Tasks 4, 5, 6, 7, 8 (Hero, WhyValinor, Features, Tiers, Footer) are **independent** and can be dispatched as parallel subagents after Tasks 1-3 are complete.
