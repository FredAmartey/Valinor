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

function Divider({ color }: { color: string }) {
  return (
    <div
      style={{
        width: 1,
        height: 24,
        background: color,
        marginInline: (G - 1) / 2,
        transition: "background 0.5s ease",
      }}
    />
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
          {i < LANDING_NAV.length - 1 && <Divider color={c.divider} />}
        </div>
      ))}

      <Divider color={c.divider} />

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
