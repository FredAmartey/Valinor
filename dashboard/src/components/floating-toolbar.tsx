"use client"

import { useState } from "react"

/* ──────────────────────── SVG Icons ──────────────────────── */

function IconHome({ active }: { active: boolean }) {
  return (
    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth={active ? 2.0 : 1.5} strokeLinecap="round" strokeLinejoin="round">
      <path d="M3 9.5L12 3l9 6.5V20a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V9.5z" />
      <path d="M9 21V13h6v8" />
    </svg>
  )
}

function IconSearch({ active }: { active: boolean }) {
  return (
    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth={active ? 2.0 : 1.5} strokeLinecap="round" strokeLinejoin="round">
      <circle cx="11" cy="11" r="7" />
      <path d="M21 21l-4.35-4.35" />
    </svg>
  )
}

function IconUser({ active }: { active: boolean }) {
  return (
    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth={active ? 2.0 : 1.5} strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="8" r="4" />
      <path d="M5 21c0-4 3.5-7 7-7s7 3 7 7" />
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

/* ──────────────────────── Config ──────────────────────── */

const NAV = [
  { id: "home", label: "Home", Icon: IconHome },
  { id: "search", label: "Search", Icon: IconSearch },
  { id: "user", label: "User", Icon: IconUser },
] as const

const S  = 64                   // button / indicator size
const P  = 10                   // toolbar inner padding
const G  = 24                   // gap between buttons (includes divider)
const STRIDE = S + G            // 88px — distance between button left-edges

/* Golden conic gradient — 70% gold, 2 white hotspots, thin pink/blue hints */
const RING = `conic-gradient(
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

/* SVG noise for film grain */
const GRAIN = `url("data:image/svg+xml,%3Csvg viewBox='0 0 256 256' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='g'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.8' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23g)'/%3E%3C/svg%3E")`

/* ──────────────────────── Component ──────────────────────── */

export function FloatingToolbar() {
  const [activeIdx, setActiveIdx] = useState(0)
  const [dark, setDark] = useState(true)
  const [bouncing, setBouncing] = useState(false)

  const handleThemeToggle = () => {
    setDark((d) => !d)
    setBouncing(true)
  }

  /* ── theme-aware palette ── */
  const bg      = dark ? "#0c0c0e" : "#e4e4e8"
  const barBg   = dark ? "rgba(28,28,32,0.92)" : "rgba(250,250,250,0.88)"
  const barBdr  = dark ? "rgba(255,255,255,0.08)" : "rgba(0,0,0,0.06)"
  const plate   = dark ? "#1e1e22" : "#efeff1"
  const divClr  = dark ? "rgba(255,255,255,0.06)" : "rgba(0,0,0,0.05)"
  const iconOff = dark ? "rgba(255,255,255,0.40)" : "rgba(0,0,0,0.35)"
  const iconOn  = dark ? "rgba(255,255,255,0.95)" : "rgba(0,0,0,0.90)"
  const toggleC = dark ? "rgba(255,255,255,0.85)" : "rgba(0,0,0,0.75)"
  const glowA   = dark ? 0.07 : 0.04
  const grainA  = dark ? 0.30 : 0.12

  const barShadow = [
    dark ? "0 10px 40px rgba(0,0,0,0.55)" : "0 10px 40px rgba(0,0,0,0.10)",
    dark ? "inset 0 1px 0 rgba(255,255,255,0.06)" : "inset 0 1px 0 rgba(255,255,255,0.65)",
    dark ? "inset 0 -1px 0 rgba(0,0,0,0.15)" : "inset 0 -1px 0 rgba(0,0,0,0.03)",
  ].join(",")

  return (
    <div
      className="fixed inset-0 flex items-end justify-center pb-12 font-sans"
      style={{ background: bg, transition: "background 0.6s ease" }}
    >
      {/* ── Ambient radial glow ── */}
      <div
        className="fixed inset-0 pointer-events-none"
        style={{
          background: `radial-gradient(ellipse 700px 350px at 50% 100%, rgba(232,175,72,${glowA}) 0%, transparent 70%)`,
          transition: "background 0.6s ease",
        }}
      />

      {/* ── Film grain ── */}
      <div
        className="fixed inset-0 pointer-events-none"
        style={{
          opacity: grainA,
          mixBlendMode: "overlay",
          backgroundImage: GRAIN,
          backgroundRepeat: "repeat",
          backgroundSize: "256px 256px",
          transition: "opacity 0.6s ease",
        }}
      />

      {/* ── Toolbar ── */}
      <div
        className="relative flex items-center"
        style={{
          padding: P,
          borderRadius: 34,
          background: barBg,
          backdropFilter: "blur(24px) saturate(1.3)",
          WebkitBackdropFilter: "blur(24px) saturate(1.3)",
          border: `1px solid ${barBdr}`,
          boxShadow: barShadow,
          transition: "background 0.5s ease, border-color 0.5s ease, box-shadow 0.5s ease",
        }}
      >
        {/* ── Golden indicator ring ── */}
        <div
          className="absolute pointer-events-none"
          style={{
            top: P,
            left: P,
            width: S,
            height: S,
            transform: `translateX(${activeIdx * STRIDE}px)`,
            transition: "transform 0.5s cubic-bezier(0.34, 1.2, 0.64, 1)",
            zIndex: 1,
          }}
        >
          {/* Layer 1 — Glow */}
          <div
            className="absolute rounded-[26px]"
            style={{
              inset: -6,
              background: "#e8af48",
              opacity: 0.15,
              filter: "blur(14px)",
            }}
          />
          {/* Layer 2 — Clip container */}
          <div className="absolute inset-0 rounded-[22px] overflow-hidden">
            {/* Layer 3 — Rotating conic-gradient */}
            <div
              className="absolute animate-[spin-ring_10s_linear_infinite]"
              style={{
                width: "200%",
                height: "200%",
                top: "-50%",
                left: "-50%",
                background: RING,
                willChange: "transform",
              }}
            />
          </div>
          {/* Layer 4 — Inner plate */}
          <div
            className="absolute rounded-[19px]"
            style={{
              inset: 3,
              background: plate,
              transition: "background 0.5s ease",
            }}
          />
        </div>

        {/* ── Nav buttons ── */}
        {NAV.map((item, i) => (
          <div key={item.id} className="flex items-center">
            <button
              onClick={() => setActiveIdx(i)}
              aria-label={item.label}
              className="relative flex items-center justify-center border-none bg-transparent cursor-pointer rounded-[20px] p-0 active:scale-95"
              style={{
                width: S,
                height: S,
                color: i === activeIdx ? iconOn : iconOff,
                zIndex: 2,
                transition: "color 0.3s ease, transform 0.15s ease",
              }}
            >
              <item.Icon active={i === activeIdx} />
            </button>
            {i < NAV.length - 1 && <Divider color={divClr} />}
          </div>
        ))}

        <Divider color={divClr} />

        {/* ── Theme toggle ── */}
        <button
          onClick={handleThemeToggle}
          onAnimationEnd={() => setBouncing(false)}
          aria-label={dark ? "Switch to light mode" : "Switch to dark mode"}
          className="relative flex items-center justify-center border-none bg-transparent cursor-pointer rounded-[20px] p-0 active:scale-90"
          style={{
            width: S,
            height: S,
            color: toggleC,
            zIndex: 2,
            animation: bouncing ? "theme-bounce 0.5s cubic-bezier(0.34,1.56,0.64,1)" : "none",
            transition: "color 0.3s ease",
          }}
        >
          <div className="relative" style={{ width: 22, height: 22 }}>
            <div
              className="absolute inset-0 flex items-center justify-center"
              style={{
                opacity: dark ? 0 : 1,
                transform: dark ? "rotate(-90deg) scale(0.5)" : "rotate(0deg) scale(1)",
                transition: "opacity 0.4s ease, transform 0.4s cubic-bezier(0.34,1.2,0.64,1)",
              }}
            >
              <IconSun />
            </div>
            <div
              className="absolute inset-0 flex items-center justify-center"
              style={{
                opacity: dark ? 1 : 0,
                transform: dark ? "rotate(0deg) scale(1)" : "rotate(90deg) scale(0.5)",
                transition: "opacity 0.4s ease, transform 0.4s cubic-bezier(0.34,1.2,0.64,1)",
              }}
            >
              <IconMoon />
            </div>
          </div>
        </button>
      </div>

      <style>{`
        @keyframes spin-ring {
          to { transform: rotate(360deg); }
        }
        @keyframes theme-bounce {
          0%   { transform: scale(1); }
          35%  { transform: scale(1.25); }
          100% { transform: scale(1); }
        }
      `}</style>
    </div>
  )
}
