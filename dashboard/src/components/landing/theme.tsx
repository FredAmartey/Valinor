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
