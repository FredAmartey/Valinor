"use client"

import { useState, useEffect, useCallback } from "react"
import { ThemeProvider, useTheme, palette, GRAIN_URL } from "@/components/landing/theme"
import { LandingToolbar, LANDING_NAV } from "@/components/landing/landing-toolbar"
import { Hero } from "@/components/landing/hero"
import { WhyHeimdall } from "@/components/landing/why-heimdall"
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
    if (el) el.scrollIntoView({ behavior: "smooth" })
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

      {/* Page sections */}
      <Hero />
      <WhyHeimdall />
      <Features />
      <Tiers />
      <FooterCta />

      {/* Toolbar navigation */}
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
