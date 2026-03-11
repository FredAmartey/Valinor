# Landing Page Design

**Date:** 2026-03-11
**Goal:** Lead-generation landing page driving "Request Demo" conversions.
**Design language:** Subtle callbacks to the floating toolbar — dark aesthetic, glassmorphism panels, gold accents on CTAs. Toolbar used as page navigation.

## Sections

### 1. Hero
- Dark background (`#0c0c0e`), film grain overlay, radial ambient glow
- Left-aligned: headline ("Deploy AI Agents at Enterprise Scale"), subtext (one sentence positioning), "Request Demo" CTA with gold gradient border (static version of the ring technique)
- Right side: stylized glassmorphism card showing agent dashboard mockup (semi-transparent, blurred bg, subtle gold border accent) — static visual, not interactive
- Light mode: inverts to `#e4e4e8` bg, white glass cards, same gold accents

### 2. Problem / Solution ("Why Valinor")
- Slightly lighter dark bg (`#111114`) for visual rhythm
- 3 pain-point cards in horizontal row:
  1. **Isolation** — "Every tenant gets its own sandbox"
  2. **Compliance** — "Audit trails, RBAC, deny-by-default"
  3. **Speed** — "Weeks of infra work → one API call"
- Cards: glassmorphism (backdrop-blur, `border white/8`, inner highlight shadow)
- Gold-tinted Phosphor icons

### 3. Features (zigzag)
- 2-column layout alternating text/visual per row
- 3 features:
  1. **Multi-tenant isolation** — Docker (Teams) / Firecracker (Enterprise)
  2. **RBAC + Audit** — role hierarchy, resource policies, full action trail
  3. **Multi-channel** — Slack, WhatsApp, Telegram webhooks
- Each visual: a simplified glassmorphism UI panel mockup
- Back to `#0c0c0e` bg

### 4. Tiers
- Two side-by-side cards: **Teams** vs **Enterprise**
- Glass cards with subtle border
- Enterprise card has gold gradient badge (ring gradient, static)
- Feature comparison list inside each card
- CTAs: "Get Started" (Teams, outlined) / "Contact Sales" (Enterprise, gold-bordered)

### 5. Footer CTA + Footer
- Full-width dark section, centered:
  - Headline: "Ready to deploy your agent fleet?"
  - "Request Demo" gold-bordered button
- Minimal footer below: links (Docs, GitHub, Contact), copyright

## Navigation
- `FloatingToolbar` component fixed at bottom-center
- Modified nav items: Overview (home), Features, Pricing, Contact
- Gold ring indicator tracks active section via scroll spy
- Theme toggle (dark/light) preserved

## Technical Approach
- New route group `(marketing)` in Next.js app with its own layout (no sidebar)
- Reuses/adapts `FloatingToolbar` with different nav items
- Tailwind CSS + inline styles matching toolbar design patterns
- No new dependencies beyond what's already installed
- Dark mode default, light mode via component state (same as toolbar)

## Color Palette
| Token | Dark | Light |
|-------|------|-------|
| Page bg | `#0c0c0e` | `#e4e4e8` |
| Section alt bg | `#111114` | `#dddde0` |
| Glass card bg | `rgba(28,28,32,0.92)` | `rgba(250,250,250,0.88)` |
| Glass border | `rgba(255,255,255,0.08)` | `rgba(0,0,0,0.06)` |
| Gold accent | `#e8af48` | `#d4982e` |
| Text primary | `rgba(255,255,255,0.95)` | `rgba(0,0,0,0.90)` |
| Text secondary | `rgba(255,255,255,0.55)` | `rgba(0,0,0,0.50)` |
| CTA gold border | Conic gradient from toolbar (static) | Same |
