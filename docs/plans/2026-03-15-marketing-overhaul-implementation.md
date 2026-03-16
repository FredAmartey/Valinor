# Marketing Pages Overhaul Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Complete visual overhaul of the landing page and architecture page — dark cosmic aesthetic with sparkling gold accents, Afacad + Geist typography, nebula backgrounds, white pill buttons. All existing copy is preserved.

**Architecture:** Replace the existing theme system (dark/light toggle, palette function) with a dark-only design token file. Rebuild every landing and architecture component from scratch against the new tokens. Shared marketing layout provides fonts, navbar, and footer. Each section is its own component file.

**Tech Stack:** Next.js 16 (App Router), React 19, Tailwind CSS v4, Afacad + Geist fonts via next/font/google, Vitest + RTL for tests, motion library for scroll animations.

---

### Task 1: Install Afacad font and update marketing layout

**Files:**
- Modify: `dashboard/src/app/(marketing)/layout.tsx`
- Modify: `dashboard/src/app/layout.tsx`

**Step 1: Update the root layout to add Afacad font**

The root layout already loads Geist and Geist_Mono. Add Afacad:

```tsx
import { Geist, Geist_Mono } from "next/font/google"
import { Afacad } from "next/font/google"

const afacad = Afacad({
  subsets: ["latin"],
  weight: ["600", "700"],
  variable: "--font-afacad",
})

// In the html tag, add the variable:
<html lang="en" className={`${geistSans.variable} ${geistMono.variable} ${afacad.variable}`}>
```

**Step 2: Update the marketing layout to enforce dark background and provide shared structure**

Replace `dashboard/src/app/(marketing)/layout.tsx` with a layout that:
- Sets `bg-black text-white` on a wrapper div
- Provides metadata
- Does NOT render navbar/footer here (each page handles its own since landing is a single scroll and architecture is a separate page — but both will import the shared Navbar and Footer components)

```tsx
import type { Metadata } from "next"

export const metadata: Metadata = {
  title: "Heimdall — Security, observability, and governance for AI agents",
  description:
    "Trust AI agents with real access using visibility, isolation, governance, and auditability built for teams and enterprises.",
}

export default function MarketingLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <div className="min-h-dvh bg-black text-white" style={{ fontFamily: "var(--font-geist-sans)" }}>
      {children}
    </div>
  )
}
```

**Step 3: Verify the app builds**

Run:
```bash
cd dashboard && npx next build 2>&1 | tail -20
```

Expected: Build succeeds (pages may have import errors from old components — that's fine, we're replacing them).

**Step 4: Commit**

```bash
git add dashboard/src/app/layout.tsx dashboard/src/app/\(marketing\)/layout.tsx
git commit -m "feat(marketing): add Afacad font and dark-only marketing layout"
```

---

### Task 2: Create the new design tokens and shared primitives

**Files:**
- Create: `dashboard/src/components/marketing/tokens.ts`
- Create: `dashboard/src/components/marketing/glass-card.tsx`

**Step 1: Create design tokens**

Create `dashboard/src/components/marketing/tokens.ts` with all shared design values:

```ts
/** Dark-only design tokens for marketing pages */

export const colors = {
  bg: "#000000",
  bgAlt: "#0a0a0a",
  text: "#FFFFFF",
  textSecondary: "#9CA3AF",
  textMuted: "#6B7280",
  gold: "#FFD700",
  goldAlt: "#FFC125",
  goldWarm: "#F0C030",
  border: "rgba(255, 215, 0, 0.12)",
  borderSubtle: "rgba(255, 255, 255, 0.06)",
  glassBg: "rgba(1, 1, 2, 0.3)",
  glassBgSolid: "rgba(10, 10, 12, 0.85)",
  greenDot: "#34d399",
} as const

export const GOLD_SHIMMER = `linear-gradient(135deg, #FFD700, #FFC125, #F0C030, #FFD700)`
export const GOLD_SHIMMER_ANIMATED = `linear-gradient(135deg, #FFD700 0%, #FFC125 25%, #F0C030 50%, #FFD700 75%, #FFC125 100%)`

export const NEBULA_HERO = `
  radial-gradient(ellipse 800px 600px at 50% 20%, rgba(255, 215, 0, 0.08) 0%, transparent 60%),
  radial-gradient(ellipse 600px 400px at 30% 40%, rgba(255, 193, 37, 0.04) 0%, transparent 50%),
  radial-gradient(ellipse 500px 300px at 70% 30%, rgba(240, 192, 48, 0.03) 0%, transparent 50%),
  #000000
`

export const NEBULA_BREATHER = `
  radial-gradient(ellipse 1000px 500px at 50% 50%, rgba(255, 215, 0, 0.06) 0%, transparent 60%),
  radial-gradient(ellipse 400px 400px at 30% 60%, rgba(255, 193, 37, 0.04) 0%, transparent 50%),
  radial-gradient(ellipse 300px 300px at 80% 40%, rgba(240, 192, 48, 0.03) 0%, transparent 50%),
  #000000
`

export const GRAIN_URL = `url("data:image/svg+xml,%3Csvg viewBox='0 0 256 256' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='g'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.8' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23g)'/%3E%3C/svg%3E")`
```

**Step 2: Create shared GlassCard component**

Create `dashboard/src/components/marketing/glass-card.tsx`:

```tsx
import { colors } from "./tokens"

export function GlassCard({
  children,
  className = "",
  hover = false,
}: {
  children: React.ReactNode
  className?: string
  hover?: boolean
}) {
  return (
    <div
      className={`rounded-[20px] border p-8 backdrop-blur-xl ${
        hover
          ? "transition-all duration-300 hover:border-[rgba(255,215,0,0.25)] hover:shadow-[0_8px_32px_rgba(255,215,0,0.06)] hover:-translate-y-0.5"
          : ""
      } ${className}`}
      style={{
        background: colors.glassBg,
        borderColor: colors.border,
      }}
    >
      {children}
    </div>
  )
}
```

**Step 3: Commit**

```bash
git add dashboard/src/components/marketing/
git commit -m "feat(marketing): add dark-only design tokens and glass card primitive"
```

---

### Task 3: Build the Navbar component

**Files:**
- Create: `dashboard/src/components/marketing/navbar.tsx`
- Test: `dashboard/src/components/marketing/navbar.test.tsx`

**Step 1: Write the failing test**

```tsx
import { describe, it, expect } from "vitest"
import { render, screen } from "@testing-library/react"

describe("Navbar", () => {
  it("renders nav links and CTA", async () => {
    const { Navbar } = await import("./navbar")
    render(<Navbar />)

    expect(screen.getByText("VALINOR")).toBeInTheDocument()
    expect(screen.getByRole("link", { name: /features/i })).toBeInTheDocument()
    expect(screen.getByRole("link", { name: /pricing/i })).toBeInTheDocument()
    expect(screen.getByRole("link", { name: /architecture/i })).toBeInTheDocument()
    expect(screen.getByRole("link", { name: /get started/i })).toBeInTheDocument()
  })
})
```

**Step 2: Run test to verify it fails**

Run:
```bash
cd dashboard && npx vitest run src/components/marketing/navbar.test.tsx
```

Expected: FAIL — module not found.

**Step 3: Implement the Navbar**

Create `dashboard/src/components/marketing/navbar.tsx`:

- `position: sticky`, `top: 0`, `z-index: 50`
- Background: `#000000e6` with `backdrop-filter: blur(24px)`
- Left: "VALINOR" wordmark — `font-family: var(--font-afacad)`, all-caps, tracking-wide, font-weight 700
- Center/right: Three links — "Features" (`#features`), "Pricing" (`#tiers`), "Architecture" (`/architecture`). Color: `colors.textSecondary`, hover: white
- Far right: White pill link → "Get Started →" — white bg, black text, `rounded-full`, `px-5 py-2`
- Max content width: 1200px, centered
- The "Features" and "Pricing" links use `href="#features"` / `href="#tiers"` (anchor scroll on landing page)
- The "Architecture" link uses `href="/architecture"` (separate page)

**Step 4: Run test to verify it passes**

Run:
```bash
cd dashboard && npx vitest run src/components/marketing/navbar.test.tsx
```

Expected: PASS.

**Step 5: Commit**

```bash
git add dashboard/src/components/marketing/navbar.tsx dashboard/src/components/marketing/navbar.test.tsx
git commit -m "feat(marketing): add sticky navbar with nav links and CTA"
```

---

### Task 4: Build the Hero section

**Files:**
- Create: `dashboard/src/components/marketing/hero.tsx`
- Test: `dashboard/src/components/marketing/hero.test.tsx`

**Step 1: Write the failing test**

```tsx
import { describe, it, expect } from "vitest"
import { render, screen } from "@testing-library/react"

describe("Hero", () => {
  it("renders headline, subheading, value props, and CTA", async () => {
    const { Hero } = await import("./hero")
    render(<Hero />)

    expect(screen.getByText("Trust AI agents with real access")).toBeInTheDocument()
    expect(screen.getByText(/visibility, isolation/)).toBeInTheDocument()
    expect(screen.getByRole("link", { name: /get started/i })).toBeInTheDocument()
  })
})
```

**Step 2: Run test to verify it fails**

Run:
```bash
cd dashboard && npx vitest run src/components/marketing/hero.test.tsx
```

Expected: FAIL.

**Step 3: Implement the Hero**

Create `dashboard/src/components/marketing/hero.tsx`:

- Full viewport height section, centered text
- Background: `NEBULA_HERO` from tokens — layered radial gradients creating gold-tinged cosmic glow
- Film grain overlay at 0.25 opacity, mix-blend-mode: overlay
- Eyebrow: small gold text "Security, observability, and governance for broad-access AI agents"
- Main headline: "Trust AI agents with real access" — `font-family: var(--font-afacad)`, weight 700, 72px desktop / 56px md / 36px base, white, `letter-spacing: -0.4px`, `line-height: 1em`
- Subheading: one line silver-gray — current hero paragraph copy. Key terms like "visibility", "isolation", "governance", "auditability" bolded in white
- Value props row: three horizontal items — gold SVG line-art icon + white label each:
  - Shield icon + "Enterprise Trust"
  - Eye icon + "Full Visibility"
  - Lock icon + "Defense in Depth"
- CTA: White pill link → "Get Started →" — `rounded-full`, white bg, black text, `px-7 py-3`
- Below CTA: small muted text "Built to make agents like OpenClaw safe for real teams and enterprises."

**Step 4: Run test to verify it passes**

Run:
```bash
cd dashboard && npx vitest run src/components/marketing/hero.test.tsx
```

Expected: PASS.

**Step 5: Commit**

```bash
git add dashboard/src/components/marketing/hero.tsx dashboard/src/components/marketing/hero.test.tsx
git commit -m "feat(marketing): add hero section with nebula background and gold accents"
```

---

### Task 5: Build the Stylized Dashboard Mock

**Files:**
- Create: `dashboard/src/components/marketing/dashboard-mock.tsx`

**Step 1: Implement the Dashboard Mock**

Create `dashboard/src/components/marketing/dashboard-mock.tsx`:

- Large container (~1200px max-width), centered
- Built as a styled React component matching the dark/gold theme (not a screenshot)
- Shows a mock dashboard with:
  - Left sidebar with nav items (Overview, Agents, Users, Departments, Audit, Channels) — dark bg, subtle gold active indicator
  - Top bar with search input mock
  - Three stat cards in a row: "Protected Agents: 24", "Isolated Tenants: 8", "Audit Coverage: 100%" — glass card style, gold accent on values
  - Below: agent rows with name (monospace), status badge (running = green, idle = muted), "observed" tag
- Bottom-masked with CSS gradient: `mask-image: linear-gradient(to bottom, black 70%, transparent 100%)`
- Entire mock uses `colors` from tokens — gold borders, glassBg for cards, textSecondary for labels
- No interactivity — purely visual

**Step 2: Commit**

```bash
git add dashboard/src/components/marketing/dashboard-mock.tsx
git commit -m "feat(marketing): add stylized dashboard mock component"
```

---

### Task 6: Build the Feature Cards section

**Files:**
- Create: `dashboard/src/components/marketing/feature-cards.tsx`
- Test: `dashboard/src/components/marketing/feature-cards.test.tsx`

**Step 1: Write the failing test**

```tsx
import { describe, it, expect } from "vitest"
import { render, screen } from "@testing-library/react"

describe("FeatureCards", () => {
  it("renders three feature cards with titles", async () => {
    const { FeatureCards } = await import("./feature-cards")
    render(<FeatureCards />)

    expect(screen.getByText("Isolation That Holds")).toBeInTheDocument()
    expect(screen.getByText("Security That Shows Its Work")).toBeInTheDocument()
    expect(screen.getByText("Useful From Day One")).toBeInTheDocument()
  })
})
```

**Step 2: Run test to verify it fails**

Run:
```bash
cd dashboard && npx vitest run src/components/marketing/feature-cards.test.tsx
```

Expected: FAIL.

**Step 3: Implement FeatureCards**

Create `dashboard/src/components/marketing/feature-cards.tsx`:

- Section heading: "Why Heimdall" eyebrow in gold + main heading in white (Afacad)
- Three glass cards in a horizontal row (`grid-cols-1 md:grid-cols-3`)
- Each card uses `GlassCard` with `hover={true}`:
  - Gold SVG line-art icon at top (quadrants/shield/lightning — same concepts as current icons)
  - White title in Afacad 600, ~20px
  - Silver-gray description in Geist 400, ~15px
- Copy is identical to current `why-heimdall.tsx` cards array
- Cards have `gap-6`, max-width 1200px container

**Step 4: Run test to verify it passes**

Run:
```bash
cd dashboard && npx vitest run src/components/marketing/feature-cards.test.tsx
```

Expected: PASS.

**Step 5: Commit**

```bash
git add dashboard/src/components/marketing/feature-cards.tsx dashboard/src/components/marketing/feature-cards.test.tsx
git commit -m "feat(marketing): add feature cards section with glass card hover effects"
```

---

### Task 7: Build the Tiers section

**Files:**
- Create: `dashboard/src/components/marketing/tiers.tsx`
- Test: `dashboard/src/components/marketing/tiers.test.tsx`

**Step 1: Write the failing test**

```tsx
import { describe, it, expect } from "vitest"
import { render, screen } from "@testing-library/react"

describe("Tiers", () => {
  it("renders both tier cards", async () => {
    const { Tiers } = await import("./tiers")
    render(<Tiers />)

    expect(screen.getByText("Teams")).toBeInTheDocument()
    expect(screen.getByText("Enterprise")).toBeInTheDocument()
    expect(screen.getByText("Recommended")).toBeInTheDocument()
    expect(screen.getByText("Docker containers")).toBeInTheDocument()
    expect(screen.getByText("Firecracker microVMs")).toBeInTheDocument()
  })
})
```

**Step 2: Run test to verify it fails**

Run:
```bash
cd dashboard && npx vitest run src/components/marketing/tiers.test.tsx
```

Expected: FAIL.

**Step 3: Implement Tiers**

Create `dashboard/src/components/marketing/tiers.tsx`:

- Section header: "Pricing" gold eyebrow + "Choose the trust boundary that fits your team." white heading (Afacad)
- Two cards side-by-side (`grid-cols-1 md:grid-cols-2`)
- Teams card: standard glass card, outline CTA button (transparent bg, white border, white text)
- Enterprise card: gold-tinted border (`rgba(255, 215, 0, 0.25)`), subtle gold glow shadow, "Recommended" gold badge at top. White pill CTA button
- Copy/data: identical to current `tiers.tsx` — same specs array, same features array
- Specs: label (silver-gray) + value (white mono) pairs
- Features: green checkmark SVG + feature text list
- Max-width 1200px container

**Step 4: Run test to verify it passes**

Run:
```bash
cd dashboard && npx vitest run src/components/marketing/tiers.test.tsx
```

Expected: PASS.

**Step 5: Commit**

```bash
git add dashboard/src/components/marketing/tiers.tsx dashboard/src/components/marketing/tiers.test.tsx
git commit -m "feat(marketing): add tiers section with gold enterprise accent"
```

---

### Task 8: Build the Nebula Breather section

**Files:**
- Create: `dashboard/src/components/marketing/nebula-section.tsx`

**Step 1: Implement the Nebula Breather**

Create `dashboard/src/components/marketing/nebula-section.tsx`:

- Full-bleed section with `NEBULA_BREATHER` background from tokens
- Film grain overlay at 0.20 opacity
- Generous vertical padding: `py-48` (200px+ equivalent)
- Centered tagline: large white text in Afacad 700, ~48px desktop
- Tagline copy: "The trust layer for AI agents that touch real systems."
- Subtitle: silver-gray smaller text below
- Very slow ken-burns style animation: CSS `@keyframes drift` that slowly scales and translates the background (scale 1 → 1.05, translateY 0 → -10px over 30s, alternating)

**Step 2: Commit**

```bash
git add dashboard/src/components/marketing/nebula-section.tsx
git commit -m "feat(marketing): add nebula breather section with cosmic background"
```

---

### Task 9: Build the Bottom CTA and Footer

**Files:**
- Create: `dashboard/src/components/marketing/cta-card.tsx`
- Create: `dashboard/src/components/marketing/footer.tsx`
- Test: `dashboard/src/components/marketing/footer.test.tsx`

**Step 1: Write the failing test**

```tsx
import { describe, it, expect } from "vitest"
import { render, screen } from "@testing-library/react"

describe("Footer", () => {
  it("renders links and copyright", async () => {
    const { Footer } = await import("./footer")
    render(<Footer />)

    expect(screen.getByText("VALINOR")).toBeInTheDocument()
    expect(screen.getByRole("link", { name: /architecture/i })).toHaveAttribute("href", "/architecture")
    expect(screen.getByRole("link", { name: /github/i })).toHaveAttribute(
      "href",
      expect.stringContaining("github.com"),
    )
    expect(screen.getByText(/© 2026 Heimdall/)).toBeInTheDocument()
  })
})
```

**Step 2: Run test to verify it fails**

Run:
```bash
cd dashboard && npx vitest run src/components/marketing/footer.test.tsx
```

Expected: FAIL.

**Step 3: Implement CtaCard**

Create `dashboard/src/components/marketing/cta-card.tsx`:

- Large rounded card (20px radius), glass background
- Centered layout:
  - Small gray text: "Ready to trust AI agents with real access?"
  - Large white headline (Afacad 700): "Give your agents the trust layer they need."
  - White pill CTA: "Get Started →"

**Step 4: Implement Footer**

Create `dashboard/src/components/marketing/footer.tsx`:

- Black background, full-width, subtle top border (gold-tinted `rgba(255, 215, 0, 0.08)`)
- Left column: "VALINOR" wordmark (Afacad, uppercase, tracking-wide) + one-line brand description in gray
- Right columns (3): Product (Architecture, Docs), Company (About), Socials (GitHub, LinkedIn)
- Bottom bar: "© 2026 Heimdall. All rights reserved." left, Privacy + Terms links right
- All links: silver-gray, hover to white

**Step 5: Run test to verify it passes**

Run:
```bash
cd dashboard && npx vitest run src/components/marketing/footer.test.tsx
```

Expected: PASS.

**Step 6: Commit**

```bash
git add dashboard/src/components/marketing/cta-card.tsx dashboard/src/components/marketing/footer.tsx dashboard/src/components/marketing/footer.test.tsx
git commit -m "feat(marketing): add bottom CTA card and footer with gold-tinted borders"
```

---

### Task 10: Assemble the new Landing Page

**Files:**
- Modify: `dashboard/src/app/(marketing)/landing/page.tsx`

**Step 1: Replace the landing page**

Replace `dashboard/src/app/(marketing)/landing/page.tsx` with a new version that:

- Marks the page as `"use client"` (for scroll spy on navbar anchors)
- Imports all new components from `@/components/marketing/`
- Renders in order: Navbar → Hero → DashboardMock → FeatureCards → Tiers → NebulaSection → CtaCard → Footer
- Each section gets an `id` attribute for anchor scrolling: `hero`, `features`, `tiers`, `contact`
- Add the shimmer keyframes and drift animation keyframes in a `<style>` tag
- Black background on the wrapper div

**Step 2: Verify the page builds and renders**

Run:
```bash
cd dashboard && npx next build 2>&1 | tail -20
```

Expected: Build succeeds.

**Step 3: Commit**

```bash
git add dashboard/src/app/\(marketing\)/landing/page.tsx
git commit -m "feat(marketing): assemble new landing page with all sections"
```

---

### Task 11: Rebuild the Architecture page

**Files:**
- Create: `dashboard/src/components/marketing/architecture-page.tsx`
- Create: `dashboard/src/components/marketing/architecture-diagram.tsx`
- Modify: `dashboard/src/app/(marketing)/architecture/page.tsx`
- Test: `dashboard/src/components/marketing/architecture-page.test.tsx`
- Test: `dashboard/src/components/marketing/architecture-diagram.test.tsx`

**Step 1: Write failing tests**

Architecture page test:
```tsx
import { describe, it, expect } from "vitest"
import { render, screen } from "@testing-library/react"

describe("ArchitecturePage", () => {
  it("renders key architecture sections", async () => {
    const { ArchitecturePage } = await import("./architecture-page")
    render(<ArchitecturePage />)

    expect(screen.getByText("Architecture built for broad-access AI agents")).toBeInTheDocument()
    expect(screen.getByText("Trust boundaries")).toBeInTheDocument()
    expect(screen.getByText("Lifecycle security")).toBeInTheDocument()
    expect(screen.getByText("Product tiers")).toBeInTheDocument()
    expect(screen.getByRole("link", { name: /read the technical architecture/i })).toBeInTheDocument()
  })
})
```

Architecture diagram test:
```tsx
import { describe, it, expect } from "vitest"
import { render, screen } from "@testing-library/react"

describe("ArchitectureDiagram", () => {
  it("renders trust layers and runtime tiers", async () => {
    const { ArchitectureDiagram } = await import("./architecture-diagram")
    render(<ArchitectureDiagram />)

    expect(screen.getByText("Users and operators")).toBeInTheDocument()
    expect(screen.getByText("Heimdall control plane")).toBeInTheDocument()
    expect(screen.getByText("Teams runtime")).toBeInTheDocument()
    expect(screen.getByText("Enterprise runtime")).toBeInTheDocument()
    expect(screen.getByText("OpenClaw runtime")).toBeInTheDocument()
  })
})
```

**Step 2: Run tests to verify they fail**

Run:
```bash
cd dashboard && npx vitest run src/components/marketing/architecture-page.test.tsx src/components/marketing/architecture-diagram.test.tsx
```

Expected: FAIL.

**Step 3: Implement ArchitectureDiagram**

Create `dashboard/src/components/marketing/architecture-diagram.tsx`:

- Same layered structure as current diagram (Users → Channels → Control Plane → Policy/Audit → Runtimes → OpenClaw)
- Restyled with gold accent lines connecting layers instead of plain dividers
- Each layer is a glass card with gold-tinted border
- Connector lines between layers use gold gradient (`GOLD_SHIMMER`)
- Accent layers (Users, Channels, Control Plane, OpenClaw) get slightly brighter background
- All copy identical to current `architecture-diagram.tsx`

**Step 4: Implement ArchitecturePage**

Create `dashboard/src/components/marketing/architecture-page.tsx`:

- Same sections as current architecture page — all copy preserved
- Uses new tokens and glass card styling
- Imports Navbar and Footer from marketing components
- Same section structure:
  1. Header with CTA buttons (white pills instead of gold button)
  2. ArchitectureDiagram
  3. Trust Boundaries (3 glass cards)
  4. Security Lifecycle (3 glass cards)
  5. Product Tiers table
  6. Channels & Integrations (3 glass cards)
  7. Bottom CTA
- Nebula background on the header area
- Gold eyebrow text on each section heading

**Step 5: Update the architecture route**

Modify `dashboard/src/app/(marketing)/architecture/page.tsx` to import from `@/components/marketing/architecture-page` instead of the old path. Remove the ThemeProvider wrapper (no longer needed — dark only).

**Step 6: Run tests to verify they pass**

Run:
```bash
cd dashboard && npx vitest run src/components/marketing/architecture-page.test.tsx src/components/marketing/architecture-diagram.test.tsx
```

Expected: PASS.

**Step 7: Commit**

```bash
git add dashboard/src/components/marketing/architecture-page.tsx \
  dashboard/src/components/marketing/architecture-diagram.tsx \
  dashboard/src/components/marketing/architecture-page.test.tsx \
  dashboard/src/components/marketing/architecture-diagram.test.tsx \
  dashboard/src/app/\(marketing\)/architecture/page.tsx
git commit -m "feat(marketing): rebuild architecture page with dark cosmic aesthetic"
```

---

### Task 12: Delete old landing and architecture components

**Files:**
- Delete: `dashboard/src/components/landing/theme.tsx`
- Delete: `dashboard/src/components/landing/landing-toolbar.tsx`
- Delete: `dashboard/src/components/landing/hero.tsx`
- Delete: `dashboard/src/components/landing/why-heimdall.tsx`
- Delete: `dashboard/src/components/landing/features.tsx`
- Delete: `dashboard/src/components/landing/tiers.tsx`
- Delete: `dashboard/src/components/landing/footer.tsx`
- Delete: `dashboard/src/components/landing/footer.test.tsx`
- Delete: `dashboard/src/components/architecture/architecture-page.tsx`
- Delete: `dashboard/src/components/architecture/architecture-diagram.tsx`
- Delete: `dashboard/src/components/architecture/architecture-page.test.tsx`
- Delete: `dashboard/src/components/architecture/architecture-diagram.test.tsx`

**Step 1: Verify no other files import from the old paths**

Run:
```bash
cd dashboard && grep -r "components/landing" src/ --include="*.tsx" --include="*.ts" -l
cd dashboard && grep -r "components/architecture" src/ --include="*.tsx" --include="*.ts" -l
```

Expected: Only the old files themselves (no imports from dashboard pages or other components). If any imports remain, update them first.

**Step 2: Delete old files**

```bash
rm dashboard/src/components/landing/theme.tsx \
   dashboard/src/components/landing/landing-toolbar.tsx \
   dashboard/src/components/landing/hero.tsx \
   dashboard/src/components/landing/why-heimdall.tsx \
   dashboard/src/components/landing/features.tsx \
   dashboard/src/components/landing/tiers.tsx \
   dashboard/src/components/landing/footer.tsx \
   dashboard/src/components/landing/footer.test.tsx \
   dashboard/src/components/architecture/architecture-page.tsx \
   dashboard/src/components/architecture/architecture-diagram.tsx \
   dashboard/src/components/architecture/architecture-page.test.tsx \
   dashboard/src/components/architecture/architecture-diagram.test.tsx
```

Remove the now-empty directories if applicable:
```bash
rmdir dashboard/src/components/landing dashboard/src/components/architecture 2>/dev/null || true
```

**Step 3: Commit**

```bash
git add -u dashboard/src/components/landing/ dashboard/src/components/architecture/
git commit -m "chore(marketing): remove old landing and architecture components"
```

---

### Task 13: Update site-links.ts

**Files:**
- Modify: `dashboard/src/lib/site-links.ts`

**Step 1: Read current file and update if needed**

Ensure links are consistent with the new pages. The `CONTACT_SECTION_URL` should point to `/landing#contact` and `TECHNICAL_ARCHITECTURE_URL` should remain pointing to GitHub docs.

**Step 2: Commit if changed**

```bash
git add dashboard/src/lib/site-links.ts
git commit -m "fix(marketing): update site links for new page structure"
```

---

### Task 14: Full test verification

**Files:**
- Verify: `dashboard/`

**Step 1: Run all marketing tests**

Run:
```bash
cd dashboard && npx vitest run src/components/marketing/
```

Expected: All PASS.

**Step 2: Run the full dashboard test suite**

Run:
```bash
cd dashboard && npx vitest run
```

Expected: All PASS. If any old tests reference deleted components, they were already deleted in Task 12.

**Step 3: Build verification**

Run:
```bash
cd dashboard && npx next build 2>&1 | tail -30
```

Expected: Build succeeds with no errors.

**Step 4: Commit any fixes needed**

If any tests or build issues, fix and commit:
```bash
git add -A dashboard/
git commit -m "fix(marketing): resolve test and build issues from overhaul"
```

---

### Task 15: Visual polish pass

**Files:**
- Potentially modify any file in `dashboard/src/components/marketing/`

> **For Claude:** REQUIRED SUB-SKILLS: Invoke `frontend-design`, `design-taste-frontend`, and `polish` skills before starting this task. Review every component visually and apply fixes.

**Step 1: Start the dev server**

Run:
```bash
cd dashboard && npm run dev
```

**Step 2: Review each section visually**

Open `http://localhost:3000/landing` and `http://localhost:3000/architecture` in the browser. Check:

- Typography hierarchy and sizing
- Gold shimmer effect visibility and quality
- Nebula background depth and warmth
- Card hover states (border brighten, slight lift)
- Dashboard mock readability and polish
- Responsive behavior at tablet (810px) and mobile (390px) widths
- Navbar sticky behavior and blur
- Footer layout and spacing
- Overall spacing and breathing room between sections

**Step 3: Apply CSS and markup fixes**

Fix any spacing, alignment, color, animation, or responsive issues found during review.

**Step 4: Commit**

```bash
git add dashboard/src/components/marketing/
git commit -m "fix(marketing): visual polish pass — spacing, colors, responsive fixes"
```
