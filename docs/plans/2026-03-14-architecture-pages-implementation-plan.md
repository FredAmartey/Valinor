# Architecture Pages Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a buyer-facing marketing architecture page plus a technical docs architecture reference, and link them cleanly into the current marketing experience.

**Architecture:** The marketing page should be a dedicated Next.js route built on the existing marketing theme system from `dashboard/src/components/landing/theme.tsx`. It should use one or two architecture-specific React components, with a tested, diagram-led layout that explains trust boundaries, lifecycle security, and product tiers. The technical reference should live as markdown in `docs/architecture.md`, using the same vocabulary and a simplified diagram so both surfaces reinforce one another without duplicating every paragraph.

**Tech Stack:** Next.js 16, React 19, TypeScript, Tailwind utility classes, Vitest + Testing Library, markdown docs in `docs/`

---

### Task 1: Add the technical architecture reference in docs

**Files:**
- Create: `docs/architecture.md`
- Reference: `docs/product-overview.md`
- Reference: `docs/plans/2026-03-14-architecture-pages-design.md`

**Step 1: Write the failing existence check**

Run: `test -f /Users/fred/Documents/Heimdall/.worktrees/architecture-pages/docs/architecture.md`
Expected: non-zero exit status because the file does not exist yet

**Step 2: Write the markdown document**

Create `docs/architecture.md` with these exact top-level sections:

```md
# Heimdall Architecture

## Overview
## Core Components
## Runtime Model
## Isolation Model
## Security Model
## Event and Ledger Model
## Channels and Integrations
## Product Tiers
## What Heimdall Does Not Try to Own
```

Inside the document:
- describe Heimdall as the security, observability, and governance layer above the runtime
- keep OpenClaw-first language
- include a mermaid diagram that shows:
  - users and channels
  - Heimdall control plane
  - policy / approvals / activity / audit
  - runtime tier layer
  - OpenClaw runtime
  - integrations and external systems
- explicitly name `agent_activity_events` and `audit_events`
- reuse the current Teams vs Enterprise tier framing from `docs/product-overview.md`

**Step 3: Verify the document shape**

Run:

```bash
rg -n "^## (Overview|Core Components|Runtime Model|Isolation Model|Security Model|Event and Ledger Model|Channels and Integrations|Product Tiers|What Heimdall Does Not Try to Own)$" /Users/fred/Documents/Heimdall/.worktrees/architecture-pages/docs/architecture.md
rg -n "^```mermaid$|agent_activity_events|audit_events" /Users/fred/Documents/Heimdall/.worktrees/architecture-pages/docs/architecture.md
```

Expected:
- all required sections found
- mermaid block found
- both ledger names found

**Step 4: Commit**

```bash
git -C /Users/fred/Documents/Heimdall/.worktrees/architecture-pages add docs/architecture.md
git -C /Users/fred/Documents/Heimdall/.worktrees/architecture-pages commit -m "docs: add technical architecture reference"
```

### Task 2: Create the architecture diagram component with a focused rendering test

**Files:**
- Create: `dashboard/src/components/architecture/architecture-diagram.tsx`
- Create: `dashboard/src/components/architecture/architecture-diagram.test.tsx`
- Reference: `dashboard/src/components/landing/theme.tsx`

**Step 1: Write the failing component test**

Create `dashboard/src/components/architecture/architecture-diagram.test.tsx`:

```tsx
import { describe, it, expect } from "vitest"
import { render, screen } from "@testing-library/react"

import { ThemeProvider } from "@/components/landing/theme"

describe("ArchitectureDiagram", () => {
  it("renders the trust layers and runtime tiers", async () => {
    const { ArchitectureDiagram } = await import("./architecture-diagram")

    render(
      <ThemeProvider>
        <ArchitectureDiagram />
      </ThemeProvider>,
    )

    expect(screen.getByText("Users and operators")).toBeDefined()
    expect(screen.getByText("Heimdall control plane")).toBeDefined()
    expect(screen.getByText("Policy and approvals")).toBeDefined()
    expect(screen.getByText("Activity and audit")).toBeDefined()
    expect(screen.getByText("Teams runtime")).toBeDefined()
    expect(screen.getByText("Enterprise runtime")).toBeDefined()
    expect(screen.getByText("OpenClaw runtime")).toBeDefined()
    expect(screen.getByText("Channels and integrations")).toBeDefined()
  })
})
```

**Step 2: Run the test to verify it fails**

Run:

```bash
cd /Users/fred/Documents/Heimdall/.worktrees/architecture-pages/dashboard
npm run test:run -- src/components/architecture/architecture-diagram.test.tsx
```

Expected: FAIL because `architecture-diagram.tsx` does not exist yet

**Step 3: Implement the diagram component**

Create `dashboard/src/components/architecture/architecture-diagram.tsx` as a `"use client"` component that:
- uses `useTheme()` and `palette()` from `@/components/landing/theme`
- renders a layered grid / stacked-card diagram
- labels these layers exactly:
  - `Users and operators`
  - `Channels and integrations`
  - `Heimdall control plane`
  - `Policy and approvals`
  - `Activity and audit`
  - `Teams runtime`
  - `Enterprise runtime`
  - `OpenClaw runtime`
- keeps the current gold + glass visual language, but calmer than the landing hero

**Step 4: Run the test again**

Run:

```bash
cd /Users/fred/Documents/Heimdall/.worktrees/architecture-pages/dashboard
npm run test:run -- src/components/architecture/architecture-diagram.test.tsx
```

Expected: PASS

**Step 5: Commit**

```bash
git -C /Users/fred/Documents/Heimdall/.worktrees/architecture-pages add \
  dashboard/src/components/architecture/architecture-diagram.tsx \
  dashboard/src/components/architecture/architecture-diagram.test.tsx
git -C /Users/fred/Documents/Heimdall/.worktrees/architecture-pages commit -m "feat(marketing): add architecture diagram component"
```

### Task 3: Build the buyer-facing architecture page route

**Files:**
- Create: `dashboard/src/components/architecture/architecture-page.tsx`
- Create: `dashboard/src/components/architecture/architecture-page.test.tsx`
- Create: `dashboard/src/app/(marketing)/architecture/page.tsx`
- Reference: `dashboard/src/app/(marketing)/landing/page.tsx`
- Reference: `dashboard/src/app/(marketing)/layout.tsx`

**Step 1: Write the failing page test**

Create `dashboard/src/components/architecture/architecture-page.test.tsx`:

```tsx
import { describe, it, expect } from "vitest"
import { render, screen } from "@testing-library/react"

import { ThemeProvider } from "@/components/landing/theme"

describe("ArchitecturePage", () => {
  it("renders the key architecture sections", async () => {
    const { ArchitecturePage } = await import("./architecture-page")

    render(
      <ThemeProvider>
        <ArchitecturePage />
      </ThemeProvider>,
    )

    expect(screen.getByText("Architecture built for broad-access AI agents")).toBeDefined()
    expect(screen.getByText("Trust boundaries")).toBeDefined()
    expect(screen.getByText("Lifecycle security")).toBeDefined()
    expect(screen.getByText("Product tiers")).toBeDefined()
    expect(screen.getByText("Channels and integrations")).toBeDefined()
    expect(screen.getByRole("link", { name: /read the technical architecture/i })).toBeDefined()
  })
})
```

**Step 2: Run the test to verify it fails**

Run:

```bash
cd /Users/fred/Documents/Heimdall/.worktrees/architecture-pages/dashboard
npm run test:run -- src/components/architecture/architecture-page.test.tsx
```

Expected: FAIL because `architecture-page.tsx` does not exist yet

**Step 3: Implement the page component**

Create `dashboard/src/components/architecture/architecture-page.tsx` as a `"use client"` component that:
- uses the existing theme system from `@/components/landing/theme`
- renders:
  - hero
  - diagram section using `ArchitectureDiagram`
  - `Trust boundaries`
  - `Lifecycle security`
  - `Product tiers`
  - `Channels and integrations`
  - CTA section
- uses `Product tiers` content aligned with `docs/product-overview.md`
- links the secondary CTA to the technical docs URL:

```ts
const TECHNICAL_ARCHITECTURE_URL =
  "https://github.com/FredAmartey/Heimdall/blob/master/docs/architecture.md"
```

- does **not** reuse the floating one-page landing toolbar

**Step 4: Add the route wrapper**

Create `dashboard/src/app/(marketing)/architecture/page.tsx`:

```tsx
import type { Metadata } from "next"

import { ThemeProvider } from "@/components/landing/theme"
import { ArchitecturePage } from "@/components/architecture/architecture-page"

export const metadata: Metadata = {
  title: "Heimdall Architecture — Trust boundaries for broad-access AI agents",
  description:
    "See how Heimdall isolates customers, governs risky actions, and secures AI agents across ingress, execution, and egress.",
}

export default function ArchitectureRoute() {
  return (
    <ThemeProvider>
      <ArchitecturePage />
    </ThemeProvider>
  )
}
```

**Step 5: Run the test again**

Run:

```bash
cd /Users/fred/Documents/Heimdall/.worktrees/architecture-pages/dashboard
npm run test:run -- src/components/architecture/architecture-page.test.tsx
```

Expected: PASS

**Step 6: Commit**

```bash
git -C /Users/fred/Documents/Heimdall/.worktrees/architecture-pages add \
  dashboard/src/components/architecture/architecture-page.tsx \
  dashboard/src/components/architecture/architecture-page.test.tsx \
  'dashboard/src/app/(marketing)/architecture/page.tsx'
git -C /Users/fred/Documents/Heimdall/.worktrees/architecture-pages commit -m "feat(marketing): add architecture page"
```

### Task 4: Link the architecture surfaces into the marketing experience

**Files:**
- Modify: `dashboard/src/components/landing/footer.tsx`
- Create: `dashboard/src/components/landing/footer.test.tsx`
- Optional modify: `dashboard/src/components/landing/hero.tsx`

**Step 1: Write the failing footer test**

Create `dashboard/src/components/landing/footer.test.tsx`:

```tsx
import { describe, it, expect } from "vitest"
import { render, screen } from "@testing-library/react"

import { ThemeProvider } from "./theme"

describe("FooterCta", () => {
  it("links to architecture and docs", async () => {
    const { FooterCta } = await import("./footer")

    render(
      <ThemeProvider>
        <FooterCta />
      </ThemeProvider>,
    )

    expect(screen.getByRole("link", { name: "Architecture" }).getAttribute("href")).toBe("/architecture")
    expect(screen.getByRole("link", { name: "Docs" }).getAttribute("href")).toContain("/docs/architecture.md")
  })
})
```

**Step 2: Run the test to verify it fails**

Run:

```bash
cd /Users/fred/Documents/Heimdall/.worktrees/architecture-pages/dashboard
npm run test:run -- src/components/landing/footer.test.tsx
```

Expected: FAIL because the footer still uses placeholder `href="#"` links

**Step 3: Implement the link updates**

Modify `dashboard/src/components/landing/footer.tsx` to:
- replace placeholder footer links with real URLs
- include `Architecture` linking to `/architecture`
- include `Docs` linking to `https://github.com/FredAmartey/Heimdall/blob/master/docs/architecture.md`
- keep `GitHub` and `Contact`
- preserve the existing visual style

Optional:
- add a subtle secondary link in the CTA band such as `Read the architecture`
- only do this if it improves the layout without overcrowding it

**Step 4: Run the footer test again**

Run:

```bash
cd /Users/fred/Documents/Heimdall/.worktrees/architecture-pages/dashboard
npm run test:run -- src/components/landing/footer.test.tsx
```

Expected: PASS

**Step 5: Commit**

```bash
git -C /Users/fred/Documents/Heimdall/.worktrees/architecture-pages add \
  dashboard/src/components/landing/footer.tsx \
  dashboard/src/components/landing/footer.test.tsx
git -C /Users/fred/Documents/Heimdall/.worktrees/architecture-pages commit -m "feat(marketing): link architecture and docs from footer"
```

### Task 5: Verify the full architecture-pages slice end to end

**Files:**
- Verify all touched files from Tasks 1-4

**Step 1: Run focused frontend tests**

Run:

```bash
cd /Users/fred/Documents/Heimdall/.worktrees/architecture-pages/dashboard
npm run test:run -- \
  src/components/architecture/architecture-diagram.test.tsx \
  src/components/architecture/architecture-page.test.tsx \
  src/components/landing/footer.test.tsx
```

Expected: all targeted tests PASS

**Step 2: Run dashboard typecheck**

Run:

```bash
cd /Users/fred/Documents/Heimdall/.worktrees/architecture-pages/dashboard
npx tsc --noEmit
```

Expected: PASS

**Step 3: Run production build**

Run:

```bash
cd /Users/fred/Documents/Heimdall/.worktrees/architecture-pages/dashboard
npm run build
```

Expected:
- PASS
- `/architecture` appears in the built route list

**Step 4: Run backend baseline to catch collateral regressions**

Run:

```bash
cd /Users/fred/Documents/Heimdall/.worktrees/architecture-pages
go test ./...
```

Expected: PASS

**Step 5: Commit**

```bash
git -C /Users/fred/Documents/Heimdall/.worktrees/architecture-pages status --short
```

Expected:
- clean working tree
- all intended commits already created from prior tasks

### Task 6: Final docs and delivery notes

**Files:**
- Modify if needed: `docs/product-overview.md`
- Verify: `docs/architecture.md`

**Step 1: Compare terminology across docs**

Run:

```bash
rg -n "control plane|OpenClaw-first|agent_activity_events|audit_events|Product Tiers|Lifecycle security" \
  /Users/fred/Documents/Heimdall/.worktrees/architecture-pages/docs/architecture.md \
  /Users/fred/Documents/Heimdall/.worktrees/architecture-pages/docs/product-overview.md
```

Expected:
- consistent terminology across both docs
- no stale `control plane` lead language in product-overview positioning sections

**Step 2: Make only the minimum follow-up doc edits**

If the wording diverges:
- update the docs to match the final architecture page terminology
- do **not** widen scope into a docs rewrite

**Step 3: Commit**

```bash
git -C /Users/fred/Documents/Heimdall/.worktrees/architecture-pages add docs/architecture.md docs/product-overview.md
git -C /Users/fred/Documents/Heimdall/.worktrees/architecture-pages commit -m "docs: align architecture terminology"
```

