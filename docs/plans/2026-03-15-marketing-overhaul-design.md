# Marketing Pages Overhaul Design

## Scope

Complete visual overhaul of the landing page (`/landing`) and architecture page (`/architecture`). All existing copy is retained. Every visual element — layout, colors, typography, components, effects, animations — is redesigned from scratch.

## Goals

- Dark, cosmic, royal aesthetic inspired by StarSling.dev and the Tolkien origins of "Heimdall"
- Premium, technical, modern — conveys "serious infrastructure" not "consumer app"
- Sparkling gold accents, nebula backgrounds, silver-white text on pure black
- Responsive across desktop, tablet, and mobile

## Non-goals

- Changing any product copy or messaging
- Adding new product content or features
- Light mode support (dark only)
- Backend changes

## Visual Language

The visual identity draws from Tolkien's Heimdall — an ancient civilization whose technology feels impossibly advanced. Dark, luminous, refined. Elvish craftsmanship rendered as a product page.

### Palette

| Token | Value | Usage |
|-------|-------|-------|
| Background | `#000000` | Page background |
| Text primary | `#FFFFFF` | Headings |
| Text secondary | `#9CA3AF` | Body copy |
| Gold shimmer | `#FFD700` ↔ `#FFC125` ↔ `#F0C030` | Accent gradient, never flat |
| Border | `rgba(255, 215, 0, 0.12)` | Card/section borders, warm gold tint |
| Glass bg | `rgba(1, 1, 2, 0.3)` | Card backgrounds |
| Glass blur | `backdrop-filter: blur(24px)` | Glassmorphism on cards and navbar |

### Typography

| Element | Font | Weight | Size (desktop / tablet / mobile) | Extras |
|---------|------|--------|----------------------------------|--------|
| Headlines | Afacad | 700 | 72px / 56px / 36px | letter-spacing: -0.4px, line-height: 1em |
| Section titles | Afacad | 600 | 46px / 40px / 32px | |
| Card titles | Afacad | 600 | 24px | |
| Body | Geist | 400/500 | 16px / 14px / 12px | line-height: 1.5 |
| Mono | Geist Mono | 400/600 | As needed | |

### Buttons

- Style: White pill (`#FFF` bg, `#000` text), `rounded-full`, no gold on buttons
- Hover: Subtle opacity shift or slight scale
- Pattern: Always include arrow → in CTA text

### Gold Shimmer Effect

Accent elements (icons, decorative borders, highlight text) use an animated CSS gradient that shifts between gold tones. Never flat color — always a `background-image` with subtle movement.

```css
background-image: linear-gradient(135deg, #FFD700, #FFC125, #F0C030, #FFD700);
background-size: 300% 300%;
animation: shimmer 4s ease infinite;
```

### Card Style

- Border radius: 16px–20px
- Border: 1px solid `rgba(255, 215, 0, 0.12)`
- Background: dark glass `rgba(1, 1, 2, 0.3)` with `backdrop-filter: blur(24px)`
- Padding: 32px
- Hover: border brightens, slight lift with box-shadow

## Landing Page Structure (`/landing`)

### Section 1 — Sticky Navbar

- Full-width, `position: sticky`, top: 0
- Background: `#000000e6` with `backdrop-filter: blur(24px)`
- Left: Heimdall wordmark (Afacad, all-caps, tracking-wide)
- Center/right: 3 nav links — Features, Pricing, Architecture (silver-gray, hover to white)
- Far right: White pill CTA ("Get Started →")
- "Architecture" link routes to `/architecture`

### Section 2 — Hero

- Full viewport height, centered text layout
- Background: Deep cosmic nebula — dark indigo-black base with gold-tinged light filaments radiating from center-top. Built with layered CSS radial gradients creating depth and warmth. Gold shimmer threads woven through the nebula effect.
- Main headline: Very large Afacad 700, white, centered
- Subheading: One line silver-gray, key product terms bolded in white
- Value props row: Three horizontal items, each with a small gold line-art icon + white label, spaced evenly
- CTA: White pill button
- Generous spacing between all elements

### Section 3 — Stylized Dashboard Mock

- Large (~1200px wide) idealized dashboard mockup
- Built as a styled React component (not a screenshot) matching the dark/gold theme
- Shows: sidebar nav, stat cards (Protected Agents, Isolated Tenants, Audit Coverage), agent rows with status badges
- Bottom-masked with CSS gradient fade: visible at top, dissolves into black at bottom
- `linear-gradient(#000 79%, transparent 100%)` mask

### Section 4 — Feature Cards (3 columns)

- Three glass cards in a horizontal row, equal width
- Each card: gold line-art icon at top, white Afacad title, silver-gray Geist description
- Content from existing "Why Heimdall" copy:
  - Card 1: Isolation That Holds
  - Card 2: Security That Shows Its Work
  - Card 3: Useful From Day One
- Subtle hover state: border brightens, slight lift with box-shadow

### Section 5 — Tiers (2 cards side-by-side)

- Two glass cards: Teams and Enterprise
- Enterprise card: gold border glow / shimmer accent, subtle differentiation
- Each shows: runtime type, cold start time, isolation level, feature bullet list
- CTA buttons: Teams = outline style, Enterprise = white pill
- Enterprise labeled "Recommended" or similar with gold badge

### Section 6 — Nebula Breather

- Full-bleed cosmic nebula background (distinct from hero — more expansive, deeper, with gold dust and starfield)
- Centered tagline in large white Afacad
- Generous vertical padding (200px+ top and bottom)
- Very slow ken-burns drift animation on the nebula

### Section 7 — Bottom CTA Card

- Large rounded card (20px radius), dark glass background
- Nebula bleeds through subtly
- Centered layout: small gray text → large white headline → white pill CTA button

### Section 8 — Footer

- Black background, full-width, subtle top border (gold-tinted)
- Left column: Heimdall wordmark + one-line brand description in gray
- Right columns: Product links, Company links, Socials (white headers, gray link text)
- Bottom bar: "© 2026 Heimdall. All rights reserved." left, Privacy + Terms right

## Architecture Page Structure (`/architecture`)

Same dark/gold aesthetic. Separate route. Shares navbar and footer with landing page via the marketing layout.

### Sections (in order)

1. **Header** — Page title + subtitle + CTA buttons (white pills)
2. **Architecture Diagram** — Layered visualization (Users → Channels → Control Plane → Policy/Audit → Runtimes → OpenClaw). Restyled with gold accent lines connecting layers, dark glass cards for each layer. Not a static image — built as a React component.
3. **Trust Boundaries** — 3 glass cards: tenant isolation, department/user scope, layered memory. Gold icons.
4. **Security Lifecycle** — 3 stages: before execution (ingress scanning), during execution (tools/policies), before external effects (review/audit). Gold line-art icons, timeline or sequential layout.
5. **Tier Comparison Table** — Teams vs Enterprise in a clean table format, same visual style.
6. **Channels & Integrations** — 3 glass cards: governed channels, scoped credentials, reviewable actions.
7. **Bottom CTA** — Same pattern as landing page.

## Responsive Behavior

| Breakpoint | Behavior |
|------------|----------|
| Desktop (1200px+) | Full layout as described |
| Tablet (810–1199px) | Feature/tier cards stack to single column, hero text 56px, navbar stays sticky |
| Mobile (<810px) | Everything single column, hero text 36px, full-width cards with same padding |

## Animations & Effects

| Element | Effect |
|---------|--------|
| Navbar | Backdrop blur on scroll |
| Hero nebula | Very slow ambient drift / ken-burns |
| Gold accents | Animated gradient shimmer (4s ease infinite) |
| Dashboard mock | Gentle fade-in / slide-up on scroll (intersection observer) |
| Feature cards | Hover: border brightens + slight lift with box-shadow |
| Nebula breather | Slow parallax or ken-burns drift |
| Page transitions | Subtle fade between landing and architecture |

## Shared Layout

The `(marketing)/layout.tsx` wraps both pages and provides:
- Dark-only body styling (no theme toggle)
- Shared navbar component
- Shared footer component
- Font loading (Afacad + Geist + Geist Mono)
- Global dark background enforcement

## Files Affected

### Delete / Replace
- `dashboard/src/components/landing/theme.tsx` (dark/light toggle removed)
- All existing components in `dashboard/src/components/landing/`
- All existing components in `dashboard/src/components/architecture/`

### Modify
- `dashboard/src/app/(marketing)/layout.tsx`
- `dashboard/src/app/(marketing)/landing/page.tsx`
- `dashboard/src/app/(marketing)/architecture/page.tsx`

### Create
- New landing components (navbar, hero, dashboard-mock, feature-cards, tiers, nebula-section, cta-card, footer)
- New architecture components (architecture-page, architecture-diagram, trust-cards, security-lifecycle, tier-table, channel-cards)
- Shared marketing utilities if needed (shimmer animation, glass card primitive)

### Tests
- Update existing tests to match new component structure
- Maintain coverage for key sections rendering
