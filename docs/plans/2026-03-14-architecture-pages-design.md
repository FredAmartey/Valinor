# Architecture Pages Design

## Summary

Heimdall should have two architecture pages with different jobs:

- a buyer-facing marketing page that explains why the architecture makes AI agents safer to trust
- a technical docs page that explains how the system is structured and where the trust boundaries live

These pages should share the same core vocabulary and high-level diagram, but they should not duplicate each other.

## Goals

- Add a first-class marketing architecture page under the existing marketing site
- Add a technical architecture reference page in docs
- Keep both pages aligned with Heimdall's current security-first positioning
- Make the architecture easy to understand for both buyers and technical evaluators

## Recommended Approach

### 1. Buyer-facing architecture page

Route:
- `dashboard/src/app/(marketing)/architecture/page.tsx`

Purpose:
- explain why Heimdall's architecture is trustworthy
- support sales, fundraising, and product evaluation conversations

Tone:
- visual
- polished
- high-signal
- low-jargon where possible

Content structure:
- hero
- layered system diagram
- trust boundary section
- lifecycle security section
- product tiers section
- channels and integrations section
- CTA linking to docs and product entry points

### 2. Technical architecture docs page

File:
- `docs/architecture.md`

Purpose:
- serve as the canonical reference for how Heimdall is structured
- explain the control plane, runtime, security, and event model clearly

Tone:
- direct
- technical
- explicit
- still readable to non-implementers

Content structure:
- overview
- core components
- runtime model
- isolation model
- security model
- event and ledger model
- channels and integrations
- product tiers
- what Heimdall does not try to own

## Shared Vocabulary

Both pages should use the same core terms:

- control plane
- runtime
- OpenClaw-first
- isolation
- policy
- approvals
- activity ledger
- audit ledger
- channels
- connectors
- product tiers

## Marketing Page Information Architecture

### Hero

Headline direction:
- Architecture built for broad-access AI agents

Subheadline:
- explain that Heimdall is designed to keep high-access agents observable, isolated, governable, and auditable

### System Diagram

A layered diagram should show:

- users and operators
- channels and external systems
- Heimdall control plane
- policy, approvals, activity, audit, and security layers
- runtime tiers
- agent runtime
- integrations and external tools

### Trust Boundaries

This section should explain:

- tenant isolation
- department isolation
- per-user agent boundaries
- memory scopes
- tenant-scoped credentials

### Lifecycle Security

This section should explain the three-stage model:

- what agents receive
- what agents can do
- what agents send

### Product Tiers

Reuse the current Teams vs Enterprise framing:

- runtime
- cold start
- isolation
- target

### Channels and Integrations

Explain that agents can operate in real workflows without giving up governance or visibility.

### CTA

Primary:
- get started / contact sales

Secondary:
- read the technical architecture

## Docs Page Information Architecture

### Overview

Explain that Heimdall is the security, observability, and governance layer above the agent runtime.

### Core Components

- control plane
- proxy
- runtime
- channels
- connectors
- policy and approvals
- activity and audit ledgers

### Runtime Model

- OpenClaw-first today
- runtime-extensible later
- teams vs enterprise runtime tiers

### Isolation Model

- tenant, department, user
- layered memory
- credential boundaries
- runtime boundaries

### Security Model

- ingress scanning
- execution controls
- egress checks
- hybrid enforcement

### Event and Ledger Model

- `agent_activity_events`
- `audit_events`
- how they differ and why both exist

### Channels and Integrations

- delivery
- scoped credentials
- governed actions
- approvals for sensitive behavior

### What Heimdall Does Not Try to Own

- OpenClaw's own session-centric UX
- low-level runtime/provider configuration UX
- narrow runtime-only workflows better handled inside OpenClaw itself

## Navigation and Linking

### Marketing

- keep the existing landing toolbar unchanged for now
- add links to the architecture page from landing content and footer

### Docs

- link from the marketing architecture page into `docs/architecture.md`
- optionally link back from docs to the marketing page as the high-level overview

## Visual Direction

The marketing architecture page should reuse the current marketing theme system, but feel calmer and more diagram-led than the homepage.

Design rules:

- same palette and background system
- less ornamental density than the landing hero
- stronger hierarchy around diagrams and explanatory blocks
- more trust-product tone than growth-page tone

## Implementation Notes

- The marketing page should reuse existing theme helpers from `dashboard/src/components/landing/theme.tsx`
- The page can introduce one or two new architecture-specific components instead of overloading the landing components
- The docs page should live in repo docs and be written as markdown, not built as a dashboard route
- The system diagram can be implemented as a styled React component for marketing and echoed as a simplified mermaid diagram in docs

## Recommendation

Build both pages now, but keep them intentionally different:

- marketing page = why this architecture is trustworthy
- docs page = how this architecture works

That gives Heimdall a cleaner narrative ladder:

- homepage
- architecture page
- technical architecture docs
