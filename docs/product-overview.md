# Heimdall Product Overview

## What Is Heimdall?

Heimdall is a security-first platform for AI agents.

More specifically, Heimdall gives teams, businesses, platform builders, and enterprises the visibility, isolation, governance, and auditability needed to use broad-access AI agents securely and with confidence.

These are not toy chatbots. They are agents that can:
- read real data
- call real tools
- message real users
- take real actions across connected systems

Heimdall exists to make those agents safe to trust.

## Positioning

Heimdall provides security, observability, and governance for broad-access AI agents.

Public language:
- Trust AI agents with real access
- Built to make agents like OpenClaw safe for real teams and enterprises

Internal product model:
- trust
- visibility
- control

OpenClaw is the flagship runtime today, but Heimdall should be understood as the enterprise security, observability, and governance layer above the runtime, not as "OpenClaw hosting".

## The Core Problem

Once an agent has meaningful access, the main buyer question stops being "can it run?" and becomes:

**Can we trust it?**

Without Heimdall, organizations have to solve:

| Problem | Without Heimdall | With Heimdall |
| --- | --- | --- |
| Isolation | Shared runtime and weak boundaries create cross-customer and cross-team risk | Tenant, department, and user boundaries with isolated runtimes and scoped memory |
| Visibility | Agents behave like black boxes | Activity timelines, traces, and runtime/security events |
| Governance | Permissions are ad hoc and hard to reason about | RBAC, scoped roles, tenant controls, policy defaults, and approval workflows |
| Security | Prompt injection, tool abuse, secret leakage, and risky outbound behavior are hard to contain | Ingress scanning, execution controls, egress checks, and safer defaults |
| Auditability | No trustworthy system of record | Audit events plus activity history tied to users, agents, and actions |
| Channels and integrations | Slack, WhatsApp, Telegram, and external systems become bespoke reliability and security work | Governed channels, scoped connectors, delivery visibility, and approval-gated risky actions |

## Who Heimdall Is For

### 1. Enterprise internal teams

Security, IT, platform, operations, and departmental teams that want to use AI agents without losing control of data, permissions, or auditability.

### 2. Platform builders

Companies deploying agents to their own customers who need hard customer isolation, tenant-safe channels, and policy/governance around shared infrastructure.

### 3. Regulated industries

Healthcare, finance, legal, and other compliance-heavy environments where agent interactions must be logged, access controlled, and data isolated. Heimdall's role-based access control, row-level security, audit trail and credential encryption address compliance requirements.

### 4. High-trust businesses

Organizations like sports clubs, agencies, recruiting firms, and other high-stakes teams that need AI agents to be useful while still being constrained, observable, and safe.

## Product Pillars

### 1. Visibility

Heimdall makes agent behavior legible.

This includes:
- agent activity timelines
- session and runtime events
- tool and connector activity
- channel delivery visibility
- security event visibility
- debugging and operational context

### 2. Isolation

Heimdall gives each customer, department, and user the right trust boundary.

This includes:
- tenant isolation
- department isolation
- per-user agent boundaries
- layered memory scopes
- tenant-scoped credentials
- isolated execution environments

### 3. Governance

Heimdall lets organizations decide who can see, configure, approve, and operate what.

This includes:
- RBAC
- scoped permissions
- policy defaults and overrides
- impersonation with audit
- approval workflows for risky actions
- administrative control over tenants, departments, and users

### 4. Auditability

Heimdall gives teams and enterprises a reliable record of what happened.

This includes:
- audit trails for security and administrative actions
- activity history for agent behavior
- correlation across users, agents, channels, connectors, and approvals
- exportable records for review, investigation, and compliance

## Product Offerings

### Isolation and Memory

Heimdall supports:
- tenant isolation between customers
- department isolation inside a tenant
- per-user agents
- layered personal, department, tenant, and shared memory
- controlled shared knowledge

This is the basis for "Chelsea cannot see Everton" style guarantees.

### Security and Governance

Heimdall secures AI agents across the full action lifecycle.

Messages are scanned before they reach the agent, risky behavior is governed during execution, and outbound actions can be reviewed, blocked, or audited before they reach users or external systems.

Security and governance capabilities include:
- prompt injection defense
- tool allow-lists and runtime policy
- network and integration restrictions
- secret protection and outbound scanning
- approval workflows for sensitive actions
- tenant and admin policy controls

### Observability and Audit

Heimdall provides the operator layer for understanding agent behavior.

This includes:
- per-agent timelines
- tenant-wide activity feeds
- security center views
- delivery and failure visibility
- audit logs tied back to runtime activity

### Channels and Delivery

Heimdall makes agents usable in real workflows, not just in a sandbox.

This includes:
- Slack, WhatsApp, Telegram, and other channel support
- inbound and outbound delivery handling
- retries and outbox visibility
- identity linking and conversation continuity
- operator visibility into delivery failures and routing

### Integrations and Approvals

Heimdall governs how agents interact with external systems.

This includes:
- MCP and connector registration
- scoped credentials
- integration-level visibility
- explicit governance metadata on connector tools
- policy decisions for connector writes: allow, block, or require approval
- pause-and-resume approval flows for governed external writes
- human review for sensitive external actions
- audit trails tied to governed connector actions

## Example Use Case

Consider two football clubs using the same platform:

- Chelsea is one tenant
- Everton is another tenant
- each club has its own departments such as scouting, front office, and analytics
- each staff member can have their own agent
- each agent can have personal, department, tenant, and approved shared memory

Heimdall is designed so a failure in one customer environment does not expose another customer's data. Those boundaries are enforced across runtime isolation, network posture, tenant-scoped credentials, database controls, memory scope, and policy.

That is the kind of trust boundary serious teams actually need.

## Runtime Model

OpenClaw is the flagship runtime today.

Heimdall should be designed so the trust layer is runtime-agnostic over time, but the product should not lead with broad "bring your own agent" marketing until the runtime contract, policy model, observability model, and support model are genuinely ready.

Current stance:
- OpenClaw-first
- runtime-extensible by design
- broader runtime support later

## Product Tiers

Heimdall currently supports two product tiers:

| | Teams | Enterprise |
| --- | --- | --- |
| **Runtime** | Docker containers | Firecracker MicroVMs (separate kernel per agent) |
| **Cold start** | 2-5 seconds | ~125 milliseconds |
| **Isolation** | Container-level | Hardware-virtualized |
| **Target** | Dev teams, small orgs | Regulated industries, high-trust environments |

Both tiers share the same governance, visibility, audit, channel, and connector model.

## Security Model

Heimdall uses defense in depth.

Key layers:
1. tenant and runtime isolation
2. RBAC and policy evaluation
3. in-guest tool and execution restrictions
4. prompt-injection and risky-input detection
5. outbound scanning and risky-action controls
6. tenant-scoped credentials and secret handling
7. audit plus activity history for investigation

## Core Data and Product Model

Key entities include:
- tenants
- departments
- users
- roles and policy bindings
- agent instances
- agent activity events
- approval requests
- audit events
- channel links, conversations, and outbox rows
- connectors and connector tools

At a high level:
- `audit_events` are the compliance ledger
- `agent_activity_events` are the operator truth layer

## Dashboard Experience

The dashboard is where admins and operators:
- inspect agents
- manage users, departments, and roles
- monitor channels and connectors
- review activity and security events
- audit sensitive actions
- approve or deny risky operations

The dashboard should reflect the product story:
not just configuration, but visibility, isolation, governance, and trust.

## What Heimdall Is Not

Heimdall is not primarily:
- generic AI agent hosting
- a simple deployment layer
- just an integration layer
- just a semantic firewall
- just an "AI employee" product

It should absorb the best capabilities from those categories without collapsing into any one of them.

## Why Heimdall Wins

Heimdall's moat is the enterprise trust layer around agent behavior:
- visibility into what agents are doing
- isolation between customers, teams, and users
- governance over who can configure and approve what
- auditability strong enough for serious organizations
- channels and integrations that remain governable instead of chaotic

The runtime matters.
The agent matters.
But the durable product value is whether organizations can safely rely on those agents in real environments.
