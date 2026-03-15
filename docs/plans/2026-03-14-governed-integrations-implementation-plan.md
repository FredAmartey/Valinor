# Governed Integrations Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add governed connector write execution so agent-initiated integration writes are evaluated by policy, pause for approval when required, and resume or fail through the existing trust layer.

**Architecture:** Extend connector tool metadata to declare governed write actions, introduce a durable pending connector action record for pause/resume, route governed connector executions through policy evaluation before external execution, and integrate the results into activity, approvals, security, and audit surfaces. Keep V1 scoped to agent-initiated connector writes only; leave connector CRUD and read-only connector approvals untouched.

**Tech Stack:** Go, PostgreSQL/pgx, Next.js dashboard, existing Valinor activity/approvals/policies/proxy/runtime plumbing, Go tests, TypeScript/React query surfaces.

---

### Task 1: Add durable storage for governed connector actions

**Files:**
- Create: `/Users/fred/Documents/Valinor/migrations/000020_governed_connector_actions.up.sql`
- Create: `/Users/fred/Documents/Valinor/migrations/000020_governed_connector_actions.down.sql`
- Create: `/Users/fred/Documents/Valinor/internal/connectors/actions.go`
- Create: `/Users/fred/Documents/Valinor/internal/connectors/actions_test.go`

**Step 1: Write the failing tests**

Add store-level tests covering:
- create pending governed action
- fetch pending action by id and tenant
- mark action approved/denied/executed/failed
- reject cross-tenant lookup

Include assertions for persisted fields:
- tenant_id
- agent_id
- session_id
- correlation_id
- connector_id
- tool_name
- risk_class
- serialized args/payload
- status
- approval_request_id

**Step 2: Run test to verify it fails**

Run: `go test ./internal/connectors -run GovernedAction -v`
Expected: FAIL because the action store/types do not exist.

**Step 3: Write minimal implementation**

Create a new durable record shape for governed connector actions with statuses such as:
- `pending`
- `awaiting_approval`
- `approved`
- `denied`
- `executed`
- `failed`

Add migration with:
- append/update-safe table for governed connector actions
- tenant RLS
- indexes on tenant/status/created_at and correlation_id

Create store helpers in `internal/connectors/actions.go` for create/load/update transitions.

**Step 4: Run test to verify it passes**

Run: `go test ./internal/connectors -run GovernedAction -v`
Expected: PASS

**Step 5: Commit**

```bash
git add migrations/000020_governed_connector_actions.* internal/connectors/actions.go internal/connectors/actions_test.go
git commit -m "feat: add governed connector action store"
```

### Task 2: Extend connector tool metadata for governance

**Files:**
- Modify: `/Users/fred/Documents/Valinor/internal/connectors/connectors.go`
- Modify: `/Users/fred/Documents/Valinor/internal/connectors/store.go`
- Modify: `/Users/fred/Documents/Valinor/internal/connectors/store_test.go`
- Modify: `/Users/fred/Documents/Valinor/internal/connectors/handler_test.go`

**Step 1: Write the failing tests**

Add tests showing connector tools can persist governance metadata:
- `action_type: write`
- `risk_class: external_writes`
- optional target/summary metadata

Add a validation test that governed write tools missing required governance metadata fail validation.

**Step 2: Run test to verify it fails**

Run: `go test ./internal/connectors -run 'ToolMetadata|ConnectorCreate' -v`
Expected: FAIL because governance metadata is not modeled/validated.

**Step 3: Write minimal implementation**

Extend connector tool structs/JSON handling to support:
- `action_type`
- `risk_class`
- optional `target_type`
- optional `target_label_template`
- optional `approval_summary_template`

Validation rules:
- `write` tools require `risk_class`
- unknown `action_type` values are rejected
- existing connectors without governance metadata remain valid for read/default behavior unless marked `write`

**Step 4: Run test to verify it passes**

Run: `go test ./internal/connectors -run 'ToolMetadata|ConnectorCreate' -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/connectors/connectors.go internal/connectors/store.go internal/connectors/store_test.go internal/connectors/handler_test.go
git commit -m "feat: add connector governance metadata"
```

### Task 3: Add policy evaluation for governed connector writes

**Files:**
- Create: `/Users/fred/Documents/Valinor/internal/connectors/governance.go`
- Create: `/Users/fred/Documents/Valinor/internal/connectors/governance_test.go`
- Modify: `/Users/fred/Documents/Valinor/internal/policies/store.go`
- Modify: `/Users/fred/Documents/Valinor/internal/policies/store_test.go`

**Step 1: Write the failing tests**

Cover:
- write tool with tenant default `allow` proceeds
- write tool with tenant default `block` returns blocked decision
- write tool with tenant default `require_approval` returns approval-required decision
- missing required governance metadata on a write tool fails closed
- agent-level override beats tenant default

**Step 2: Run test to verify it fails**

Run: `go test ./internal/connectors ./internal/policies -run 'Govern|Policy' -v`
Expected: FAIL because connector actions are not policy-aware.

**Step 3: Write minimal implementation**

Create a governance evaluator that:
- inspects connector tool metadata
- decides whether the action is governed
- resolves the effective policy from agent override + tenant default + fallback default
- returns `allow`, `block`, or `require_approval`

Missing required governance metadata on a write tool must fail closed with a typed error/decision.

**Step 4: Run test to verify it passes**

Run: `go test ./internal/connectors ./internal/policies -run 'Govern|Policy' -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/connectors/governance.go internal/connectors/governance_test.go internal/policies/store.go internal/policies/store_test.go
git commit -m "feat: evaluate policy for governed connector writes"
```

### Task 4: Pause agent runs on approval-required connector writes

**Files:**
- Modify: `/Users/fred/Documents/Valinor/cmd/valinor-agent/openclaw.go`
- Modify: `/Users/fred/Documents/Valinor/internal/proxy/protocol.go`
- Modify: `/Users/fred/Documents/Valinor/internal/proxy/handler.go`
- Modify: `/Users/fred/Documents/Valinor/internal/proxy/handler_test.go`
- Modify: `/Users/fred/Documents/Valinor/cmd/valinor-agent/openclaw_test.go`
- Modify: `/Users/fred/Documents/Valinor/internal/activity/activity.go`

**Step 1: Write the failing tests**

Add runtime/proxy tests for:
- governed connector write emits policy-allowed execution path
- blocked write emits blocked event and does not execute
- approval-required write emits paused/waiting event and does not execute immediately
- runtime receives a clear “awaiting approval” state instead of pretending success

**Step 2: Run test to verify it fails**

Run: `go test ./cmd/valinor-agent ./internal/proxy -run 'Connector|Approval|RuntimeEvent' -v`
Expected: FAIL because connector writes are not yet governed in the runtime bridge.

**Step 3: Write minimal implementation**

Extend the runtime/proxy protocol with the minimal message(s) needed to:
- submit governed connector action intents
- return allow/block/awaiting-approval responses
- mark run state as waiting when approval is required

Add new activity kinds/statuses only if existing ones are insufficient; prefer reuse where possible.

**Step 4: Run test to verify it passes**

Run: `go test ./cmd/valinor-agent ./internal/proxy -run 'Connector|Approval|RuntimeEvent' -v`
Expected: PASS

**Step 5: Commit**

```bash
git add cmd/valinor-agent/openclaw.go cmd/valinor-agent/openclaw_test.go internal/proxy/protocol.go internal/proxy/handler.go internal/proxy/handler_test.go internal/activity/activity.go
git commit -m "feat: pause runs for governed connector approvals"
```

### Task 5: Create approval requests and persist waiting connector actions

**Files:**
- Modify: `/Users/fred/Documents/Valinor/internal/approvals/approvals.go`
- Modify: `/Users/fred/Documents/Valinor/internal/approvals/approvals_test.go`
- Modify: `/Users/fred/Documents/Valinor/internal/connectors/actions.go`
- Modify: `/Users/fred/Documents/Valinor/internal/connectors/actions_test.go`
- Modify: `/Users/fred/Documents/Valinor/internal/activity/store.go`

**Step 1: Write the failing tests**

Cover:
- approval-required connector write creates approval request with connector-specific metadata
- governed connector action is stored as `awaiting_approval`
- approval record links back to governed action and correlation/session context
- activity event is emitted for approval-required connector action

**Step 2: Run test to verify it fails**

Run: `go test ./internal/approvals ./internal/connectors ./internal/activity -run 'Connector|ApprovalRequired' -v`
Expected: FAIL because connector approvals are not created from runtime actions.

**Step 3: Write minimal implementation**

When connector governance returns `require approval`:
- persist governed connector action
- create approval request with connector/action metadata
- link approval request to governed connector action
- emit connector-specific activity/security events

Reuse existing approvals queue rather than adding new approval objects.

**Step 4: Run test to verify it passes**

Run: `go test ./internal/approvals ./internal/connectors ./internal/activity -run 'Connector|ApprovalRequired' -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/approvals/approvals.go internal/approvals/approvals_test.go internal/connectors/actions.go internal/connectors/actions_test.go internal/activity/store.go
git commit -m "feat: persist approval-required connector actions"
```

### Task 6: Resume or deny connector actions after approval resolution

**Files:**
- Modify: `/Users/fred/Documents/Valinor/internal/approvals/approvals.go`
- Modify: `/Users/fred/Documents/Valinor/internal/approvals/approvals_test.go`
- Modify: `/Users/fred/Documents/Valinor/internal/connectors/actions.go`
- Modify: `/Users/fred/Documents/Valinor/internal/connectors/actions_test.go`
- Modify: `/Users/fred/Documents/Valinor/cmd/valinor-agent/openclaw.go`
- Modify: `/Users/fred/Documents/Valinor/cmd/valinor-agent/openclaw_test.go`

**Step 1: Write the failing tests**

Cover:
- approving a governed connector action resumes execution from the connector boundary
- denying a governed connector action marks it denied and returns a governed failure to the run
- action state transitions are durable and idempotent enough for retries/replays

**Step 2: Run test to verify it fails**

Run: `go test ./internal/approvals ./internal/connectors ./cmd/valinor-agent -run 'Resume|Denied|ConnectorAction' -v`
Expected: FAIL because approval resolution only resumes channel outbox work today.

**Step 3: Write minimal implementation**

Extend approval resolution so connector-backed approvals:
- mark governed action approved/denied
- trigger the narrow re-entry/resume path for approved actions
- emit correct runtime/activity outcomes for approved or denied actions

Keep this scoped to connector action continuation, not arbitrary run replay.

**Step 4: Run test to verify it passes**

Run: `go test ./internal/approvals ./internal/connectors ./cmd/valinor-agent -run 'Resume|Denied|ConnectorAction' -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/approvals/approvals.go internal/approvals/approvals_test.go internal/connectors/actions.go internal/connectors/actions_test.go cmd/valinor-agent/openclaw.go cmd/valinor-agent/openclaw_test.go
git commit -m "feat: resume governed connector actions after approval"
```

### Task 7: Surface governed connector actions in timeline, approvals, and security views

**Files:**
- Modify: `/Users/fred/Documents/Valinor/internal/activity/activity.go`
- Modify: `/Users/fred/Documents/Valinor/internal/activity/posture.go`
- Modify: `/Users/fred/Documents/Valinor/internal/activity/handler.go`
- Modify: `/Users/fred/Documents/Valinor/dashboard/src/lib/types.ts`
- Modify: `/Users/fred/Documents/Valinor/dashboard/src/lib/queries/activity.ts`
- Modify: `/Users/fred/Documents/Valinor/dashboard/src/components/agents/agent-activity-timeline.tsx`
- Modify: `/Users/fred/Documents/Valinor/dashboard/src/components/approvals/approvals-queue.tsx`
- Modify: `/Users/fred/Documents/Valinor/dashboard/src/components/security/security-events-view.tsx`

**Step 1: Write the failing tests**

Add frontend/backend tests for:
- connector governance events appearing in activity results
- approvals queue showing connector/tool context
- security view showing blocked/approval-required connector actions

**Step 2: Run test to verify it fails**

Run: `go test ./internal/activity -run Connector -v`
Run: `npm run test:run -- src/components/agents/agent-activity-timeline.test.tsx src/components/approvals/approvals-queue.test.tsx src/components/security/security-events-view.test.tsx`
Expected: FAIL because connector action details are not surfaced yet.

**Step 3: Write minimal implementation**

Update activity payloads/types/UI to display connector-specific context:
- connector name
- tool/action name
- governed status
- approval resolution state

Keep the UX inside the existing timeline/approvals/security surfaces.

**Step 4: Run test to verify it passes**

Run: `go test ./internal/activity -run Connector -v`
Run: `npm run test:run -- src/components/agents/agent-activity-timeline.test.tsx src/components/approvals/approvals-queue.test.tsx src/components/security/security-events-view.test.tsx`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/activity/activity.go internal/activity/posture.go internal/activity/handler.go dashboard/src/lib/types.ts dashboard/src/lib/queries/activity.ts dashboard/src/components/agents/agent-activity-timeline.tsx dashboard/src/components/approvals/approvals-queue.tsx dashboard/src/components/security/security-events-view.tsx
git commit -m "feat: surface governed connector actions in trust views"
```

### Task 8: Add audit coverage and full verification

**Files:**
- Modify: `/Users/fred/Documents/Valinor/internal/audit/` (relevant files discovered during implementation)
- Modify: `/Users/fred/Documents/Valinor/internal/platform/server/server_test.go`
- Modify: `/Users/fred/Documents/Valinor/docs/product-overview.md`
- Modify: `/Users/fred/Documents/Valinor/docs/architecture.md`

**Step 1: Write the failing tests**

Add coverage for:
- blocked governed connector writes generating audit records where expected
- approved connector writes generating audit records tied to approval/correlation context
- route/permission coverage for any new backend endpoints introduced in this slice

**Step 2: Run test to verify it fails**

Run: `go test ./internal/audit ./internal/platform/server -run 'Connector|Approval|Audit' -v`
Expected: FAIL because governed connector write audit coverage is incomplete.

**Step 3: Write minimal implementation**

Add audit emission for connector governance milestones and update docs to reflect that integrations are now governed external actions, not just registered connectors.

**Step 4: Run full verification**

Run:
- `go test ./...`
- `npx tsc --noEmit`
- `npm run build`

Expected: all pass

**Step 5: Commit**

```bash
git add internal/audit internal/platform/server/server_test.go docs/product-overview.md docs/architecture.md
git commit -m "feat: audit governed connector actions"
```
