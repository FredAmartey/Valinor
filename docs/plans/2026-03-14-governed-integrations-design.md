# Governed Integrations Design

## Summary
Valinor should extend its trust layer from governed channel delivery to governed connector execution.

The first slice will cover agent-initiated connector write actions during a run. Read-only connector calls remain observable but are not approval-gated in V1. Connector CRUD remains a separate administrative governance problem and is out of scope for this slice.

The core product goal is to make connector writes subject to the same trust model as channel sends:
- explicit metadata defines whether a connector tool is a governed write
- risk-class policy determines allow, block, or approval-required
- approval-required actions pause the run and wait
- approved actions resume from the connector action boundary
- all outcomes emit correlated activity, security, and audit events

## Core approach
The recommended design is inline governed connector execution.

When an agent attempts a connector tool call:
1. Valinor checks explicit governance metadata on the connector tool
2. If the tool is a governed write, Valinor evaluates policy for the declared risk class
3. Valinor then either:
   - allows execution
   - blocks execution
   - creates an approval request and pauses the run
4. After approval, Valinor resumes that connector action without replaying the entire run

This approach keeps governance in the execution path instead of bolting it on afterward.

## System shape
Valinor needs a governed connector action path between the agent runtime and external execution.

For V1:
- only connector tools explicitly marked as write actions enter this path
- read-only tools execute normally but still log activity
- connector execution becomes governable, not just observable

A narrow internal execution object should represent a paused governed connector action. Whether that becomes a first-class table or another durable storage shape, it should carry:
- tenant and agent identity
- session and correlation IDs
- connector ID and tool name
- serialized tool arguments or payload reference
- target label and action summary
- risk class
- status such as pending, blocked, awaiting approval, approved, denied, executed, failed

## Metadata model
Connector tool governance depends on explicit metadata.

Minimum V1 metadata:
- `action_type`: `read` or `write`
- `risk_class`: usually `external_writes` in the first slice

Optional metadata for better operator clarity:
- `target_type`
- `target_label_template`
- `approval_summary_template`

Rules:
- write actions with valid governance metadata use the policy engine
- read actions bypass approval gating in V1
- write actions missing required governance metadata fail closed and emit security/activity events

## Policy model
Connector writes use the same existing risk-class decision model:
- allow
- block
- require approval

V1 recommendation:
- default governed connector writes to `external_writes`
- allow richer connector-specific risk classes later

This keeps connectors aligned with the rest of Valinor instead of creating a separate policy system.

## Pause and resume behavior
When a connector write requires approval:
- the external action must not execute
- an approval request is created
- the run moves into a waiting-for-approval state
- the timeline shows the run paused on that connector action

If approved:
- Valinor resumes the paused connector action from the connector boundary
- the write executes
- the run continues

If denied:
- the connector action is marked denied
- the run receives a governed failure/denial signal
- the run does not continue as if the action succeeded

The first version should resume the action from persisted execution context, not replay the entire run.

## Activity, approvals, and UI
This work should deepen existing trust surfaces rather than create a disconnected subsystem.

### Agent timeline
Connector governance should show up as first-class events:
- connector write requested
- policy evaluated
- blocked, approval required, or allowed
- approval resolved
- connector execution started
- connector execution succeeded or failed

### Approvals queue
Connector approvals should include:
- connector name
- tool/action name
- target label
- risk class
- action summary
- requester and agent context

### Security Center
Security views should reflect:
- blocked governed writes
- missing governance metadata on write tools
- approval-required connector actions
- denied connector actions

### Audit
Audit coverage should include:
- approval creation and resolution
- blocked governed connector writes
- approved connector writes that execute

## Rollout scope
### In scope
- governed connector writes only
- explicit metadata-driven policy evaluation
- pause-and-wait approvals
- action resume or deny after approval resolution
- integrated activity, approvals, security, and audit coverage

### Out of scope
- connector CRUD approvals
- approval gating for read-only connector actions
- heuristic write detection
- full connector payload DLP scanning unless it falls out naturally during implementation
- connector marketplace/productization improvements

## Risks
1. Resume complexity: resuming a paused action safely is the hardest part
2. Metadata quality: governance depends on correct connector tool metadata
3. Runtime/control-plane coordination: policy and approval handshakes must be durable and race-safe

## Recommendation
Implement governed integrations parity as the next product slice.

This closes the biggest trust gap left on top of the current platform: channels are already governed, but connector writes are not. Once this slice lands, Valinor will have a much more credible story for governed external actions across both channels and integrations.
