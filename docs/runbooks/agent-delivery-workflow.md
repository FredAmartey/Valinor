# Agent Delivery Workflow

## Purpose
This runbook defines the execution workflow we use to move fast without losing product direction, security, or quality.

Use this in two cases:
- Starting a new project.
- Joining an existing project mid-stream.

It is agent-agnostic and focuses on delivery behavior, not a specific coding tool.

## Non-Negotiables
- Work from end-state product outcomes, not random task lists.
- Ship in thin vertical slices with explicit acceptance criteria.
- Verify before claiming success.
- Do not merge without explicit owner approval.
- After checks are green, run manual external review (for example `@claude`) and triage findings.

## Skills Pack Source
Install the full superpowers skills pack once:
- Install guide: `https://raw.githubusercontent.com/obra/superpowers/refs/heads/main/.codex/INSTALL.md`
- Repository: `https://github.com/obra/superpowers`

## Core Process Skills We Use (Exact Names)
These are the exact skills that define this workflow process:
1. Start and skill resolution: `using-superpowers`
2. Scope/design: `brainstorming`
3. Plan writing: `writing-plans`
4. Branch isolation: `using-git-worktrees`
5. Feature/bug implementation: `test-driven-development`
6. Failure analysis: `systematic-debugging`
7. Pre-completion evidence gate: `verification-before-completion`
8. Request review before merge: `requesting-code-review`
9. Triage external findings: `receiving-code-review`
10. Final branch wrap-up: `finishing-a-development-branch`

Optional scale skills used as needed:
- `dispatching-parallel-agents`
- `subagent-driven-development`

## Additional Skills Policy
Agents are not limited to the core process skills above.
- They may use any other installed superpowers skill when it improves quality, speed, or clarity.
- Core process skills remain mandatory for this workflow.
- If additional skills materially change approach, call them out in the PR summary.

## Operating Loop
1. Align on end-state.
2. Pick the highest-leverage slice.
3. Implement in isolated branch/worktree.
4. Run local verification.
5. Open PR with clear summary and evidence.
6. Wait for CI/security checks.
7. Trigger manual external review (for example `@claude`).
8. Address or challenge findings with technical reasoning.
9. Re-verify.
10. Ask owner for merge decision.

## Phase 0: Project Intake
For a new or inherited project, produce this baseline first:
- Target user journey(s).
- Security and isolation invariants.
- Architecture constraints and banned shortcuts.
- Definition of done for current phase.

Required output:
- A short written artifact in `docs/plans/` describing:
  - Goal
  - Scope
  - Acceptance criteria
  - Risks and rollback

## Phase 1: Slice Planning
Each slice must:
- Deliver visible product value or unblock a hard dependency.
- Be small enough for 1 focused PR when possible.
- Have testable acceptance criteria.

For every slice, define:
- In scope
- Out of scope
- Files/components expected to change
- Verification commands
- Rollback plan

## Phase 2: Execution Discipline
- Use isolated git worktree/branch for the slice.
- Prefer test-first for behavior changes.
- Keep changes minimal and deliberate.
- Avoid opportunistic refactors unless required to satisfy slice acceptance criteria.

## Phase 3: Verification Discipline
Before PR:
- Run targeted tests for changed behavior.
- Run broader relevant suites.
- Capture exact commands and outcomes for PR notes.

Never claim "fixed" or "done" without command evidence.

## Phase 4: PR Discipline
PR description must include:
- What changed
- Why it changed
- Verification commands and outcomes
- Risks/follow-ups

Comment style:
- Write as a human owner would write (plain, direct, non-robotic).
- Avoid noisy status comments unless needed.

## Phase 5: Review Gate
After checks are green:
- Trigger manual review on the PR (command depends on your reviewer bot/tool).
- If findings appear:
  - Address when correct.
  - Challenge with technical reasoning when incorrect or out-of-scope.
- Re-run verification and checks.

Important:
- Manual review trigger is intentional.
- Owner decides merge after findings are resolved or intentionally deferred.

## Phase 6: Merge Gate
Merge only when all are true:
- CI/security checks pass.
- Manual review findings triaged.
- Acceptance criteria satisfied.
- Owner gives explicit go-ahead.

After merge:
- Record product impact in progress tracking.
- Start next highest-value slice.

## Progress Tracking
Maintain a simple, always-current tracker:
- `Now`: active slice and blocker (if any)
- `Next`: next 1-3 slices by product impact
- `Risks`: open technical/security risks
- `Decisions`: key tradeoffs and rationale

Focus progress language on capability delivered, not just commits merged.

## Default Commands Checklist
Adapt per project, but this is the baseline:
- `go test ./...`
- targeted package tests for changed behavior
- repo lint command
- repo security checks (SAST/secrets/vuln)

## Decision Rules
- Prefer end-state alignment over local optimization.
- Prefer correctness and safety over speed when tradeoff is real.
- Prefer explicit follow-up items over hidden technical debt.
- If unsure, escalate quickly with concrete options and recommendation.

## Portable Setup for Another Repo
Copy this operating pack:
- `docs/runbooks/agent-delivery-workflow.md` (this file)
- CI workflow
- Security workflow
- Manual review workflow
- PR template with acceptance criteria + verification

Then run one test slice through full loop before scaling.

## Quick Start Script (Human)
When entering a project, start with:
1. "Here is the end-state I am optimizing for."
2. "Here is the next thin slice and acceptance criteria."
3. "I will implement in an isolated branch/worktree."
4. "I will provide verification evidence before PR."
5. "After checks pass, I will trigger manual review, triage findings, then ask for merge."
