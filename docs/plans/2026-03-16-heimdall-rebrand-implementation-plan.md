# Heimdall Rebrand Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Rename Valinor to Heimdall everywhere in a single hard cutover across repo identity, Go module/commands, runtime/config surfaces, frontend copy, docs, and operational tooling.

**Architecture:** Execute the rename in four layers: structural identifiers first (`cmd/`, module path, binaries), then runtime/config/container surfaces, then frontend/product copy, then documentation/history. Use targeted tests for the changed surfaces plus a final repo-wide leftover scan; do not block the rebrand on the six pre-existing `dashboard` Vitest failures unless they change or widen.

**Tech Stack:** Go 1.25, Next.js 16, React 19, TypeScript, Vitest, Playwright, Docker, GitHub Actions, shell scripts.

---

## Preconditions

1. Rename the GitHub repository from `valinor` to `heimdall` in the GitHub UI before merging the code changes.
2. In the worktree, update the local remote after the GitHub rename:

```bash
git remote set-url origin https://github.com/FredAmartey/heimdall.git
git remote -v
```

Expected: both fetch and push URLs end in `github.com/FredAmartey/heimdall.git`.

## Baseline Note

- `go test ./... -count=1` passes in `/Users/fred/Documents/Valinor/.worktrees/heimdall-rebrand`.
- `cd dashboard && npm run test:run` already fails before the rebrand in:
  - `dashboard/src/components/channels/channels-view.test.tsx`
  - `dashboard/src/components/connectors/connectors-view.test.tsx`
  - `dashboard/src/components/nav/sidebar.test.tsx`
- Use targeted dashboard tests plus `npx tsc --noEmit` as the regression signal during this rename.

### Task 1: Rename Repository Entry Points and Go Module Identity

**Files:**
- Move: `cmd/valinor` -> `cmd/heimdall`
- Move: `cmd/valinor-agent` -> `cmd/heimdall-agent`
- Modify: `go.mod`
- Modify: `.github/workflows/ci.yml`
- Modify: `.gitignore`
- Modify: `Dockerfile.agent`
- Modify: every Go file returned by `rg -l 'github.com/valinor-ai/valinor|cmd/valinor|cmd/valinor-agent' cmd internal`

**Step 1: Write the failing structural verification**

Run:

```bash
test -d cmd/heimdall && test -d cmd/heimdall-agent && go test ./cmd/heimdall ./cmd/heimdall-agent -count=1
```

Expected: FAIL because the renamed command directories do not exist yet.

**Step 2: Perform the structural rename**

- Use `git mv` for the command directories.
- Change `go.mod` from `github.com/valinor-ai/valinor` to `github.com/FredAmartey/heimdall`.
- Update import paths, command path references, CI invocations, `.gitignore` build output, and `Dockerfile.agent` build paths to use `heimdall`.

**Step 3: Verify the renamed commands compile**

Run:

```bash
go test ./cmd/heimdall ./cmd/heimdall-agent -count=1
```

Expected: PASS.

**Step 4: Verify the full Go tree still builds/tests**

Run:

```bash
go test ./... -count=1
```

Expected: PASS.

**Step 5: Commit**

```bash
git add go.mod .github/workflows/ci.yml .gitignore Dockerfile.agent cmd internal
git commit -m "refactor: rename valinor commands and module path"
```

### Task 2: Rename Auth, Config, and Database Defaults

**Files:**
- Modify: `config.yaml`
- Modify: `internal/platform/config/config.go`
- Modify: `internal/platform/config/config_test.go`
- Modify: `internal/platform/server/server_test.go`
- Modify: `internal/auth/token_test.go`
- Modify: `internal/auth/exchange_test.go`
- Modify: `internal/platform/database/migrate_test.go`
- Modify: `internal/platform/database/postgres_test.go`
- Modify: `internal/platform/database/tenant_test.go`
- Modify: `internal/platform/database/rls_test.go`
- Modify: `scripts/seed_dev_roles.sql`

**Step 1: Update the test expectations first**

- Change test expectations and sample strings from `valinor` to `heimdall` for:
  - JWT issuer values
  - default database URLs
  - database names such as `valinor_test`
  - comments/examples that reference `cmd/valinor/main.go`

**Step 2: Run the targeted tests and confirm they fail against old defaults**

Run:

```bash
go test ./internal/platform/config ./internal/platform/server ./internal/auth ./internal/platform/database -run 'TestLoad|Token|Exchange|Migrate|Postgres|Tenant|RLS' -count=1
```

Expected: FAIL while runtime/config defaults still emit `valinor`.

**Step 3: Update the implementation/defaults**

- Change `config.yaml` defaults to `heimdall`.
- Change config code defaults in `internal/platform/config/config.go`.
- Update any remaining literal issuer/database references in the listed test files and seed SQL comments.

**Step 4: Re-run the targeted verification**

Run:

```bash
go test ./internal/platform/config ./internal/platform/server ./internal/auth ./internal/platform/database -run 'TestLoad|Token|Exchange|Migrate|Postgres|Tenant|RLS' -count=1
```

Expected: PASS.

**Step 5: Commit**

```bash
git add config.yaml internal/platform/config internal/platform/server internal/auth internal/platform/database scripts/seed_dev_roles.sql
git commit -m "chore: rename heimdall auth and database defaults"
```

### Task 3: Rename Runtime, Docker, and Filesystem Surfaces

**Files:**
- Modify: `Dockerfile.agent`
- Modify: `cmd/heimdall-agent/agent.go`
- Modify: `cmd/heimdall-agent/main.go`
- Modify: `cmd/heimdall-agent/openclaw.go`
- Modify: `cmd/heimdall-agent/openclaw_test.go`
- Modify: `internal/orchestrator/docker_driver.go`
- Modify: `internal/orchestrator/docker_driver_test.go`
- Modify: `internal/orchestrator/docker_e2e_test.go`
- Modify: `internal/orchestrator/firecracker_driver.go`
- Modify: `internal/platform/config/config.go`
- Modify: `scripts/firecracker/bootstrap-linux-kvm.sh`
- Modify: `scripts/firecracker/fetch-ci-artifacts.sh`
- Modify: `scripts/firecracker/install-guest-runtime.sh`

**Step 1: Update the runtime/orchestrator assertions first**

- Change expected image names to `heimdall/agent:dev`.
- Change labels, container names, and network names from `valinor.*` / `valinor-*` to `heimdall.*` / `heimdall-*`.
- Change filesystem/runtime paths from `/var/lib/valinor`, `/opt/valinor`, and `/etc/valinor` to the Heimdall equivalents.
- Change log prefixes from `valinor-agent` to `heimdall-agent`.

**Step 2: Run the targeted backend tests and confirm they fail before implementation**

Run:

```bash
go test ./cmd/heimdall-agent ./internal/orchestrator ./internal/platform/config -run 'OpenClaw|Docker|Firecracker|SelectVMDriver|TestLoad_Orchestrator' -count=1
```

Expected: FAIL while runtime code and scripts still reference `valinor`.

**Step 3: Update the runtime implementation**

- Patch Docker build/output paths and entrypoints in `Dockerfile.agent`.
- Patch agent logs/comments and runtime bridging text in `cmd/heimdall-agent`.
- Patch orchestrator naming/labels/paths in `internal/orchestrator`.
- Patch Firecracker helper scripts and guest runtime install paths.

**Step 4: Re-run the targeted verification**

Run:

```bash
go test ./cmd/heimdall-agent ./internal/orchestrator ./internal/platform/config -run 'OpenClaw|Docker|Firecracker|SelectVMDriver|TestLoad_Orchestrator' -count=1
```

Expected: PASS.

**Step 5: Commit**

```bash
git add Dockerfile.agent cmd/heimdall-agent internal/orchestrator internal/platform/config scripts/firecracker
git commit -m "chore: rename heimdall runtime and container surfaces"
```

### Task 4: Rename Marketing Pages, Metadata, and Component Names

**Files:**
- Modify: `dashboard/src/app/(marketing)/layout.tsx`
- Modify: `dashboard/src/app/(marketing)/landing/page.tsx`
- Modify: `dashboard/src/app/(marketing)/architecture/page.tsx`
- Modify: `dashboard/src/components/landing/hero.tsx`
- Move: `dashboard/src/components/landing/why-valinor.tsx` -> `dashboard/src/components/landing/why-heimdall.tsx`
- Modify: `dashboard/src/components/landing/footer.tsx`
- Modify: `dashboard/src/components/landing/footer.test.tsx`
- Modify: `dashboard/src/components/architecture/architecture-diagram.tsx`
- Modify: `dashboard/src/components/architecture/architecture-diagram.test.tsx`
- Modify: `dashboard/src/components/architecture/architecture-page.tsx`

**Step 1: Update the targeted passing tests first**

- Change the assertions in `dashboard/src/components/landing/footer.test.tsx` and `dashboard/src/components/architecture/architecture-diagram.test.tsx` from `Valinor` to `Heimdall`.
- Update the landing-page import to use `WhyHeimdall` after the component rename.

**Step 2: Run the targeted tests and confirm they fail**

Run:

```bash
cd dashboard && npx vitest run src/components/landing/footer.test.tsx src/components/architecture/architecture-diagram.test.tsx
```

Expected: FAIL while the components still render `Valinor` copy and old links.

**Step 3: Update the marketing implementation**

- Replace visible `Valinor` copy with `Heimdall`.
- Update metadata titles/descriptions for the marketing layout and architecture page.
- Rename `why-valinor.tsx` to `why-heimdall.tsx` and update its exported component name and import site.
- Update GitHub links to the renamed repository.

**Step 4: Re-run the targeted frontend verification**

Run:

```bash
cd dashboard && npx vitest run src/components/landing/footer.test.tsx src/components/architecture/architecture-diagram.test.tsx && npx tsc --noEmit
```

Expected: PASS.

**Step 5: Commit**

```bash
git add dashboard/src/app/'(marketing)' dashboard/src/components/landing dashboard/src/components/architecture
git commit -m "feat: rename marketing surfaces to heimdall"
```

### Task 5: Rename Dashboard Shell, Auth Copy, and Session Keys

**Files:**
- Modify: `dashboard/src/app/layout.tsx`
- Modify: `dashboard/src/components/auth/auth-card.tsx`
- Create: `dashboard/src/components/auth/auth-card.test.tsx`
- Modify: `dashboard/src/components/nav/sidebar.tsx`
- Modify: `dashboard/src/components/nav/tenant-sidebar.tsx`
- Modify: `dashboard/src/lib/auth.ts`
- Modify: `dashboard/src/lib/permissions.ts`
- Modify: `dashboard/src/lib/site-links.ts`
- Modify: `dashboard/src/app/(auth)/signup/page.tsx`
- Modify: `dashboard/src/app/(auth)/signup/verify/page.tsx`
- Modify: `dashboard/src/app/(auth)/sso-callback/page.tsx`
- Modify: `dashboard/tests/e2e/smoke.spec.ts`

**Step 1: Add a focused dashboard branding test**

Create `dashboard/src/components/auth/auth-card.test.tsx` with a simple assertion that the auth card renders `Heimdall`.

**Step 2: Run the focused test and confirm it fails**

Run:

```bash
cd dashboard && npx vitest run src/components/auth/auth-card.test.tsx
```

Expected: FAIL while the auth card still renders `Valinor`.

**Step 3: Update dashboard shell/auth implementation**

- Rename dashboard/app titles from `Valinor Dashboard` to `Heimdall Dashboard`.
- Replace product-name strings in auth and nav components.
- Rename signup/session storage keys from `valinor_signup_pending` to `heimdall_signup_pending`.
- Update comments and links that still name the old repo or old command paths.
- Update the Playwright smoke assertion to expect `Heimdall Dashboard`.

**Step 4: Re-run targeted dashboard verification**

Run:

```bash
cd dashboard && npx vitest run src/components/auth/auth-card.test.tsx && npx tsc --noEmit && rg -n 'Valinor|valinor' src/app src/components src/lib tests/e2e
```

Expected: test passes, TypeScript passes, and `rg` returns no matches.

**Step 5: Commit**

```bash
git add dashboard/src/app dashboard/src/components/auth dashboard/src/components/nav dashboard/src/lib dashboard/tests/e2e/smoke.spec.ts
git commit -m "chore: rename dashboard shell and auth branding"
```

### Task 6: Rewrite Active Docs and Runbooks to Heimdall

**Files:**
- Modify: `CLAUDE.md`
- Modify: `docs/product-overview.md`
- Modify: `docs/architecture.md`
- Modify: `docs/runbooks/docker-teams-tier-setup.md`
- Modify: `docs/runbooks/firecracker-build-test.md`
- Modify: `docs/runbooks/openclaw-security-hardening-checklist.md`

**Step 1: Capture the current live-doc matches**

Run:

```bash
rg -n 'Valinor|valinor' CLAUDE.md docs/product-overview.md docs/architecture.md docs/runbooks
```

Expected: multiple matches.

**Step 2: Rewrite the live docs**

- Replace `Valinor`/`valinor` with `Heimdall`/`heimdall`.
- Update command examples, Docker tags, filesystem paths, and agent binary names to the renamed forms.

**Step 3: Verify the live docs are clean**

Run:

```bash
rg -n 'Valinor|valinor' CLAUDE.md docs/product-overview.md docs/architecture.md docs/runbooks
```

Expected: no matches.

**Step 4: Spot-check the most operational docs**

Run:

```bash
sed -n '1,220p' docs/runbooks/docker-teams-tier-setup.md
sed -n '1,220p' docs/runbooks/firecracker-build-test.md
```

Expected: commands, image names, and paths all use `heimdall`.

**Step 5: Commit**

```bash
git add CLAUDE.md docs/product-overview.md docs/architecture.md docs/runbooks
git commit -m "docs: rename active docs and runbooks to heimdall"
```

### Task 7: Sweep Historical Plans and Remove Leftover Valinor Filenames

**Files:**
- Move: `docs/plans/2026-02-21-valinor-design.md` -> `docs/plans/2026-02-21-heimdall-design.md`
- Modify: every file returned by `rg -l 'Valinor|valinor' docs/plans`
- Modify: `docs/plans/2026-03-16-heimdall-rebrand-design.md`
- Modify: `docs/plans/2026-03-16-heimdall-rebrand-implementation-plan.md`

**Step 1: Capture the historical-doc inventory**

Run:

```bash
rg -l 'Valinor|valinor' docs/plans | sort
find docs/plans -iname '*valinor*' | sort
```

Expected: many content matches and one historical filename match.

**Step 2: Update the historical docs**

- Rename `docs/plans/2026-02-21-valinor-design.md` to `docs/plans/2026-02-21-heimdall-design.md`.
- Replace present-tense references, code snippets, commands, image names, paths, and product names throughout `docs/plans`.
- In the two rebrand docs, preserve the rename comparison where necessary but keep the active system identity as `Heimdall`.

**Step 3: Verify the historical sweep**

Run:

```bash
rg -n 'Valinor|valinor' docs/plans --glob '!2026-03-16-heimdall-rebrand-design.md' --glob '!2026-03-16-heimdall-rebrand-implementation-plan.md'
find docs/plans -iname '*valinor*' | sort
```

Expected: the `rg` command returns no matches, and the filename scan returns nothing.

**Step 4: Spot-check the biggest plan families**

Run:

```bash
sed -n '1,160p' docs/plans/2026-03-02-openclaw-integration-plan.md
sed -n '1,160p' docs/plans/2026-03-03-clerk-headless-auth-plan.md
sed -n '1,160p' docs/plans/2026-03-14-architecture-pages-design.md
```

Expected: commands and prose use `Heimdall`.

**Step 5: Commit**

```bash
git add docs/plans
git commit -m "docs: sweep historical valinor references"
```

### Task 8: Final Leftover Scan and Full Verification

**Files:**
- Review the full repository state after Tasks 1-7

**Step 1: Run the final leftover scans**

Run:

```bash
rg -n --hidden --glob '!.git' --glob '!node_modules' --glob '!.next' 'Valinor|valinor' . --glob '!docs/plans/2026-03-16-heimdall-rebrand-design.md' --glob '!docs/plans/2026-03-16-heimdall-rebrand-implementation-plan.md'
find . -path './.git' -prune -o -path './node_modules' -prune -o -path './.next' -prune -o -iname '*valinor*' -print
```

Expected: both commands return nothing.

**Step 2: Run backend verification**

Run:

```bash
go test ./... -count=1
```

Expected: PASS.

**Step 3: Run frontend verification**

Run:

```bash
cd dashboard && npx vitest run src/components/landing/footer.test.tsx src/components/architecture/architecture-diagram.test.tsx src/components/auth/auth-card.test.tsx && npx tsc --noEmit
```

Expected: PASS.

**Step 4: Record the known dashboard baseline failures separately**

Run:

```bash
cd dashboard && npm run test:run
```

Expected: either the same six pre-existing failures in `channels-view`, `connectors-view`, and `sidebar`, or fewer. Stop and investigate if any new failing file appears.

**Step 5: Commit**

```bash
git add .
git commit -m "chore: complete heimdall rebrand cutover"
```
