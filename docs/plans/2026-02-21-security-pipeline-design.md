# Security Pipeline Design

**Date:** 2026-02-21
**Status:** Approved

## Overview

Defense-in-depth security pipeline for Valinor. Code quality and security are enforced at four layers: CLAUDE.md self-review, pre-commit hooks, CI scanners, and AI-powered PR review.

## Architecture: Parallel Workflows (Approach B)

Fast local hooks for immediate feedback. Full security suite runs in CI in parallel. Claude reviews PRs in an isolated workflow so Anthropic API issues don't block CI.

```
Code written
  → CLAUDE.md forces self-review
    → pre-commit blocks secrets + lint failures locally
      → CI runs full security suite in parallel
        → Claude reviews the PR against project rules
          → corrections feed back into docs/lessons.md
```

## Components

### 1. CLAUDE.md — Self-review Quality Gate

Lives at repo root. Read automatically by every Claude Code session.

**Security rules:**
- All SQL must use parameterized queries (no string concatenation)
- All new tables must have RLS policies
- No secrets, API keys, or credentials in code — use env vars / config
- All user input validated at API boundaries
- Auth/RBAC checks required on every handler

**Architecture rules:**
- Module boundaries: packages under `internal/` must not import each other's internals (only exported interfaces)
- Error handling: wrap errors with `fmt.Errorf("context: %w", err)`, never swallow errors silently
- Context propagation: all functions that do I/O must accept `context.Context` as first param
- Database: all queries go through the `database` package, never raw `pgx` in handlers

**Go idioms & quality:**
- Naming follows Go conventions (`MixedCaps`, not `snake_case`; acronyms like `HTTP`, `ID` fully capitalized)
- Test coverage required for all new exported functions
- No `interface{}` / `any` without justification — use concrete types
- Struct fields ordered: exported first, then unexported, grouped logically
- No `init()` functions — explicit initialization in `main.go`

**Performance:**
- Connection pooling for all external resources
- No unbounded goroutines — always use `errgroup` or similar with limits
- Avoid allocations in hot paths — prefer `sync.Pool` where measured

**Bug workflow:**
- When given a bug report, do not start by trying to fix it
- Write a test that reproduces the bug first
- Dispatch subagents to fix the bug and prove it with a passing test

**Self-improvement loop:**
- After any correction from the user, update `docs/lessons.md` with the pattern
- Write rules that prevent the same mistake recurring

**Core principles:**
- Simplicity first — make every change as simple as possible, minimal code impact
- No laziness — find root causes, no temporary fixes, senior developer standards
- Minimal impact — changes touch only what's necessary
- Demand elegance for non-trivial changes — pause and ask "is there a more elegant way?"

### 2. Pre-commit Hooks

`.pre-commit-config.yaml` — fast local gate (~10 seconds total).

| Hook | Purpose | Speed |
|---|---|---|
| gitleaks | Catch leaked secrets before they hit git history | ~1s |
| golangci-lint | Linting + go vet + staticcheck + errcheck | ~3-5s |
| go mod tidy check | Ensure go.mod/go.sum are clean | ~1s |
| gofmt check | Formatting consistency | <1s |

Heavy scanners (gosec, semgrep, govulncheck) run in CI only to keep commits fast.

### 3. GitHub Actions — CI Pipeline

Three parallel workflows, all triggered on push and PR to master:

**`ci.yml` — Build, Test, Lint:**
- `go build ./...`
- `go test ./... -race -coverprofile`
- `golangci-lint run`

**`security.yml` — Security Scanners (4 parallel jobs):**
- `gosec ./...` — Go-specific security analysis
- `semgrep --config=auto --lang=go` — SAST pattern matching
- `govulncheck ./...` — Go vulnerability database (call-graph aware)
- `gitleaks detect --source=.` — Secret detection

Any failure blocks the PR.

**`claude-review.yml` — AI PR Review (PR only):**
- `anthropics/claude-code-action@v1`
- Reviews against CLAUDE.md project rules
- Requires `ANTHROPIC_API_KEY` in GitHub repo secrets

### 4. golangci-lint Configuration

`.golangci.yml` with strict-but-practical linter set:

**Enabled:**
- errcheck, govet, staticcheck, unused, gosimple, ineffassign, typecheck
- misspell, gofmt, revive
- bodyclose, noctx, sqlclosecheck

**Excluded (too noisy):**
- wsl, gofumpt, nlreturn (cosmetic whitespace)
- godox (TODOs expected during active development)
- exhaustruct (impractical with large config structs)

### 5. Supporting Files

| File | Purpose |
|---|---|
| `docs/lessons.md` | Cross-session learning from corrections |

## Tools Not Included (Decided Against)

| Tool | Reason |
|---|---|
| claude-agent-sdk batch audit | claude-code-action already covers PR review; add later if gaps appear |
| Factory.ai droids | Vendor overlap with existing pipeline; revisit if needed |
| bandit, ruff, mypy | Python-specific — not applicable to Go project |
| Snyk | govulncheck covers Go dependency vulnerabilities natively |

## Prerequisites

- `ANTHROPIC_API_KEY` added to GitHub repo secrets (Settings → Secrets → Actions)
- `pre-commit` installed locally (`pip install pre-commit` or `brew install pre-commit`)
- `golangci-lint` installed locally (`go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest`)
