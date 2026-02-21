# Security Pipeline Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Set up a defense-in-depth security pipeline with CLAUDE.md, pre-commit hooks, CI workflows, and AI-powered PR review.

**Architecture:** Four enforcement layers — CLAUDE.md for self-review, pre-commit for fast local gating, GitHub Actions for full CI security scanning, and claude-code-action for AI PR review. See `docs/plans/2026-02-21-security-pipeline-design.md` for full design.

**Tech Stack:** GitHub Actions, golangci-lint, gosec, semgrep, govulncheck, gitleaks, pre-commit, claude-code-action

---

### Task 1: Create CLAUDE.md

**Files:**
- Create: `CLAUDE.md`

**Step 1: Create CLAUDE.md at repo root**

```markdown
# Valinor — Project Rules

## Security

- All SQL must use parameterized queries — no string concatenation
- All new database tables must have Row Level Security (RLS) policies
- No secrets, API keys, or credentials in code — use env vars or config.yaml
- All user input must be validated at API boundaries
- Auth and RBAC checks required on every HTTP handler

## Architecture

- Module boundaries: packages under `internal/` must not import each other's internals — only exported interfaces
- Error handling: wrap errors with `fmt.Errorf("context: %w", err)` — never swallow errors silently
- Context propagation: all functions that do I/O must accept `context.Context` as first parameter
- Database access: all queries go through the `internal/platform/database` package — never raw `pgx` in handlers

## Go Idioms & Quality

- Naming follows Go conventions: `MixedCaps` not `snake_case`, acronyms fully capitalized (`HTTP`, `ID`, `URL`)
- Test coverage required for all new exported functions
- No `interface{}` or `any` without explicit justification — use concrete types
- Struct fields ordered: exported first, then unexported, grouped logically
- No `init()` functions — explicit initialization in `main.go`

## Performance

- Connection pooling for all external resources
- No unbounded goroutines — use `errgroup` or similar with concurrency limits
- Avoid allocations in hot paths — prefer `sync.Pool` where measured

## Bug Workflow

When I report a bug, do NOT start by trying to fix it. Instead:
1. Write a test that reproduces the bug
2. Run the test to confirm it fails
3. Dispatch subagents to fix the bug and prove it with a passing test

## Self-Improvement

- After ANY correction from me, update `docs/lessons.md` with the pattern
- Write rules for yourself that prevent the same mistake recurring
- Review `docs/lessons.md` at session start

## Core Principles

- **Simplicity first** — make every change as simple as possible, impact minimal code
- **No laziness** — find root causes, no temporary fixes, senior developer standards
- **Minimal impact** — changes should only touch what's necessary
- **Demand elegance** — for non-trivial changes, pause and ask "is there a more elegant way?"
```

**Step 2: Create docs/lessons.md**

```markdown
# Lessons Learned

Patterns and corrections captured during development. Review at session start.

---
```

**Step 3: Commit**

```bash
git add CLAUDE.md docs/lessons.md
git commit -m "feat: add CLAUDE.md project rules and lessons file"
```

---

### Task 2: Create golangci-lint configuration

**Files:**
- Create: `.golangci.yml`

**Step 1: Create .golangci.yml at repo root**

```yaml
run:
  timeout: 5m
  modules-download-mode: readonly

linters:
  disable-all: true
  enable:
    # Default linters
    - errcheck
    - govet
    - staticcheck
    - unused
    - gosimple
    - ineffassign
    - typecheck
    # Formatting
    - gofmt
    - misspell
    # Code quality
    - revive
    # Security-adjacent
    - bodyclose
    - noctx
    - sqlclosecheck

linters-settings:
  revive:
    rules:
      - name: exported
        severity: warning
      - name: var-naming
        severity: warning
      - name: unexported-return
        severity: warning
  errcheck:
    check-type-assertions: true
    check-blank: true
  govet:
    enable-all: true
  misspell:
    locale: US

issues:
  exclude-use-default: false
  max-issues-per-linter: 0
  max-same-issues: 0
```

**Step 2: Verify the config parses correctly**

Run: `golangci-lint config verify --config .golangci.yml 2>&1 || echo "golangci-lint not installed locally — config will be validated in CI"`

Expected: Either clean output or "not installed" message. No parse errors.

**Step 3: Commit**

```bash
git add .golangci.yml
git commit -m "feat: add golangci-lint configuration"
```

---

### Task 3: Create pre-commit configuration

**Files:**
- Create: `.pre-commit-config.yaml`

**Step 1: Create .pre-commit-config.yaml at repo root**

```yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.22.1
    hooks:
      - id: gitleaks

  - repo: https://github.com/golangci/golangci-lint
    rev: v2.0.2
    hooks:
      - id: golangci-lint
        args: [--config, .golangci.yml]

  - repo: https://github.com/dnephin/pre-commit-golang
    rev: v0.5.1
    hooks:
      - id: go-mod-tidy

  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v5.0.0
    hooks:
      - id: end-of-file-fixer
      - id: trailing-whitespace
```

Note: `gofmt` is already covered by golangci-lint (gofmt linter enabled), so no separate hook needed.

**Step 2: Verify config syntax**

Run: `python3 -c "import yaml; yaml.safe_load(open('.pre-commit-config.yaml'))" && echo "YAML valid"`

Expected: `YAML valid`

**Step 3: Install the hooks**

Run: `pre-commit install 2>&1 || echo "pre-commit not installed — run: brew install pre-commit"`

Expected: `pre-commit installed at .git/hooks/pre-commit` or install instructions.

**Step 4: Commit**

```bash
git add .pre-commit-config.yaml
git commit -m "feat: add pre-commit hooks for gitleaks, golangci-lint, go-mod-tidy"
```

---

### Task 4: Create CI workflow — build, test, lint

**Files:**
- Create: `.github/workflows/ci.yml`

**Step 1: Create directory structure**

```bash
mkdir -p .github/workflows
```

**Step 2: Create .github/workflows/ci.yml**

```yaml
name: CI

on:
  push:
    branches: [master]
  pull_request:
    branches: [master]

permissions:
  contents: read

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-go@v5
        with:
          go-version-file: go.mod

      - name: Build
        run: go build ./...

  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-go@v5
        with:
          go-version-file: go.mod

      - name: Test
        run: go test ./... -race -coverprofile=coverage.out

      - name: Upload coverage
        uses: actions/upload-artifact@v4
        with:
          name: coverage
          path: coverage.out

  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-go@v5
        with:
          go-version-file: go.mod

      - name: golangci-lint
        uses: golangci/golangci-lint-action@v6
        with:
          version: v2.0.2
```

**Step 3: Validate YAML syntax**

Run: `python3 -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml'))" && echo "YAML valid"`

Expected: `YAML valid`

**Step 4: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "feat: add CI workflow for build, test, and lint"
```

---

### Task 5: Create security scanning workflow

**Files:**
- Create: `.github/workflows/security.yml`

**Step 1: Create .github/workflows/security.yml**

```yaml
name: Security

on:
  push:
    branches: [master]
  pull_request:
    branches: [master]

permissions:
  contents: read

jobs:
  gosec:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: securego/gosec@master
        with:
          args: ./...

  semgrep:
    runs-on: ubuntu-latest
    container:
      image: semgrep/semgrep
    steps:
      - uses: actions/checkout@v4

      - name: Semgrep scan
        run: semgrep scan --config=auto --error

  govulncheck:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-go@v5
        with:
          go-version-file: go.mod

      - name: Install govulncheck
        run: go install golang.org/x/vuln/cmd/govulncheck@latest

      - name: Run govulncheck
        run: govulncheck ./...

  gitleaks:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: gitleaks/gitleaks-action@v2
        env:
          GITLEAKS_LICENSE: ${{ secrets.GITLEAKS_LICENSE }}
```

**Step 2: Validate YAML syntax**

Run: `python3 -c "import yaml; yaml.safe_load(open('.github/workflows/security.yml'))" && echo "YAML valid"`

Expected: `YAML valid`

**Step 3: Commit**

```bash
git add .github/workflows/security.yml
git commit -m "feat: add security scanning workflow with gosec, semgrep, govulncheck, gitleaks"
```

---

### Task 6: Create Claude PR review workflow

**Files:**
- Create: `.github/workflows/claude-review.yml`

**Step 1: Create .github/workflows/claude-review.yml**

```yaml
name: Claude PR Review

on:
  pull_request:
    types: [opened, synchronize, reopened]
  issue_comment:
    types: [created]

permissions:
  contents: read
  pull-requests: write
  issues: write

jobs:
  review:
    if: >
      (github.event_name == 'pull_request') ||
      (github.event_name == 'issue_comment' && contains(github.event.comment.body, '@claude'))
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - uses: anthropics/claude-code-action@v1
        with:
          anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
          model: claude-sonnet-4-20250514
          direct_prompt: |
            Review this PR against the project rules in CLAUDE.md.
            Focus on: security vulnerabilities, architecture violations,
            Go idiom violations, missing tests, and performance concerns.
            Be specific — cite file paths and line numbers.
```

**Step 2: Validate YAML syntax**

Run: `python3 -c "import yaml; yaml.safe_load(open('.github/workflows/claude-review.yml'))" && echo "YAML valid"`

Expected: `YAML valid`

**Step 3: Commit**

```bash
git add .github/workflows/claude-review.yml
git commit -m "feat: add Claude AI PR review workflow"
```

---

### Task 7: Verify the full pipeline

**Step 1: Check all files exist**

Run: `ls -la CLAUDE.md .golangci.yml .pre-commit-config.yaml .github/workflows/ci.yml .github/workflows/security.yml .github/workflows/claude-review.yml docs/lessons.md`

Expected: All 7 files listed, no errors.

**Step 2: Validate all YAML files parse**

Run: `python3 -c "import yaml; [yaml.safe_load(open(f)) for f in ['.golangci.yml', '.pre-commit-config.yaml', '.github/workflows/ci.yml', '.github/workflows/security.yml', '.github/workflows/claude-review.yml']]" && echo "All YAML valid"`

Expected: `All YAML valid`

**Step 3: Run pre-commit on all files (dry run)**

Run: `pre-commit run --all-files 2>&1 || echo "Some hooks failed or pre-commit not installed — review output above"`

Expected: All hooks pass, or clear indication of what needs fixing.

**Step 4: Verify git status is clean**

Run: `git status`

Expected: Clean working tree, all files committed.
