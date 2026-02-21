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
