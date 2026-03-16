# Heimdall Rebrand Design

## Summary

Valinor will be renamed to Heimdall everywhere in a single hard cutover. After the rebrand lands, `Heimdall` is the only supported identity across product copy, code, repo naming, binaries, Docker images, config defaults, documentation, and operational tooling.

## Decision

- Use a big-bang hard cutover rather than a phased migration.
- Replace `Valinor` and `valinor` everywhere immediately.
- Do not preserve compatibility aliases, dual-brand copy, or temporary fallback names.

## Canonical Identity

The canonical post-cutover identity is:

- Product name: `Heimdall`
- Repository name: `heimdall`
- GitHub module path: `github.com/FredAmartey/heimdall`

This also resolves the current mismatch between the actual remote (`github.com/FredAmartey/valinor`) and the in-repo Go module path (`github.com/valinor-ai/valinor`).

### Rename Rules

- `cmd/valinor` -> `cmd/heimdall`
- `cmd/valinor-agent` -> `cmd/heimdall-agent`
- `valinor-agent` binary/log prefixes -> `heimdall-agent`
- `valinor/agent:dev` -> `heimdall/agent:dev`
- `/var/lib/valinor` -> `/var/lib/heimdall`
- Defaults based on `valinor` in database URLs, usernames, database names, labels, or issuers -> `heimdall`

## Scope

The cutover includes all of the following:

### Core Code

- Go module path and import paths
- Command directories and executable names
- Dockerfile outputs and runtime references
- Scripts, hardcoded paths, labels, and log prefixes
- Default config values and auth issuer strings

### Frontend and Product

- Dashboard copy and metadata
- Marketing/site copy and metadata
- UI labels, titles, and brand references in tests
- Any route or component names that expose the old brand

### Operations

- CI commands
- Runbooks and setup guides
- Docker image tags and examples
- Local database examples and seed instructions
- Filesystem paths and bootstrap/install scripts

### Documentation

- README and current product documentation
- Architecture and runbook docs
- Timestamped plan/design docs where the old name is presented as the current system identity

## Documentation Policy

- Rename and rewrite current, user-facing docs when filenames are part of the live experience.
- Keep timestamped historical filenames unless the filename itself is actively misleading.
- Update historical document content where it refers to the present-day system so the repository no longer presents `Valinor` as the active name.

## Execution Order

Perform the cutover in this order within a single branch:

1. Rename structural identifiers: command directories, module path, imports, binaries, Dockerfile outputs, scripts, and config defaults.
2. Rename product surfaces: dashboard copy, marketing content, metadata, and test assertions.
3. Rename operational surfaces: CI commands, runbooks, bootstrap scripts, Docker tags, filesystem paths, and example commands.
4. Run a final repository-wide sweep for leftover `Valinor|valinor` references, then format and verify.

## Risks

### Go and Build Breakage

Changing the module path and command directories can break imports, build targets, and CI commands if any references are missed.

### Operational Drift

If scripts, runbooks, CI, or Docker references still point at `cmd/valinor`, old image names, or `/var/lib/valinor`, the repo will be inconsistent and operational setup will fail.

### Case-Sensitive Misses

Both `Valinor` and `valinor` appear in copy, paths, labels, usernames, database names, and tests. A partial rename will leave hidden failures.

### Repo Rename Dependency

The repository host and path must be renamed to `heimdall` so the new module path matches the actual remote. Otherwise the codebase will reference a module path that cannot be fetched.

## Success Criteria

- Repository-wide search finds no live `Valinor|valinor` references except clearly historical contexts that are intentionally retained.
- `go build ./...` succeeds under the new names.
- `go test ./...` succeeds under the new names.
- Relevant dashboard verification passes after product copy updates.
- CI, Docker, config examples, docs, and scripts all consistently reference `Heimdall`.
- The repository rename requirement is captured alongside the code changes so the module path and remote stay aligned.
