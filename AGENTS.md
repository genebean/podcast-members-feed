# AGENTS.md — Guidance for AI coding agents

## Who you're working with

The owner is an experienced infrastructure engineer (SRE) who manages Linux
fleets, runs a NixOS homelab, and is comfortable in a terminal. He is **not an
application developer**. When working on application code:

- Comment generously — future maintenance may be done by an agent returning
  cold to this code, or by the owner who did not write the application layer
- Prefer explicit over implicit — avoid patterns that require deep framework
  knowledge to maintain
- Prefer simple over clever — the best solution is the one easiest to
  understand six months later
- Add a comment whenever the reason for a choice is non-obvious, e.g.:
  - Why string manipulation instead of an XML parser (CDATA safety)
  - Why `context.Background()` instead of the request context (notification isolation)
  - Why `SetMaxOpenConns(1)` (SQLite single-writer constraint)
  - Why `nip04.ComputeSharedSecret` takes `(pub, sk)` not `(sk, pub)` (easy to swap)

## Toolchain

**Go is not installed on the host.** It is provided exclusively by the Nix
dev shell. Always prefix Go commands with `nix develop --command`:

```bash
nix develop --command go test ./...
nix develop --command go build ./...
nix develop --command go mod tidy
nix develop --command go mod vendor
nix develop --command golangci-lint run
```

Never install Go separately or assume it is on `$PATH` outside the dev shell.
Never suggest using homebrew, apt, or any system package manager for project
tooling. If a tool is missing from the dev shell, suggest adding it to
`flake.nix` instead.

## Repository structure

```
cmd/podcast-token-service/    HTTP service — main entry point
cmd/podcast-members-manage/   Management CLI
internal/db/                  Shared SQLite layer (used by both binaries)
vendor/                       Committed vendored dependencies (do not delete)
pkgs/podcast-token-service/   Nix derivation (buildGoModule, vendorHash=null)
modules/services/             NixOS systemd module
podman/                       Podman Compose deployment
alerts/                       Prometheus/AlertManager rules
docs/                         HTML documentation (served via GitHub Pages)
```

## Specification

Read `docs/reference/spec.html` before making any change to HTTP handler
behaviour, database schema, token format, or notification logic. It is the
single source of truth for what the service must do. If a change deviates
from the spec, update `docs/reference/spec.html` in the same commit and
describe the reasoning in the PR.

## Running tests

```bash
nix develop --command go test ./...
```

All tests must pass before committing. The test suite uses `httptest` for HTTP
handler tests and real in-memory SQLite (via `modernc.org/sqlite`) for database
tests — no mocks.

## Vendored dependencies

The `vendor/` directory is committed and used by the Nix build. After any
`go mod tidy`, run:

```bash
nix develop --command go mod vendor
git add vendor/
```

Do not use `go get` without also running `go mod vendor` and committing the
updated vendor directory.

## Nix packaging

`pkgs/podcast-token-service/default.nix` uses `buildGoModule` with
`vendorHash = null`, which instructs Nix to use the committed `vendor/`
directory instead of fetching from the network. This avoids needing to
compute a hash after every dependency change.

The docker image is built with `nix build .#dockerImage` and contains only the
compiled binary and `cacert`. No native library (`libsecp256k1`, etc.) is
included — the Go binary is self-contained.

## NixOS module

The NixOS module lives in this repo at `modules/services/podcast-token-service.nix`
and is exported from `flake.nix` as `nixosModules.default`. The consuming
`dots` repo adds this repo as a flake input and imports the module for the
relevant host. This keeps deployment config co-located with the code.

When modifying the module:
- Expose typed options with `lib.mkOption` — domain, ports, data directories,
  secrets file path, enable flag
- Use `DynamicUser = true` for the systemd service where possible
- Secrets are passed via `EnvironmentFile` — never hardcode secrets
- Add `systemd.tmpfiles.rules` entries for any required directories

## Documentation

All project documentation is written as pure HTML files in `docs/`.

- `docs/index.html` — user-facing landing page
- `docs/reference/spec.html` — authoritative technical spec
- No static site generator, no build step — Pages serves the HTML directly
- Navigate between pages with standard `<a href>` links
- Edit HTML files directly; do not introduce Jekyll, Hugo, or any generator

A GitHub Actions workflow (`.github/workflows/docs.yml`) deploys `docs/` to
GitHub Pages automatically on every push to `main` that touches `docs/`.
GitHub Pages must be configured in repo settings to use **GitHub Actions** as
the source.

## Infrastructure preferences

When making architectural decisions or suggesting approaches:

- **Self-hosted over cloud** — prefer solutions that run on infrastructure the
  owner controls over third-party SaaS
- **Open-source over proprietary** — all else equal, prefer open-source tools
- **Simple over clever** — the least complex solution that meets requirements

## Key design decisions

- **Pure Go Nostr:** `github.com/nbd-wtf/go-nostr` provides all Nostr
  cryptography (Schnorr signing, NIP-04 ECDH, relay WebSocket). There is no
  `libsecp256k1` dependency.

- **Token URL stability:** On `SubscriptionRenewed`, the active token is
  extended (expiry updated in-place) rather than replaced. This avoids
  silently breaking subscribers whose podcast apps have cached the URL.

- **3-day grace period:** Tokens continue serving the normal feed for 3 days
  past `expires_at` before the expiry episode is injected. This covers
  billing-cycle timing gaps.

- **Expiry notification is one-shot:** The first feed request after the grace
  period injects a synthetic episode and sets `expiry_notified_at`. Subsequent
  requests return 402. This prevents a flood of expiry episodes.

- **Notification failures are non-fatal:** The webhook handler writes the
  token to the DB before notifications fire. Notifications run in a detached
  goroutine using `context.Background()` so they are not cancelled when the
  HTTP request ends. A failure logs an error but does not signal BTCPay to
  retry (which would create a duplicate token).

- **No CGO:** `modernc.org/sqlite` (pure Go) is used instead of
  `github.com/mattn/go-sqlite3` (CGO). This keeps the binary and Docker
  image fully static.

## Commit and PR hygiene

- Write clear commit messages that explain *why*, not just *what*
- If a change affects the spec, update `docs/reference/spec.html` in the same commit
- Do not bundle unrelated changes in a single commit

## What NOT to change without updating docs/reference/spec.html

- Database schema (column names, types, constraints)
- Token format (32 bytes, base64url no-padding)
- HTTP endpoint paths
- Prometheus metric names or label values
- NIP-98 verification logic (kind, timestamp window, tag names)
- Nostr relay list
