# AGENTS.md — Guidance for AI coding agents

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

## Repository structure

```
cmd/podcast-token-service/    HTTP service — main entry point
cmd/podcast-members-manage/   Management CLI
internal/db/                  Shared SQLite layer (used by both binaries)
vendor/                       Committed vendored dependencies (do not delete)
pkgs/podcast-token-service/   Nix derivation (buildGoModule, vendorHash=null)
modules/services/             NixOS systemd module
podman/                       Podman Compose deployment
SPEC.md                       Authoritative endpoint and behaviour specification
```

## Specification

Read `SPEC.md` before making any change to HTTP handler behaviour, database
schema, token format, or notification logic. It is the source of truth for
what the service must do. If a change deviates from SPEC.md, update SPEC.md
first and describe the reasoning in the PR.

## Running tests

```bash
nix develop --command go test ./...
```

All tests must pass before committing. The test suite uses `httptest` for HTTP
handler tests and real in-memory SQLite (via `modernc.org/sqlite`) for database
tests — no mocks.

Tests that exercise Nostr relay publishing are integration tests and require
network access. They are omitted from the unit test suite (relay connections
in tests use pre-existing key material and stub the actual relay calls).

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

## Key design decisions

- **Pure Go Nostr:** `github.com/nbd-wtf/go-nostr` provides all Nostr
  cryptography (Schnorr signing, NIP-04 ECDH, relay WebSocket). There is no
  `libsecp256k1` dependency.

- **Token URL stability:** On `SubscriptionRenewed`, the active token is
  extended (expiry updated in-place) rather than replaced. This avoids
  silently breaking subscribers whose podcast apps have cached the URL.

- **Expiry notification is one-shot:** The first feed request after expiry
  injects a synthetic episode and sets `expiry_notified_at`. Subsequent
  requests return 402. This prevents a flood of expiry episodes in the
  subscriber's podcast app.

- **Notification failures are non-fatal:** The webhook handler writes the
  token before attempting notifications. A notification failure logs an error
  but does not return a failure to BTCPay (which would cause a retry and a
  duplicate token).

- **No CGO:** `modernc.org/sqlite` is used (pure Go) instead of
  `github.com/mattn/go-sqlite3` (CGO). This keeps the binary and Docker
  image fully static.

## What NOT to change without updating SPEC.md

- Database schema (column names, types, constraints)
- Token format (32 bytes, base64url no-padding)
- HTTP endpoint paths
- Prometheus metric names or label values
- NIP-98 verification logic (kind, timestamp window, tag names)
- Nostr relay list (update in both main.go and SPEC.md together)
