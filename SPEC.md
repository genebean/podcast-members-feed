# Podcast Members Feed — Service Specification

## Purpose

The podcast token service bridges BTCPay Server subscription webhooks to
private RSS feed access. When a subscriber pays through BTCPay, the service
issues them a unique, token-bearing feed URL. The subscriber adds that URL to
any podcast app and gets access to member-only episodes. When the subscription
expires or is cancelled, access is cut off automatically.

## Architecture

```
BTCPay Server
    │ HMAC-signed webhook
    ▼
podcast-token-service (Go, net/http + chi)
    │                  │               │
    ▼                  ▼               ▼
 SQLite DB      PodServer feed    Nostr relays / SMTP
(tokens.db)    (upstream proxy)   (notifications)
```

- **No native library dependencies.** Nostr cryptography (Schnorr signing,
  NIP-04 ECDH) is provided by `github.com/nbd-wtf/go-nostr` in pure Go.
  `libsecp256k1` is not required.
- **Single SQLite file** stores all subscribers and tokens. WAL-mode not
  explicitly set; the driver defaults are used. Concurrent access serialised
  via `SetMaxOpenConns(1)`.
- **No framework beyond chi.** Business logic is in plain Go functions, making
  it easy to unit-test handlers directly without mocking HTTP layers.

## Database Schema

```sql
CREATE TABLE subscribers (
    btcpay_subscriber_id  TEXT PRIMARY KEY,
    email                 TEXT,
    nostr_pubkey          TEXT,
    created_at            TEXT NOT NULL,
    -- at least one contact method required
    CHECK (email IS NOT NULL OR nostr_pubkey IS NOT NULL)
);

CREATE TABLE tokens (
    token                 TEXT PRIMARY KEY,
    btcpay_subscriber_id  TEXT NOT NULL REFERENCES subscribers,
    expires_at            TEXT NOT NULL,    -- RFC3339Nano UTC
    created_at            TEXT NOT NULL,
    last_used_at          TEXT,
    revoked               INTEGER NOT NULL DEFAULT 0,
    expiry_notified_at    TEXT,             -- set after injecting expiry episode
);

CREATE INDEX idx_tokens_subscriber ON tokens(btcpay_subscriber_id);
```

`expiry_notified_at` records when the one-time expiry audio episode was served.
Once set, subsequent feed requests for that token return 402.

## Token Format

Tokens are 32 random bytes encoded as URL-safe base64 without padding (43
characters), matching Python's `secrets.token_urlsafe(32)` output format for
database compatibility.

## Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `BTCPAY_WEBHOOK_SECRET` | ✓ | — | HMAC-SHA256 shared secret from BTCPay webhook settings |
| `PODSERVER_FEED_URL` | ✓ | — | Internal URL of the PodServer members RSS feed |
| `FEED_BASE_URL` | ✓ | — | Public base URL for subscriber feed URLs and /recover |
| `ADMIN_TOKEN` | ✓ | — | Bearer token for /metrics and /admin/ endpoints |
| `NOSTR_PRIVATE_KEY` | ✓ | — | Service Nostr keypair: nsec bech32 or 32-byte hex |
| `DATABASE_PATH` | | `tokens.db` | Path to SQLite database file |
| `EXPIRED_AUDIO_URL` | | `` | URL of pre-recorded expiry audio clip (optional) |
| `SMTP_HOST` | | `` | SMTP server (required for email delivery) |
| `SMTP_PORT` | | `587` | SMTP port |
| `SMTP_USER` | | `` | SMTP username |
| `SMTP_PASSWORD` | | `` | SMTP password |
| `SMTP_FROM` | | `` | Sender address for outgoing email |

If `SMTP_HOST` is empty, email delivery is skipped silently. At least one of
SMTP or Nostr must be configured — the database constraint `CHECK (email IS NOT
NULL OR nostr_pubkey IS NOT NULL)` enforces a contact method per subscriber.

## HTTP Endpoints

### `POST /webhook/btcpay`

Receives BTCPay Server subscription lifecycle events.

**Authentication:** BTCPay-Sig header — `sha256=<HMAC-SHA256-hex>` of the
request body, keyed with `BTCPAY_WEBHOOK_SECRET`.

**Request body** (JSON from BTCPay):
```json
{
  "type": "SubscriptionCreated",
  "subscriberId": "btcpay-sub-id",
  "email": "user@example.com",
  "subscription": { "expiresAt": 1750000000 },
  "metadata": { "nostrPubkey": "hex-or-npub" }
}
```

**Handled event types:**

| Event | Action |
|---|---|
| `SubscriptionCreated` | Upsert subscriber, create token, deliver feed URL via email + Nostr DM |
| `SubscriptionRenewed` | Extend expiry on active token; if no active token exists, issue a new one |
| `SubscriptionExpired` | Revoke all tokens |
| `SubscriptionSuspended` | Revoke all tokens |

Notification failures do not crash the handler — the token is already written
and BTCPay must not be signalled to retry (which would create duplicate tokens).

**Response:** `{"status": "ok"}` on success, `{"status": "ignored", "reason":
"..."}` when subscriberId is absent.

---

### `GET /rss/{token}.xml`

Returns the members RSS feed for a valid token.

**Behaviour:**

| Condition | Response |
|---|---|
| Token unknown or revoked | `402 Payment Required` — `Subscription required or expired.` |
| Token valid, not expired | `200` — upstream feed proxied (5-minute in-memory cache) |
| Token expired, first request | `200` — upstream feed with a synthetic expiry episode prepended; `expiry_notified_at` set; optional Nostr DM sent |
| Token expired, subsequent requests | `402 Payment Required` — `Subscription expired.` |

The expiry episode contains:
- Title: `Your subscription has expired`
- Description: instructions to renew
- PubDate: current time
- Guid: `expired-notice-<unix-timestamp>` (not a permalink)
- Enclosure: `EXPIRED_AUDIO_URL` if configured

---

### `GET /api/feed-url`

Returns the subscriber's feed URL given a valid NIP-98 HTTP Auth event.
Used by the `/recover` page for self-service URL retrieval.

**Authentication:** `Authorization: Nostr <base64(JSON event)>`

**NIP-98 verification steps:**
1. Decode base64 event JSON from header
2. `kind` must be `27235`
3. `created_at` must be within 60 seconds of server time (replay prevention)
4. `tags` must contain `["u", "<FEED_BASE_URL>/api/feed-url"]`
5. `tags` must contain `["method", "GET"]`
6. Event ID and Schnorr signature must be valid

**Response on success:** `{"feed_url": "https://members.example.com/rss/<token>.xml"}`

**Error codes:**
- `401` — missing/malformed auth, wrong kind, expired timestamp, URL/method mismatch, invalid signature
- `404` — no active subscription found for the pubkey

---

### `GET /recover`

HTML page for self-service feed URL recovery via NIP-07 browser extension
(Alby, nos2x). JavaScript on the page calls `window.nostr.signEvent()` to
produce a NIP-98 event, then fetches `/api/feed-url`.

Mobile users without extension support are directed to the email fallback
(reply to their subscription confirmation email).

---

### `GET /metrics`

Prometheus metrics in text format.

**Authentication:** `Authorization: Bearer <ADMIN_TOKEN>`

**Exposed metrics:**

| Metric | Type | Description |
|---|---|---|
| `podcast_active_tokens` | Gauge | Non-revoked, non-expired tokens |
| `podcast_total_subscribers` | Gauge | Total subscribers ever registered |
| `podcast_webhooks_total{event_type}` | Counter | Successfully processed webhooks |
| `podcast_webhook_errors_total{reason}` | Counter | Webhook processing errors |
| `podcast_feed_requests_total{result}` | Counter | Feed requests by result (`valid`/`expired`/`upstream_error`) |
| `podcast_feed_upstream_errors_total` | Counter | Failures fetching upstream PodServer feed |
| `podcast_expiry_notifications_total` | Counter | Expiry episodes injected |
| `podcast_nostr_dm_total{result}` | Counter | Nostr DM delivery attempts |
| `podcast_nostr_dm_relay_total{relay,result}` | Counter | Per-relay publish results |
| `podcast_email_total{result}` | Counter | Email delivery attempts |
| `podcast_nip98_requests_total{result}` | Counter | NIP-98 feed-url requests |
| `podcast_recovery_page_visits_total` | Counter | /recover page visits |

---

### `POST /admin/cleanup`

Deletes tokens that were revoked or expired more than 90 days ago.

**Authentication:** `Authorization: Bearer <ADMIN_TOKEN>`

Intended to be called by a weekly cron/timer (see NixOS module).
Not exposed via nginx — call directly on the host:
```bash
curl -sf -X POST -H "Authorization: Bearer $ADMIN_TOKEN" http://127.0.0.1:8765/admin/cleanup
```

---

### `GET /health`

Returns `{"status": "ok"}` with HTTP 200. Used by container healthchecks and
load balancer probes.

---

## Notification Flow

### On `SubscriptionCreated` (or lapsed re-subscription)

1. Token written to database
2. Feed URL constructed: `{FEED_BASE_URL}/rss/{token}.xml`
3. Email sent via SMTP (if `SMTP_HOST` set and subscriber has email)
4. Nostr NIP-04 DM sent to subscriber's npub (if provided), published to all
   four configured relays concurrently with a 5-second per-relay timeout

### On first feed access after expiry

1. Expiry episode injected into feed response
2. `expiry_notified_at` written to database
3. Nostr DM sent with renewal instructions (fire-and-forget goroutine)

## Nostr Integration

- **Key format:** `NOSTR_PRIVATE_KEY` accepts nsec bech32 or raw 32-byte hex
- **Encryption:** NIP-04 (AES-256-CBC + ECDH x-coordinate shared secret)
- **Event signing:** BIP-340 Schnorr via `github.com/nbd-wtf/go-nostr`
- **Relays:** Four hardcoded relays (Damus, nos.lol, Primal, nostr.data.haus)
- **Publishing:** Goroutines per relay, 5-second connect + 5-second publish timeout each
- **Success threshold:** At least one relay must accept the event

## CLI — `podcast-members-manage`

Reads the SQLite database directly. All subcommands share a `--db PATH` flag.

```
podcast-members-manage [--db PATH] <command> [flags]
```

| Command | Description |
|---|---|
| `subscribers` | List all subscribers with token status. Filters: `--active`, `--never-accessed`, `--expiring-days N` |
| `feed-url` | Print feed URL for a subscriber. Lookup by `--email` or `--npub` |
| `revoke <id>` | Revoke all tokens for a BTCPay subscriber ID (prompts for confirmation unless `--yes`) |
| `stats` | Print counts: total subscribers, active tokens, never-accessed, expired-unnotified |
| `cleanup` | POST to `/admin/cleanup` on the running service (requires `ADMIN_TOKEN` env) |
| `test-webhook` | End-to-end service validation: health, metrics, webhook, feed proxy, expiry flow |

### `test-webhook` flags

```
--service-url URL      (default: $SERVICE_URL or http://127.0.0.1:8765)
--webhook-secret S     BTCPAY_WEBHOOK_SECRET value (required)
--npub KEY             Nostr npub/hex for test subscriber
--email ADDR           email for test subscriber
--feed-url URL         validate upstream feed returns real RSS content
--run-expiry-test      also test expiry injection and 402 flow
```

## Security Notes

- Webhook signatures are verified with `hmac.Equal` (constant-time comparison)
- Admin bearer token compared with `hmac.Equal` (constant-time comparison)
- NIP-98 replay window is 60 seconds — clients should generate events fresh
- Feed tokens are 32 bytes of random data (256-bit entropy), base64url-encoded
- SMTP uses STARTTLS via Go's `net/smtp.SendMail`
- Service binds to `127.0.0.1` only; nginx handles TLS and public routing
- `/admin/cleanup` and `/metrics` are not intended to be publicly routed
