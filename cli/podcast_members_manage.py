#!/usr/bin/env python3
"""
podcast-members-manage — management and testing CLI for the podcast token service.

Commands:
  subscribers       List subscribers, optionally filtered by status
  feed-url          Look up a subscriber's feed URL
  revoke            Revoke all tokens for a subscriber
  stats             Print subscriber and token summary
  cleanup           Call /admin/cleanup to remove old expired tokens
  test-webhook      Run a full end-to-end validation of the token service

Usage:
  podcast-members-manage [--db PATH] <command> [options]

Environment:
  DATABASE_PATH   path to the SQLite database (overridden by --db)
  FEED_BASE_URL   used to construct feed URLs in output
  ADMIN_TOKEN     bearer token for API calls
  SERVICE_URL     base URL of the token service (default: http://127.0.0.1:8765)

Podman example (Path A — Umbrel VPS):
  podman exec podcast-token-service \\
    podcast-members-manage --db /var/lib/podcast-token-service/tokens.db \\
    subscribers --active

NixOS example (Path B):
  podcast-members-manage subscribers --active
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import sqlite3
import sys
import textwrap
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone, timedelta
from typing import Optional


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DEFAULT_DB  = os.environ.get(
    "DATABASE_PATH", "/var/lib/podcast-token-service/tokens.db"
)
FEED_BASE   = os.environ.get("FEED_BASE_URL", "").rstrip("/")
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "")
SERVICE_URL = os.environ.get("SERVICE_URL", "http://127.0.0.1:8765").rstrip("/")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def get_db(path: str) -> sqlite3.Connection:
    if not os.path.exists(path):
        print(f"Error: database not found at {path}", file=sys.stderr)
        sys.exit(1)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


def fmt_dt(iso: Optional[str]) -> str:
    if not iso:
        return "never"
    try:
        return datetime.fromisoformat(iso).strftime("%Y-%m-%d %H:%M UTC")
    except ValueError:
        return iso


def fmt_feed_url(token: str) -> str:
    if FEED_BASE:
        return f"{FEED_BASE}/rss/{token}.xml"
    return f"<token: {token}>"


def print_row(label_width: int, **fields):
    for label, value in fields.items():
        print(f"  {label:<{label_width}} {value}")


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_subscribers(args, conn: sqlite3.Connection):
    now    = datetime.now(timezone.utc).isoformat()
    wheres = ["1=1"]
    params = []

    if args.active:
        wheres.append(
            "EXISTS (SELECT 1 FROM tokens t "
            "WHERE t.btcpay_subscriber_id = s.btcpay_subscriber_id "
            "AND t.revoked = 0 AND t.expires_at > ?)"
        )
        params.append(now)

    if args.never_accessed:
        wheres.append(
            "EXISTS (SELECT 1 FROM tokens t "
            "WHERE t.btcpay_subscriber_id = s.btcpay_subscriber_id "
            "AND t.last_used_at IS NULL AND t.revoked = 0)"
        )

    if args.expiring_days is not None:
        cutoff = (
            datetime.now(timezone.utc) + timedelta(days=args.expiring_days)
        ).isoformat()
        wheres.append(
            "EXISTS (SELECT 1 FROM tokens t "
            "WHERE t.btcpay_subscriber_id = s.btcpay_subscriber_id "
            "AND t.revoked = 0 AND t.expires_at > ? AND t.expires_at < ?)"
        )
        params.extend([now, cutoff])

    sql = f"""
        SELECT s.*,
               t.token, t.expires_at, t.last_used_at, t.revoked,
               t.expiry_notified_at
        FROM subscribers s
        LEFT JOIN tokens t ON t.btcpay_subscriber_id = s.btcpay_subscriber_id
            AND t.revoked = 0
            AND t.token = (
                SELECT token FROM tokens t2
                WHERE t2.btcpay_subscriber_id = s.btcpay_subscriber_id
                  AND t2.revoked = 0
                ORDER BY t2.created_at DESC LIMIT 1
            )
        WHERE {' AND '.join(wheres)}
        ORDER BY s.created_at DESC
    """

    rows = conn.execute(sql, params).fetchall()
    if not rows:
        print("No subscribers found.")
        return

    print(f"{'─' * 60}")
    for row in rows:
        print_row(
            16,
            ID=row["btcpay_subscriber_id"],
            Email=row["email"] or "(none)",
            Nostr=row["nostr_pubkey"] or "(none)",
            Subscribed=fmt_dt(row["created_at"]),
            Expires=fmt_dt(row["expires_at"]),
            **{"Last access": fmt_dt(row["last_used_at"])},
            **{"Feed URL": fmt_feed_url(row["token"]) if row["token"] else "(no active token)"},
        )
        print(f"{'─' * 60}")
    print(f"\nTotal: {len(rows)}")


def cmd_feed_url(args, conn: sqlite3.Connection):
    if args.email:
        row = conn.execute(
            """
            SELECT s.btcpay_subscriber_id, t.token
            FROM subscribers s
            JOIN tokens t USING (btcpay_subscriber_id)
            WHERE s.email = ? AND t.revoked = 0
            ORDER BY t.created_at DESC LIMIT 1
            """,
            (args.email,),
        ).fetchone()
    else:
        row = conn.execute(
            """
            SELECT s.btcpay_subscriber_id, t.token
            FROM subscribers s
            JOIN tokens t USING (btcpay_subscriber_id)
            WHERE s.nostr_pubkey = ? AND t.revoked = 0
            ORDER BY t.created_at DESC LIMIT 1
            """,
            (args.npub,),
        ).fetchone()

    if not row:
        print("No active subscription found.")
        return
    print(fmt_feed_url(row["token"]))


def cmd_revoke(args, conn: sqlite3.Connection):
    row = conn.execute(
        "SELECT btcpay_subscriber_id, email FROM subscribers "
        "WHERE btcpay_subscriber_id = ?",
        (args.subscriber_id,),
    ).fetchone()

    if not row:
        print(f"Subscriber {args.subscriber_id} not found.")
        return

    if not args.yes:
        confirm = input(
            f"Revoke all tokens for {row['email'] or args.subscriber_id}? [y/N] "
        )
        if confirm.lower() != "y":
            print("Aborted.")
            return

    conn.execute(
        "UPDATE tokens SET revoked = 1 WHERE btcpay_subscriber_id = ?",
        (args.subscriber_id,),
    )
    conn.commit()
    print(f"Tokens revoked for {args.subscriber_id}.")


def cmd_stats(args, conn: sqlite3.Connection):
    now = datetime.now(timezone.utc).isoformat()
    total = conn.execute("SELECT COUNT(*) FROM subscribers").fetchone()[0]
    active = conn.execute(
        "SELECT COUNT(*) FROM tokens WHERE revoked = 0 AND expires_at > ?",
        (now,),
    ).fetchone()[0]
    never_accessed = conn.execute(
        "SELECT COUNT(*) FROM tokens WHERE revoked = 0 AND last_used_at IS NULL",
    ).fetchone()[0]
    expired_pending = conn.execute(
        "SELECT COUNT(*) FROM tokens "
        "WHERE revoked = 0 AND expires_at < ? AND expiry_notified_at IS NULL",
        (now,),
    ).fetchone()[0]

    print(f"  Total subscribers:      {total}")
    print(f"  Active tokens:          {active}")
    print(f"  Never accessed feed:    {never_accessed}")
    print(f"  Expired (unnotified):   {expired_pending}")


def cmd_cleanup(args, conn: sqlite3.Connection):
    if not ADMIN_TOKEN:
        print("Error: ADMIN_TOKEN not set.", file=sys.stderr)
        sys.exit(1)

    url = f"{SERVICE_URL}/admin/cleanup"
    req = urllib.request.Request(
        url, method="POST",
        headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            print(f"Cleanup complete: {resp.read().decode()}")
    except urllib.error.HTTPError as e:
        print(f"Error: {e.code} {e.reason}", file=sys.stderr)
        sys.exit(1)
    except urllib.error.URLError as e:
        print(f"Error connecting to {url}: {e.reason}", file=sys.stderr)
        sys.exit(1)


def cmd_test_webhook(args, conn: sqlite3.Connection):
    """
    End-to-end validation of the running token service.

    Stages:
      1. Health endpoint
      2. Metrics endpoint with bearer auth
      3. Signed SubscriptionCreated webhook
      4. Token creation and feed proxy
      5. Expiry episode injection and 402 (--run-expiry-test)
    """
    try:
        import requests as req_lib
    except ImportError:
        print("Error: 'requests' package required.", file=sys.stderr)
        sys.exit(1)

    service = args.service_url.rstrip("/")
    secret  = args.webhook_secret
    passed  = 0
    failed  = 0

    def ok(msg):
        nonlocal passed
        passed += 1
        print(f"  \u2713 {msg}")

    def fail(msg):
        nonlocal failed
        failed += 1
        print(f"  \u2717 {msg}")

    def section(title):
        print(f"\n{title}")
        print("\u2500" * len(title))

    # Stage 1: Health
    section("Stage 1: Health check")
    try:
        r = req_lib.get(f"{service}/health", timeout=5)
        if r.status_code == 200 and r.json().get("status") == "ok":
            ok("Health endpoint returned ok")
        else:
            fail(f"Health returned {r.status_code}: {r.text}")
            print("\nAborted — service unreachable.")
            sys.exit(1)
    except Exception as e:
        fail(f"Could not reach service: {e}")
        sys.exit(1)

    # Stage 2: Metrics
    section("Stage 2: Metrics endpoint")
    if not ADMIN_TOKEN:
        fail("ADMIN_TOKEN not set — skipping")
    else:
        try:
            r = req_lib.get(
                f"{service}/metrics",
                headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
                timeout=5,
            )
            if r.status_code == 200 and "podcast_active_tokens" in r.text:
                ok("Metrics returned Prometheus data")
            else:
                fail(f"Metrics returned {r.status_code}")

            r2 = req_lib.get(f"{service}/metrics", timeout=5)
            if r2.status_code == 401:
                ok("Unauthenticated request correctly rejected (401)")
            else:
                fail(f"Unauthenticated request returned {r2.status_code}, expected 401")
        except Exception as e:
            fail(f"Metrics check failed: {e}")

    # Stage 3: Webhook
    section("Stage 3: Webhook")
    subscriber_id = f"test-{int(time.time())}"
    test_npub     = args.npub or None
    test_email    = args.email or None

    payload = json.dumps({
        "type": "SubscriptionCreated",
        "subscriberId": subscriber_id,
        "email": test_email,
        "subscription": {"expiresAt": 9999999999},
        "metadata": {"nostrPubkey": test_npub} if test_npub else {},
    })
    sig = "sha256=" + hmac.new(
        secret.encode(), payload.encode(), hashlib.sha256
    ).hexdigest()

    try:
        r = req_lib.post(
            f"{service}/webhook/btcpay",
            data=payload,
            headers={
                "Content-Type": "application/json",
                "BTCPay-Sig": sig,
            },
            timeout=10,
        )
        if r.status_code == 200 and r.json().get("status") == "ok":
            ok(f"Webhook accepted for subscriber {subscriber_id}")
        else:
            fail(f"Webhook returned {r.status_code}: {r.text}")
            sys.exit(1)
    except Exception as e:
        fail(f"Webhook failed: {e}")
        sys.exit(1)

    # Stage 4: Token and feed
    section("Stage 4: Token and feed")
    time.sleep(0.5)

    lookup_field = "email" if test_email else "nostr_pubkey"
    lookup_value = test_email or test_npub
    row = conn.execute(
        f"SELECT t.token FROM tokens t "
        f"JOIN subscribers s USING (btcpay_subscriber_id) "
        f"WHERE s.{lookup_field} = ? AND t.revoked = 0 "
        f"ORDER BY t.created_at DESC LIMIT 1",
        (lookup_value,),
    ).fetchone()

    if not row:
        fail("Token not found in database after webhook")
        sys.exit(1)

    token    = row["token"]
    feed_url = f"{service}/rss/{token}.xml"
    ok(f"Token created: ...{token[-12:]}")
    print(f"  Feed URL: {feed_url}")

    try:
        r = req_lib.get(feed_url, timeout=10)
        if r.status_code == 200 and (
            "<channel>" in r.text or "rss" in r.text.lower()
        ):
            ok("Feed URL returns valid RSS content")
        elif r.status_code == 502:
            fail(
                "Feed returned 502 — upstream unreachable. "
                "Check PODSERVER_FEED_URL. "
                "Sample feeds: https://podcastindex.org/"
            )
        else:
            fail(f"Feed returned {r.status_code}")
    except Exception as e:
        fail(f"Feed request failed: {e}")

    if args.feed_url:
        try:
            r = req_lib.get(args.feed_url, timeout=10)
            if r.status_code == 200 and "<item>" in r.text:
                ok(f"Upstream feed is valid RSS")
            else:
                fail(f"Upstream feed at {args.feed_url} did not look like RSS")
        except Exception as e:
            fail(f"Could not fetch upstream feed: {e}")

    # Stage 5: Expiry flow
    if args.run_expiry_test:
        section("Stage 5: Expiry flow")

        conn.execute(
            "UPDATE tokens SET expires_at = '2020-01-01T00:00:00+00:00' "
            "WHERE token = ?",
            (token,),
        )
        conn.commit()
        ok("Token expired in database")

        try:
            r = req_lib.get(feed_url, timeout=10)
            if r.status_code == 200 and "Your subscription has expired" in r.text:
                ok("First fetch: 200 with expiry episode injected")
            elif r.status_code == 200:
                fail("First fetch: 200 but expiry episode not found in feed")
            else:
                fail(f"First fetch: {r.status_code}, expected 200")
        except Exception as e:
            fail(f"First expiry fetch failed: {e}")

        try:
            r = req_lib.get(feed_url, timeout=10)
            if r.status_code == 402:
                ok("Second fetch: 402 Payment Required")
            else:
                fail(f"Second fetch: {r.status_code}, expected 402")
        except Exception as e:
            fail(f"Second expiry fetch failed: {e}")

        conn.execute(
            "UPDATE tokens SET expires_at = ?, expiry_notified_at = NULL "
            "WHERE token = ?",
            (
                (datetime.now(timezone.utc) + timedelta(days=30)).isoformat(),
                token,
            ),
        )
        conn.commit()
        ok("Token restored to active state")

    # Summary
    print(f"\n{'─' * 40}")
    print(f"  Passed: {passed}  Failed: {failed}")
    if failed:
        print("  Some checks failed — review output above")
        sys.exit(1)
    else:
        print("  All checks passed")


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="podcast-members-manage",
        description=textwrap.dedent("""\
            Management and testing CLI for the podcast token service.

            Podman example (Umbrel VPS):
              podman exec podcast-token-service \\
                podcast-members-manage \\
                --db /var/lib/podcast-token-service/tokens.db \\
                stats

            NixOS example:
              podcast-members-manage stats
        """),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--db", default=DEFAULT_DB, metavar="PATH",
        help=f"Path to SQLite database (default: {DEFAULT_DB})",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    # subscribers
    p_subs = sub.add_parser("subscribers", help="List subscribers")
    g      = p_subs.add_mutually_exclusive_group()
    g.add_argument("--active", action="store_true",
                   help="Only active subscribers")
    g.add_argument("--never-accessed", action="store_true",
                   help="Never accessed their feed")
    g.add_argument("--expiring-days", type=int, metavar="N",
                   help="Expiring within N days")

    # feed-url
    p_url = sub.add_parser("feed-url", help="Look up a subscriber's feed URL")
    g2    = p_url.add_mutually_exclusive_group(required=True)
    g2.add_argument("--email", help="Subscriber email")
    g2.add_argument("--npub",  help="Subscriber Nostr npub or hex pubkey")

    # revoke
    p_rev = sub.add_parser("revoke", help="Revoke all tokens for a subscriber")
    p_rev.add_argument("subscriber_id", help="BTCPay subscriber ID")
    p_rev.add_argument("--yes", "-y", action="store_true",
                       help="Skip confirmation")

    # stats
    sub.add_parser("stats", help="Subscriber and token summary")

    # cleanup
    sub.add_parser("cleanup", help="Remove old expired tokens via API")

    # test-webhook
    p_test = sub.add_parser(
        "test-webhook",
        help="End-to-end validation of the token service",
        description=textwrap.dedent("""\
            Validates the full token service flow without needing BTCPay or
            a real Lightning node. Requires a running token service container
            with a volume-mounted database.

            Start the container with a real RSS feed as PODSERVER_FEED_URL.
            Sample feeds can be found at https://podcastindex.org/

            Example:
              podcast-members-manage \\
                --db ./data/tokens.db \\
                test-webhook \\
                --webhook-secret testsecret \\
                --npub <hex-pubkey> \\
                --feed-url https://feeds.npr.org/500005/podcast.xml \\
                --run-expiry-test
        """),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p_test.add_argument("--service-url", default=SERVICE_URL,
                        help=f"Token service URL (default: {SERVICE_URL})")
    p_test.add_argument("--webhook-secret", required=True,
                        help="BTCPAY_WEBHOOK_SECRET from container config")
    g3 = p_test.add_mutually_exclusive_group(required=True)
    g3.add_argument("--npub",  help="Nostr npub or hex pubkey for test subscriber")
    g3.add_argument("--email", help="Email for test subscriber")
    p_test.add_argument(
        "--feed-url", metavar="URL",
        help=(
            "URL of a real podcast RSS feed used as PODSERVER_FEED_URL. "
            "Validates the proxy returns genuine podcast content. "
            "Sample feeds: https://podcastindex.org/"
        ),
    )
    p_test.add_argument(
        "--run-expiry-test", action="store_true",
        help="Also test expiry episode injection and 402 flow",
    )

    return parser


def main():
    parser = build_parser()
    args   = parser.parse_args()

    if not os.path.exists(args.db):
        print(
            f"Error: database not found at {args.db}\n"
            "Start the token service with DATABASE_PATH and a volume mount, "
            "then re-run.",
            file=sys.stderr,
        )
        sys.exit(1)

    conn = get_db(args.db)
    try:
        {
            "subscribers":  cmd_subscribers,
            "feed-url":     cmd_feed_url,
            "revoke":       cmd_revoke,
            "stats":        cmd_stats,
            "cleanup":      cmd_cleanup,
            "test-webhook": cmd_test_webhook,
        }[args.command](args, conn)
    finally:
        conn.close()


if __name__ == "__main__":
    main()
