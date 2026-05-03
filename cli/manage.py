#!/usr/bin/env python3
"""
podcast-members-manage — management CLI for the podcast token service.

Wraps common SQLite queries and admin API calls so you do not need to
write raw SQL for routine operations.

Usage:
  podcast-members-manage [--db PATH] <command> [options]

Environment:
  DATABASE_PATH   path to the SQLite database (overridden by --db)
  FEED_BASE_URL   used to construct feed URLs in output
  ADMIN_TOKEN     bearer token for API calls (cleanup command)
  SERVICE_URL     base URL of the token service (default: http://127.0.0.1:8765)

Podman example (Path A — Umbrel VPS):
  podman exec podcast-token-service \
    podcast-members-manage --db /var/lib/podcast-token-service/tokens.db \
    subscribers --active

NixOS example (Path B):
  podcast-members-manage subscribers --active
"""

from __future__ import annotations

import argparse
import os
import sqlite3
import sys
import textwrap
import urllib.request
import urllib.error
from datetime import datetime, timezone
from typing import Optional


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DEFAULT_DB   = os.environ.get(
    "DATABASE_PATH", "/var/lib/podcast-token-service/tokens.db"
)
FEED_BASE    = os.environ.get("FEED_BASE_URL", "").rstrip("/")
ADMIN_TOKEN  = os.environ.get("ADMIN_TOKEN", "")
SERVICE_URL  = os.environ.get(
    "SERVICE_URL", "http://127.0.0.1:8765"
).rstrip("/")


# ---------------------------------------------------------------------------
# Database helpers
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
        dt = datetime.fromisoformat(iso)
        return dt.strftime("%Y-%m-%d %H:%M UTC")
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
    """List subscribers, optionally filtered by status."""
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
        future = datetime.now(timezone.utc)
        from datetime import timedelta
        cutoff = (
            future + timedelta(days=args.expiring_days)
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
        print("No subscribers found matching criteria.")
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
    """Look up and print the feed URL for a subscriber by email or npub."""
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
    elif args.npub:
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
    else:
        print("Error: provide --email or --npub", file=sys.stderr)
        sys.exit(1)

    if not row:
        print("No active subscription found.")
        return

    print(fmt_feed_url(row["token"]))


def cmd_revoke(args, conn: sqlite3.Connection):
    """Revoke all tokens for a subscriber."""
    row = conn.execute(
        "SELECT btcpay_subscriber_id, email FROM subscribers WHERE btcpay_subscriber_id = ?",
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
    """Print a summary of subscriber and token counts."""
    now = datetime.now(timezone.utc).isoformat()

    total = conn.execute(
        "SELECT COUNT(*) FROM subscribers"
    ).fetchone()[0]
    active = conn.execute(
        "SELECT COUNT(*) FROM tokens WHERE revoked = 0 AND expires_at > ?",
        (now,),
    ).fetchone()[0]
    never_accessed = conn.execute(
        "SELECT COUNT(*) FROM tokens WHERE revoked = 0 AND last_used_at IS NULL",
    ).fetchone()[0]
    expired_pending = conn.execute(
        """
        SELECT COUNT(*) FROM tokens
        WHERE revoked = 0 AND expires_at < ? AND expiry_notified_at IS NULL
        """,
        (now,),
    ).fetchone()[0]

    print(f"  Total subscribers:      {total}")
    print(f"  Active tokens:          {active}")
    print(f"  Never accessed feed:    {never_accessed}")
    print(f"  Expired (unnotified):   {expired_pending}")


def cmd_cleanup(args, conn: sqlite3.Connection):
    """
    Call the token service /admin/cleanup endpoint to remove old tokens.
    Requires ADMIN_TOKEN and SERVICE_URL to be set.
    """
    if not ADMIN_TOKEN:
        print(
            "Error: ADMIN_TOKEN environment variable not set.",
            file=sys.stderr,
        )
        sys.exit(1)

    url = f"{SERVICE_URL}/admin/cleanup"
    req = urllib.request.Request(
        url,
        method="POST",
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


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="podcast-members-manage",
        description=textwrap.dedent("""\
            Management CLI for the podcast token service.

            Podman example (Umbrel VPS):
              podman exec podcast-token-service \\
                podcast-members-manage subscribers --active

            NixOS example:
              podcast-members-manage stats
        """),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--db",
        default=DEFAULT_DB,
        metavar="PATH",
        help=f"Path to SQLite database (default: {DEFAULT_DB})",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    # subscribers
    p_subs = sub.add_parser("subscribers", help="List subscribers")
    group  = p_subs.add_mutually_exclusive_group()
    group.add_argument(
        "--active", action="store_true",
        help="Only show subscribers with a valid active token",
    )
    group.add_argument(
        "--never-accessed", action="store_true",
        help="Only show subscribers who have never accessed their feed",
    )
    group.add_argument(
        "--expiring-days", type=int, metavar="N",
        help="Only show subscribers expiring within N days",
    )

    # feed-url
    p_url = sub.add_parser(
        "feed-url", help="Look up a subscriber's feed URL"
    )
    id_group = p_url.add_mutually_exclusive_group(required=True)
    id_group.add_argument("--email", help="Subscriber email address")
    id_group.add_argument("--npub", help="Subscriber Nostr npub")

    # revoke
    p_rev = sub.add_parser(
        "revoke", help="Revoke all tokens for a subscriber"
    )
    p_rev.add_argument("subscriber_id", help="BTCPay subscriber ID")
    p_rev.add_argument(
        "--yes", "-y", action="store_true",
        help="Skip confirmation prompt",
    )

    # stats
    sub.add_parser("stats", help="Print subscriber and token summary")

    # cleanup
    sub.add_parser(
        "cleanup",
        help="Call /admin/cleanup to remove old expired tokens",
    )

    return parser


def main():
    parser = build_parser()
    args   = parser.parse_args()
    conn   = get_db(args.db)

    try:
        {
            "subscribers":  cmd_subscribers,
            "feed-url":     cmd_feed_url,
            "revoke":       cmd_revoke,
            "stats":        cmd_stats,
            "cleanup":      cmd_cleanup,
        }[args.command](args, conn)
    finally:
        conn.close()


if __name__ == "__main__":
    main()
