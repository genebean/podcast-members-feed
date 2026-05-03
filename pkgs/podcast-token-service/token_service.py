"""
Podcast members feed token service.
Bridges BTCPay Server subscriptions to private RSS feed access.

Classes:
  Secp256k1           - libsecp256k1 bindings via ctypes
  Bech32              - Pure-Python bech32 encode/decode (npub/nsec)
  Database            - SQLite token/subscriber store
  BTCPayVerifier      - Webhook HMAC-SHA256 signature verification
  FeedProxy           - Cached proxy for the upstream PodServer members feed
  NostrDM             - NIP-04 encrypted direct message over Nostr relays
  NotificationService - Orchestrates email and Nostr DM delivery
  Metrics             - Prometheus metrics registry

Deploy behind nginx with TLS termination.
Run via uvicorn as a systemd/NixOS service or Podman container.

Environment variables (see .env.example):
  BTCPAY_WEBHOOK_SECRET   shared secret configured in BTCPay webhook settings
  PODSERVER_FEED_URL      internal URL of the PodServer members RSS feed
  FEED_BASE_URL           public base URL for subscriber feed URLs
  DATABASE_PATH           path to SQLite database file
  ADMIN_TOKEN             bearer token for /metrics and /admin/ endpoints
  EXPIRED_AUDIO_URL       public URL of the subscription-expired audio clip
  SMTP_HOST/PORT/USER/PASSWORD/FROM  SMTP credentials (required if no npub)
  NOSTR_PRIVATE_KEY       nsec or hex private key for the service keypair
"""

from __future__ import annotations

import asyncio
import base64
import ctypes
import ctypes.util
import hashlib
import hmac
import json
import logging
import os
import secrets
import smtplib
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from email.mime.text import MIMEText
from typing import Optional

import aiosqlite
import httpx
import uvicorn
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse
from prometheus_client import (
    Counter, Gauge, generate_latest, CONTENT_TYPE_LATEST,
)

load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(docs_url=None, redoc_url=None)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

BTCPAY_WEBHOOK_SECRET = os.environ["BTCPAY_WEBHOOK_SECRET"]
PODSERVER_FEED_URL    = os.environ["PODSERVER_FEED_URL"]
FEED_BASE_URL         = os.environ["FEED_BASE_URL"].rstrip("/")
DATABASE_PATH         = os.environ.get("DATABASE_PATH", "tokens.db")
ADMIN_TOKEN           = os.environ["ADMIN_TOKEN"]
EXPIRED_AUDIO_URL     = os.environ.get("EXPIRED_AUDIO_URL", "")
SMTP_HOST             = os.environ.get("SMTP_HOST", "")
SMTP_PORT             = int(os.environ.get("SMTP_PORT", 587))
SMTP_USER             = os.environ.get("SMTP_USER", "")
SMTP_PASSWORD         = os.environ.get("SMTP_PASSWORD", "")
SMTP_FROM             = os.environ.get("SMTP_FROM", "")
NOSTR_PRIVATE_KEY     = os.environ["NOSTR_PRIVATE_KEY"]

TOKEN_BYTES       = 32
GRACE_PERIOD_DAYS = 3
FEED_CACHE_TTL    = 300  # seconds

NOSTR_RELAYS = [
    "wss://relay.damus.io",
    "wss://relay.nostr.band",
    "wss://nos.lol",
]


# ---------------------------------------------------------------------------
# Prometheus metrics
# ---------------------------------------------------------------------------

class Metrics:
    """
    All service metrics in one place.

    Naming: podcast_<noun>_<unit/total>.
    Labels only where they add alerting or diagnostic value.

    Scrape via GET /metrics with Authorization: Bearer <ADMIN_TOKEN>.
    The endpoint listens on all interfaces since scrapes may come from
    another host (e.g. a Prometheus instance on your monitoring machine).
    """

    active_tokens = Gauge(
        "podcast_active_tokens",
        "Current number of non-revoked non-expired tokens",
    )
    total_subscribers = Gauge(
        "podcast_total_subscribers",
        "Total subscribers ever registered",
    )
    webhooks_total = Counter(
        "podcast_webhooks_total",
        "BTCPay webhook events processed successfully",
        ["event_type"],
    )
    webhook_errors_total = Counter(
        "podcast_webhook_errors_total",
        "BTCPay webhook processing errors",
        ["reason"],  # invalid_signature | missing_subscriber_id | exception
    )
    feed_requests_total = Counter(
        "podcast_feed_requests_total",
        "Feed endpoint requests by result",
        ["result"],  # valid | expired | upstream_error
    )
    feed_upstream_errors_total = Counter(
        "podcast_feed_upstream_errors_total",
        "Failures fetching the upstream PodServer feed",
    )
    expiry_notifications_total = Counter(
        "podcast_expiry_notifications_total",
        "Expired-subscription audio episodes injected into feeds",
    )
    nostr_dm_total = Counter(
        "podcast_nostr_dm_total",
        "Nostr DM delivery attempts by result",
        ["result"],  # success | failure
    )
    nostr_dm_relay_total = Counter(
        "podcast_nostr_dm_relay_total",
        "Nostr relay publish attempts by relay and result",
        ["relay", "result"],  # success | failure | rejected
    )
    email_total = Counter(
        "podcast_email_total",
        "Email delivery attempts by result",
        ["result"],  # success | failure
    )
    nip98_requests_total = Counter(
        "podcast_nip98_requests_total",
        "NIP-98 feed URL retrieval attempts by result",
        ["result"],  # success | not_found | invalid_sig | expired | malformed
    )
    recovery_page_visits_total = Counter(
        "podcast_recovery_page_visits_total",
        "Visits to the /recover page",
    )


metrics = Metrics()


# ---------------------------------------------------------------------------
# libsecp256k1 via ctypes
#
# Direct ctypes bindings avoid Python wrapper packaging issues and give
# precise control over ECDH output. NIP-04 requires the raw x-coordinate
# shared secret; most wrapper libraries return sha256(pubkey) instead.
# ---------------------------------------------------------------------------

class Secp256k1:
    """
    Minimal libsecp256k1 bindings for:
      - Schnorr signing (BIP-340) for NIP-01 event signatures
      - Schnorr verification for NIP-98 auth
      - Raw x-coordinate ECDH for NIP-04 encryption
      - Public key derivation from private key

    NixOS: provided by pkgs.secp256k1, linked by the derivation.
    Debian/Ubuntu: libsecp256k1-dev
    Alpine: secp256k1-dev
    """

    SECP256K1_CONTEXT_SIGN   = 1
    SECP256K1_CONTEXT_VERIFY = 2
    SECP256K1_EC_COMPRESSED  = 258

    def __init__(self):
        import glob
        # ctypes.util.find_library searches standard system paths which are
        # not present in a Nix-built container. Try several strategies:
        #   1. LIBSECP256K1_PATH env var (explicit override, always wins)
        #   2. find_library (works on standard Linux systems)
        #   3. Glob the Nix store directly (works in Nix-built containers)
        lib_path = os.environ.get("LIBSECP256K1_PATH")

        if not lib_path:
            lib_name = ctypes.util.find_library("secp256k1")
            if lib_name:
                lib_path = lib_name

        if not lib_path:
            candidates = sorted(
                glob.glob("/nix/store/*secp256k1*/lib/libsecp256k1.so*")
            )
            if candidates:
                lib_path = candidates[-1]

        if not lib_path:
            raise RuntimeError(
                "libsecp256k1 not found. "
                "NixOS: pkgs.secp256k1 | Debian/Ubuntu: libsecp256k1-dev | "
                "Alpine: secp256k1-dev | "
                "Override: set LIBSECP256K1_PATH=/path/to/libsecp256k1.so"
            )
        self._lib = ctypes.CDLL(lib_path)
        self._ctx = self._lib.secp256k1_context_create(
            self.SECP256K1_CONTEXT_SIGN | self.SECP256K1_CONTEXT_VERIFY
        )
        self._lib.secp256k1_context_randomize(
            self._ctx, ctypes.c_char_p(os.urandom(32))
        )

    def derive_pubkey(self, privkey: bytes) -> bytes:
        """Return 32-byte x-only public key from 32-byte private key."""
        pubkey_buf = ctypes.create_string_buffer(64)
        if not self._lib.secp256k1_ec_pubkey_create(
            self._ctx, pubkey_buf, ctypes.c_char_p(privkey)
        ):
            raise ValueError("Invalid private key")
        output     = ctypes.create_string_buffer(33)
        output_len = ctypes.c_size_t(33)
        self._lib.secp256k1_ec_pubkey_serialize(
            self._ctx, output, ctypes.byref(output_len),
            pubkey_buf, self.SECP256K1_EC_COMPRESSED,
        )
        return bytes(output)[1:]  # drop 0x02/0x03 prefix — x-only

    def schnorr_sign(self, msg32: bytes, privkey: bytes) -> bytes:
        """BIP-340 Schnorr sign. msg32 must be exactly 32 bytes."""
        sig = ctypes.create_string_buffer(64)
        if not self._lib.secp256k1_schnorrsig_sign32(
            self._ctx, sig,
            ctypes.c_char_p(msg32),
            ctypes.c_char_p(privkey),
            ctypes.c_char_p(os.urandom(32)),
        ):
            raise ValueError("Schnorr signing failed")
        return bytes(sig)

    def schnorr_verify(
        self, msg32: bytes, sig64: bytes, pubkey32: bytes
    ) -> bool:
        """Verify a BIP-340 Schnorr signature. Returns True if valid."""
        xonly_buf = ctypes.create_string_buffer(64)
        if not self._lib.secp256k1_xonly_pubkey_parse(
            self._ctx, xonly_buf, ctypes.c_char_p(pubkey32)
        ):
            return False
        return bool(self._lib.secp256k1_schnorrsig_verify(
            self._ctx,
            ctypes.c_char_p(sig64),
            ctypes.c_char_p(msg32),
            ctypes.c_size_t(32),
            xonly_buf,
        ))

    def ecdh_x_only(self, privkey: bytes, compressed_pubkey: bytes) -> bytes:
        """
        ECDH shared secret — raw x-coordinate only (32 bytes).
        NIP-04 requires the x-coordinate directly, not sha256(pubkey).
        """
        pubkey_buf = ctypes.create_string_buffer(64)
        if not self._lib.secp256k1_ec_pubkey_parse(
            self._ctx, pubkey_buf,
            ctypes.c_char_p(compressed_pubkey),
            ctypes.c_size_t(len(compressed_pubkey)),
        ):
            raise ValueError("Failed to parse recipient public key")

        HASHFP = ctypes.CFUNCTYPE(
            ctypes.c_int,
            ctypes.c_char_p, ctypes.c_char_p,
            ctypes.c_char_p, ctypes.c_void_p,
        )

        def _x_only(output, x32, y32, _data):
            ctypes.memmove(output, x32, 32)
            return 1

        result = ctypes.create_string_buffer(32)
        if not self._lib.secp256k1_ecdh(
            self._ctx, result, pubkey_buf,
            ctypes.c_char_p(privkey),
            HASHFP(_x_only), None,
        ):
            raise ValueError("ECDH failed")
        return bytes(result)


# ---------------------------------------------------------------------------
# Bech32 — pure Python, no external dependencies
# ---------------------------------------------------------------------------

class Bech32:
    """
    Bech32 encode/decode for Nostr npub and nsec keys (BIP-173).
    Nostr uses original bech32, not bech32m.
    """

    CHARSET   = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    GENERATOR = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]

    @classmethod
    def _polymod(cls, values):
        chk = 1
        for v in values:
            b    = chk >> 25
            chk  = (chk & 0x1FFFFFF) << 5 ^ v
            for i in range(5):
                chk ^= cls.GENERATOR[i] if ((b >> i) & 1) else 0
        return chk

    @classmethod
    def _hrp_expand(cls, hrp):
        return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

    @classmethod
    def _verify_checksum(cls, hrp, data):
        return cls._polymod(cls._hrp_expand(hrp) + data) == 1

    @classmethod
    def _create_checksum(cls, hrp, data):
        values  = cls._hrp_expand(hrp) + data
        p       = cls._polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
        return [(p >> 5 * (5 - i)) & 31 for i in range(6)]

    @classmethod
    def _convertbits(cls, data, frombits, tobits, pad=True):
        acc, bits, result = 0, 0, []
        maxv = (1 << tobits) - 1
        for value in data:
            acc   = ((acc << frombits) | value) & 0xFFFFFFFF
            bits += frombits
            while bits >= tobits:
                bits -= tobits
                result.append((acc >> bits) & maxv)
        if pad:
            if bits:
                result.append((acc << (tobits - bits)) & maxv)
        elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
            raise ValueError("Invalid bech32 padding")
        return result

    @classmethod
    def decode(cls, bech):
        bech = bech.lower()
        pos  = bech.rfind("1")
        if pos < 1 or pos + 7 > len(bech):
            raise ValueError("Invalid bech32 string")
        hrp  = bech[:pos]
        data = [cls.CHARSET.find(c) for c in bech[pos + 1:]]
        if any(d == -1 for d in data):
            raise ValueError("Invalid bech32 character")
        if not cls._verify_checksum(hrp, data):
            raise ValueError("Invalid bech32 checksum")
        return hrp, bytes(cls._convertbits(data[:-6], 5, 8, False))

    @classmethod
    def encode(cls, hrp, data):
        converted = cls._convertbits(data, 8, 5)
        checksum  = cls._create_checksum(hrp, converted)
        return hrp + "1" + "".join(
            cls.CHARSET[d] for d in converted + checksum
        )

    @classmethod
    def npub_to_hex(cls, npub):
        hrp, data = cls.decode(npub)
        if hrp != "npub":
            raise ValueError(f"Expected npub, got {hrp}")
        return data.hex()

    @classmethod
    def nsec_to_hex(cls, nsec):
        hrp, data = cls.decode(nsec)
        if hrp != "nsec":
            raise ValueError(f"Expected nsec, got {hrp}")
        return data.hex()

    @classmethod
    def hex_to_npub(cls, hex_key):
        return cls.encode("npub", bytes.fromhex(hex_key))

    @classmethod
    def hex_to_nsec(cls, hex_key):
        return cls.encode("nsec", bytes.fromhex(hex_key))


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

class Database:
    """
    SQLite store for subscribers and feed tokens.

    Schema note: email and nostr_pubkey are both nullable but the CHECK
    constraint enforces that at least one must be present. This allows
    Nostr-only subscribers who do not wish to provide an email address.

    expiry_notified_at records when the one-time expiry audio episode
    was served. Once set, subsequent requests for that token return 402.
    """

    def __init__(self, path: str):
        self.path = path
        self._db: Optional[aiosqlite.Connection] = None

    async def connect(self):
        self._db = await aiosqlite.connect(self.path)
        self._db.row_factory = aiosqlite.Row
        await self._db.executescript("""
            CREATE TABLE IF NOT EXISTS subscribers (
                btcpay_subscriber_id  TEXT PRIMARY KEY,
                email                 TEXT,
                nostr_pubkey          TEXT,
                created_at            TEXT NOT NULL,
                CHECK (email IS NOT NULL OR nostr_pubkey IS NOT NULL)
            );

            CREATE TABLE IF NOT EXISTS tokens (
                token                 TEXT PRIMARY KEY,
                btcpay_subscriber_id  TEXT NOT NULL,
                expires_at            TEXT NOT NULL,
                created_at            TEXT NOT NULL,
                last_used_at          TEXT,
                revoked               INTEGER NOT NULL DEFAULT 0,
                expiry_notified_at    TEXT,
                FOREIGN KEY (btcpay_subscriber_id)
                    REFERENCES subscribers(btcpay_subscriber_id)
            );

            CREATE INDEX IF NOT EXISTS idx_tokens_subscriber
                ON tokens(btcpay_subscriber_id);
        """)
        await self._db.commit()

    async def close(self):
        if self._db:
            await self._db.close()

    async def upsert_subscriber(
        self,
        btcpay_subscriber_id: str,
        email: Optional[str],
        nostr_pubkey: Optional[str] = None,
    ):
        if not email and not nostr_pubkey:
            raise ValueError("Subscriber must provide email or Nostr npub")
        await self._db.execute(
            """
            INSERT INTO subscribers
                (btcpay_subscriber_id, email, nostr_pubkey, created_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(btcpay_subscriber_id) DO UPDATE SET
                email        = COALESCE(excluded.email, email),
                nostr_pubkey = COALESCE(excluded.nostr_pubkey, nostr_pubkey)
            """,
            (btcpay_subscriber_id, email, nostr_pubkey, _now()),
        )
        await self._db.commit()

    async def create_token(
        self, btcpay_subscriber_id: str, expires_at: datetime
    ) -> str:
        token = secrets.token_urlsafe(TOKEN_BYTES)
        await self._db.execute(
            """
            INSERT INTO tokens
                (token, btcpay_subscriber_id, expires_at, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (token, btcpay_subscriber_id, expires_at.isoformat(), _now()),
        )
        await self._db.commit()
        return token

    async def get_active_token(
        self, btcpay_subscriber_id: str
    ) -> Optional[str]:
        async with self._db.execute(
            """
            SELECT token FROM tokens
            WHERE btcpay_subscriber_id = ? AND revoked = 0
            ORDER BY created_at DESC LIMIT 1
            """,
            (btcpay_subscriber_id,),
        ) as cur:
            row = await cur.fetchone()
            return row["token"] if row else None

    async def extend_token(
        self, btcpay_subscriber_id: str, new_expires_at: datetime
    ):
        """
        Extend expiry on the active token — never issue a new URL on
        renewal, which would silently break the subscriber's podcast app.
        Also clears expiry_notified_at so a renewed token works cleanly.
        """
        await self._db.execute(
            """
            UPDATE tokens SET expires_at = ?, expiry_notified_at = NULL
            WHERE btcpay_subscriber_id = ?
              AND revoked = 0
              AND token = (
                SELECT token FROM tokens
                WHERE btcpay_subscriber_id = ? AND revoked = 0
                ORDER BY created_at DESC LIMIT 1
              )
            """,
            (new_expires_at.isoformat(),
             btcpay_subscriber_id,
             btcpay_subscriber_id),
        )
        await self._db.commit()

    async def revoke_tokens(self, btcpay_subscriber_id: str):
        await self._db.execute(
            "UPDATE tokens SET revoked = 1 WHERE btcpay_subscriber_id = ?",
            (btcpay_subscriber_id,),
        )
        await self._db.commit()

    async def validate_token(self, token: str) -> Optional[aiosqlite.Row]:
        """
        Look up a non-revoked token regardless of expiry, so the feed
        endpoint can decide whether to inject the expiry notice episode.
        Returns None only for unknown or revoked tokens.
        Updates last_used_at as a side effect.
        """
        async with self._db.execute(
            """
            SELECT t.*, s.email, s.nostr_pubkey
            FROM tokens t
            JOIN subscribers s USING (btcpay_subscriber_id)
            WHERE t.token = ? AND t.revoked = 0
            """,
            (token,),
        ) as cur:
            row = await cur.fetchone()

        if row:
            await self._db.execute(
                "UPDATE tokens SET last_used_at = ? WHERE token = ?",
                (_now(), token),
            )
            await self._db.commit()

        return row

    async def mark_expiry_notified(self, token: str):
        await self._db.execute(
            "UPDATE tokens SET expiry_notified_at = ? WHERE token = ?",
            (_now(), token),
        )
        await self._db.commit()

    async def cleanup_expired(self):
        """Remove tokens revoked or expired more than 90 days ago."""
        cutoff = (
            datetime.now(timezone.utc) - timedelta(days=90)
        ).isoformat()
        result = await self._db.execute(
            "DELETE FROM tokens WHERE revoked = 1 OR expires_at < ?",
            (cutoff,),
        )
        await self._db.commit()
        logger.info(f"Cleanup: removed {result.rowcount} expired tokens")

    async def subscriber_stats(self) -> dict:
        async with self._db.execute(
            "SELECT COUNT(*) as total FROM subscribers"
        ) as cur:
            total = (await cur.fetchone())["total"]
        cutoff = datetime.now(timezone.utc).isoformat()
        async with self._db.execute(
            """
            SELECT COUNT(*) as active FROM tokens
            WHERE revoked = 0 AND expires_at > ?
            """,
            (cutoff,),
        ) as cur:
            active = (await cur.fetchone())["active"]
        return {"total_subscribers": total, "active_tokens": active}

    async def get_token_for_pubkey(self, pubkey_hex: str) -> Optional[str]:
        cutoff = datetime.now(timezone.utc).isoformat()
        async with self._db.execute(
            """
            SELECT t.token FROM tokens t
            JOIN subscribers s USING (btcpay_subscriber_id)
            WHERE s.nostr_pubkey = ?
              AND t.revoked = 0
              AND t.expires_at > ?
            ORDER BY t.created_at DESC LIMIT 1
            """,
            (pubkey_hex, cutoff),
        ) as cur:
            row = await cur.fetchone()
            return row["token"] if row else None

    async def update_gauges(self):
        """Refresh Prometheus gauges from current database state."""
        stats = await self.subscriber_stats()
        metrics.active_tokens.set(stats["active_tokens"])
        metrics.total_subscribers.set(stats["total_subscribers"])


# ---------------------------------------------------------------------------
# BTCPay webhook verification
# ---------------------------------------------------------------------------

class BTCPayVerifier:
    """
    Verifies BTCPay Server HMAC-SHA256 webhook signatures.
    Signature is in the BTCPay-Sig header as "sha256=<hex>".
    """

    def __init__(self, secret: str):
        self._secret = secret.encode()

    def verify(self, payload: bytes, sig_header: str) -> bool:
        if not sig_header or not sig_header.startswith("sha256="):
            return False
        expected = hmac.new(
            self._secret, payload, hashlib.sha256
        ).hexdigest()
        provided = sig_header.removeprefix("sha256=")
        return hmac.compare_digest(expected, provided)


# ---------------------------------------------------------------------------
# Feed proxy
# ---------------------------------------------------------------------------

class FeedProxy:
    """
    Fetches and caches the upstream PodServer RSS feed.

    fetch_raw()              — returns the feed as-is for valid tokens
    fetch_with_expiry_notice() — injects a synthetic expiry episode first
    """

    def __init__(self, feed_url: str):
        self._url        = feed_url
        self._cache: Optional[bytes]         = None
        self._cache_time: Optional[datetime] = None

    async def fetch_raw(self) -> bytes:
        now = datetime.now(timezone.utc)
        if (
            self._cache is not None
            and self._cache_time is not None
            and (now - self._cache_time).seconds < FEED_CACHE_TTL
        ):
            return self._cache
        async with httpx.AsyncClient() as client:
            resp = await client.get(self._url, timeout=10)
            resp.raise_for_status()
            self._cache      = resp.content
            self._cache_time = now
            return self._cache

    async def fetch_with_expiry_notice(self) -> bytes:
        """
        Inject a synthetic episode at the top of the feed so the podcast
        app presents an expiry notification as the latest episode. This
        is served once per token; subsequent requests return 402.
        """
        raw     = await self.fetch_raw()
        root    = ET.fromstring(raw)
        channel = root.find("channel")
        if channel is None:
            return raw  # malformed feed — return as-is

        item = ET.Element("item")
        ET.SubElement(item, "title").text = (
            "Your subscription has expired"
        )
        ET.SubElement(item, "description").text = (
            "Your members subscription has expired. "
            "Visit the members page to renew and continue "
            "receiving bonus content."
        )
        ET.SubElement(item, "pubDate").text = (
            datetime.now(timezone.utc)
            .strftime("%a, %d %b %Y %H:%M:%S +0000")
        )
        ET.SubElement(item, "guid", isPermaLink="false").text = (
            f"expired-notice-{int(time.time())}"
        )
        if EXPIRED_AUDIO_URL:
            ET.SubElement(
                item, "enclosure",
                url=EXPIRED_AUDIO_URL,
                type="audio/mpeg",
                length="0",
            )

        first_item = channel.find("item")
        if first_item is not None:
            channel.insert(list(channel).index(first_item), item)
        else:
            channel.append(item)

        return ET.tostring(root, encoding="unicode").encode()


# ---------------------------------------------------------------------------
# Nostr NIP-04 DM
# ---------------------------------------------------------------------------

class NostrDM:
    """
    NIP-04 (kind:4) encrypted direct messages via Nostr relays.

    NIP-04 is used for maximum client compatibility: Damus, Primal,
    Amethyst (NIP-17 mode off), and YakiHonne all support it. NIP-17
    offers better metadata privacy but is not yet universally supported.
    For a one-time feed URL delivery this tradeoff is acceptable.
    """

    def __init__(self, private_key_input: str, secp: Secp256k1):
        self._secp    = secp
        hex_key       = (
            Bech32.nsec_to_hex(private_key_input)
            if private_key_input.startswith("nsec")
            else private_key_input
        )
        self._privkey = bytes.fromhex(hex_key)
        self._pubkey  = secp.derive_pubkey(self._privkey)

    @property
    def pubkey_hex(self) -> str:
        return self._pubkey.hex()

    def _encrypt(self, message: str, recipient_pubkey_hex: str) -> str:
        # Nostr x-only pubkeys always have even parity — prefix with 0x02
        compressed = bytes.fromhex("02" + recipient_pubkey_hex)
        shared     = self._secp.ecdh_x_only(self._privkey, compressed)
        iv         = os.urandom(16)
        padded     = _pkcs7_pad(message.encode(), 16)
        cipher     = Cipher(
            algorithms.AES(shared), modes.CBC(iv),
            backend=default_backend()
        )
        enc        = cipher.encryptor()
        ciphertext = enc.update(padded) + enc.finalize()
        return (
            base64.b64encode(ciphertext).decode()
            + "?iv="
            + base64.b64encode(iv).decode()
        )

    def _build_event(
        self, content: str, recipient_pubkey_hex: str
    ) -> dict:
        event = {
            "pubkey":     self.pubkey_hex,
            "created_at": int(time.time()),
            "kind":       4,
            "tags":       [["p", recipient_pubkey_hex]],
            "content":    content,
        }
        id_bytes   = _event_id_bytes(event)
        event["id"]  = id_bytes.hex()
        event["sig"] = self._secp.schnorr_sign(
            id_bytes, self._privkey
        ).hex()
        return event

    async def send(self, recipient: str, message: str):
        recipient_hex = (
            Bech32.npub_to_hex(recipient)
            if recipient.startswith("npub")
            else recipient
        )
        content = self._encrypt(message, recipient_hex)
        event   = self._build_event(content, recipient_hex)

        results = await asyncio.gather(
            *[self._publish(relay, event) for relay in NOSTR_RELAYS],
            return_exceptions=True,
        )
        successes = sum(1 for r in results if r is True)
        if successes == 0:
            metrics.nostr_dm_total.labels(result="failure").inc()
            raise RuntimeError("DM publish failed on all relays")
        metrics.nostr_dm_total.labels(result="success").inc()
        logger.info(
            f"Nostr DM published to {successes}/{len(NOSTR_RELAYS)} relays"
        )

    async def _publish(self, relay_url: str, event: dict) -> bool:
        import websockets
        try:
            async with websockets.connect(
                relay_url, open_timeout=5
            ) as ws:
                await ws.send(json.dumps(["EVENT", event]))
                async with asyncio.timeout(5):
                    resp = json.loads(await ws.recv())
                    if resp[0] == "OK" and resp[2] is True:
                        metrics.nostr_dm_relay_total.labels(
                            relay=relay_url, result="success"
                        ).inc()
                        return True
                    metrics.nostr_dm_relay_total.labels(
                        relay=relay_url, result="rejected"
                    ).inc()
                    logger.warning(
                        f"Relay {relay_url} rejected: {resp}"
                    )
                    return False
        except Exception as e:
            metrics.nostr_dm_relay_total.labels(
                relay=relay_url, result="failure"
            ).inc()
            logger.warning(f"Relay {relay_url} error: {e}")
            return False


# ---------------------------------------------------------------------------
# Notification service
# ---------------------------------------------------------------------------

@dataclass
class SubscriberInfo:
    feed_url: str
    email: Optional[str]        = None
    nostr_pubkey: Optional[str] = None


class NotificationService:
    """
    Delivers feed URLs via email and/or Nostr DM.

    At least one of email or nostr_pubkey must be present per subscriber.
    Email is used when available. Nostr DM is used when the subscriber
    provided an npub. Both may be used simultaneously.
    """

    def __init__(self, nostr_dm: NostrDM):
        self._nostr = nostr_dm

    async def deliver(self, info: SubscriberInfo):
        tasks = []
        if info.email:
            tasks.append(self._send_email(info))
        if info.nostr_pubkey:
            tasks.append(self._send_nostr_dm(info, expiry_notice=False))
        await asyncio.gather(*tasks)

    async def deliver_expiry_notice(self, info: SubscriberInfo):
        """Nostr DM expiry notification — sent alongside the injected episode."""
        if info.nostr_pubkey:
            await self._send_nostr_dm(info, expiry_notice=True)

    async def _send_email(self, info: SubscriberInfo):
        body = (
            f"Thanks for subscribing!\n\n"
            f"Your private podcast feed URL:\n\n"
            f"  {info.feed_url}\n\n"
            f"Add this to Fountain, Castamatic, or any podcast app "
            f"that accepts a custom RSS feed. Keep it private — "
            f"it is unique to your subscription.\n\n"
            f"If you lose this URL, reply to this email and we will "
            f"resend it."
        )
        if info.nostr_pubkey:
            body += (
                f"\n\nYou can also retrieve it self-service at:\n"
                f"  {FEED_BASE_URL}/recover"
            )
        msg            = MIMEText(body)
        msg["Subject"] = "Your members podcast feed"
        msg["From"]    = SMTP_FROM
        msg["To"]      = info.email
        try:
            await asyncio.to_thread(_smtp_send, msg)
            metrics.email_total.labels(result="success").inc()
        except Exception as e:
            metrics.email_total.labels(result="failure").inc()
            logger.error(f"Email delivery failed to {info.email}: {e}")
            raise

    async def _send_nostr_dm(
        self, info: SubscriberInfo, expiry_notice: bool
    ):
        if expiry_notice:
            message = (
                "Your members podcast subscription has expired.\n\n"
                f"Renew at {FEED_BASE_URL} to continue receiving "
                f"bonus content. Once renewed, your existing feed URL "
                f"will keep working — no changes needed in your app."
            )
        else:
            message = (
                f"Your members podcast feed URL:\n\n"
                f"{info.feed_url}\n\n"
                f"Add this to Fountain, Castamatic, or any podcast app. "
                f"Keep it private — it is unique to your subscription.\n\n"
                f"Retrieve this URL at any time: {FEED_BASE_URL}/recover"
            )
        try:
            await self._nostr.send(info.nostr_pubkey, message)
        except Exception as e:
            # Non-fatal — email was already sent if available
            logger.error(f"Nostr DM failed: {e}")


# ---------------------------------------------------------------------------
# Application setup
# ---------------------------------------------------------------------------

_secp     = Secp256k1()
_nostr_dm = NostrDM(NOSTR_PRIVATE_KEY, _secp)

db       = Database(DATABASE_PATH)
verifier = BTCPayVerifier(BTCPAY_WEBHOOK_SECRET)
proxy    = FeedProxy(PODSERVER_FEED_URL)
notifier = NotificationService(_nostr_dm)


def _require_admin(request: Request):
    """Verify bearer token. Used for /metrics and /admin/ endpoints."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer ") or not hmac.compare_digest(
        auth.removeprefix("Bearer ").strip(), ADMIN_TOKEN
    ):
        raise HTTPException(
            status_code=401,
            detail="Valid bearer token required",
            headers={"WWW-Authenticate": "Bearer"},
        )


@app.on_event("startup")
async def startup():
    await db.connect()
    await db.update_gauges()
    logger.info(
        f"Token service started — "
        f"Nostr pubkey: {Bech32.hex_to_npub(_nostr_dm.pubkey_hex)}"
    )


@app.on_event("shutdown")
async def shutdown():
    await db.close()


# ---------------------------------------------------------------------------
# Webhook handler
# ---------------------------------------------------------------------------

@app.post("/webhook/btcpay")
async def btcpay_webhook(request: Request):
    payload = await request.body()
    sig     = request.headers.get("BTCPay-Sig", "")

    if not verifier.verify(payload, sig):
        metrics.webhook_errors_total.labels(
            reason="invalid_signature"
        ).inc()
        logger.warning("Rejected webhook: invalid signature")
        raise HTTPException(status_code=401, detail="Invalid signature")

    try:
        event         = await request.json()
        event_type    = event.get("type")
        subscriber_id = event.get("subscriberId")
        email         = event.get("email") or None
        subscription  = event.get("subscription", {})
        expires_ts    = subscription.get("expiresAt")
        nostr_pubkey  = event.get("metadata", {}).get("nostrPubkey") or None

        if not subscriber_id:
            metrics.webhook_errors_total.labels(
                reason="missing_subscriber_id"
            ).inc()
            return JSONResponse(
                {"status": "ignored", "reason": "no subscriberId"}
            )

        expires_at = (
            datetime.fromtimestamp(expires_ts, tz=timezone.utc)
            if expires_ts
            else datetime.now(timezone.utc) + timedelta(days=31)
        )

        if event_type == "SubscriptionCreated":
            await db.upsert_subscriber(subscriber_id, email, nostr_pubkey)
            token    = await db.create_token(subscriber_id, expires_at)
            feed_url = f"{FEED_BASE_URL}/rss/{token}.xml"
            await notifier.deliver(SubscriberInfo(
                feed_url=feed_url, email=email, nostr_pubkey=nostr_pubkey
            ))
            metrics.webhooks_total.labels(event_type="created").inc()
            logger.info(f"New subscriber: {subscriber_id}")

        elif event_type == "SubscriptionRenewed":
            existing = await db.get_active_token(subscriber_id)
            if existing:
                await db.extend_token(subscriber_id, expires_at)
                metrics.webhooks_total.labels(event_type="renewed").inc()
                logger.info(f"Renewed: {subscriber_id}")
            else:
                # Lapsed then re-subscribed — issue new token and re-deliver
                await db.upsert_subscriber(subscriber_id, email, nostr_pubkey)
                token    = await db.create_token(subscriber_id, expires_at)
                feed_url = f"{FEED_BASE_URL}/rss/{token}.xml"
                await notifier.deliver(SubscriberInfo(
                    feed_url=feed_url, email=email, nostr_pubkey=nostr_pubkey
                ))
                metrics.webhooks_total.labels(event_type="renewed").inc()
                logger.info(f"Re-subscribed: {subscriber_id}")

        elif event_type in ("SubscriptionExpired", "SubscriptionSuspended"):
            await db.revoke_tokens(subscriber_id)
            label = event_type.lower().removeprefix("subscription")
            metrics.webhooks_total.labels(event_type=label).inc()
            logger.info(f"Revoked: {subscriber_id} ({event_type})")

        await db.update_gauges()

    except ValueError as e:
        metrics.webhook_errors_total.labels(reason="exception").inc()
        logger.error(f"Webhook error: {e}")
        raise HTTPException(status_code=400, detail=str(e))

    return JSONResponse({"status": "ok"})


# ---------------------------------------------------------------------------
# Feed endpoint
# ---------------------------------------------------------------------------

@app.get("/rss/{token}.xml")
async def members_feed(token: str):
    row = await db.validate_token(token)

    if not row:
        metrics.feed_requests_total.labels(result="expired").inc()
        return Response(
            content="Subscription required or expired.",
            status_code=402,
            media_type="text/plain",
        )

    now        = datetime.now(timezone.utc)
    expires_at = datetime.fromisoformat(row["expires_at"])
    is_expired = expires_at < now

    if is_expired:
        if row["expiry_notified_at"]:
            # Expiry episode already served — return 402 from here on
            metrics.feed_requests_total.labels(result="expired").inc()
            return Response(
                content="Subscription expired.",
                status_code=402,
                media_type="text/plain",
            )

        # First request after expiry — inject the expiry notice episode
        try:
            content = await proxy.fetch_with_expiry_notice()
        except Exception as e:
            metrics.feed_upstream_errors_total.inc()
            logger.error(f"Feed fetch failed: {e}")
            raise HTTPException(
                status_code=502, detail="Could not fetch feed"
            )

        await db.mark_expiry_notified(token)
        metrics.expiry_notifications_total.inc()

        # Fire-and-forget Nostr DM if subscriber has a pubkey
        if row["nostr_pubkey"]:
            asyncio.create_task(
                notifier.deliver_expiry_notice(
                    SubscriberInfo(
                        feed_url=f"{FEED_BASE_URL}/rss/{token}.xml",
                        nostr_pubkey=row["nostr_pubkey"],
                    )
                )
            )

        logger.info(f"Expiry notice served: ...{token[-8:]}")
        metrics.feed_requests_total.labels(result="expired").inc()
        return Response(content=content, media_type="application/rss+xml")

    # Valid non-expired token
    try:
        content = await proxy.fetch_raw()
    except Exception as e:
        metrics.feed_upstream_errors_total.inc()
        logger.error(f"Feed fetch failed: {e}")
        raise HTTPException(status_code=502, detail="Could not fetch feed")

    metrics.feed_requests_total.labels(result="valid").inc()
    return Response(content=content, media_type="application/rss+xml")


# ---------------------------------------------------------------------------
# NIP-98 feed URL re-issuance
# ---------------------------------------------------------------------------

@app.get("/api/feed-url")
async def get_feed_url(request: Request):
    """
    Allows a subscriber to retrieve their feed URL without contacting
    support. Called by the /recover page after NIP-07 browser signing.

    NIP-98 verification:
      1. Decode base64 event JSON from Authorization: Nostr <b64>
      2. kind == 27235
      3. created_at within 60 seconds (replay prevention)
      4. 'u' tag matches this endpoint URL
      5. 'method' tag is GET
      6. Schnorr signature is valid
      7. Look up active subscription by pubkey
    """
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Nostr "):
        metrics.nip98_requests_total.labels(result="malformed").inc()
        raise HTTPException(status_code=401, detail="NIP-98 auth required")

    try:
        event = json.loads(
            base64.b64decode(auth.removeprefix("Nostr "))
        )
    except Exception:
        metrics.nip98_requests_total.labels(result="malformed").inc()
        raise HTTPException(status_code=401, detail="Invalid NIP-98 token")

    if event.get("kind") != 27235:
        metrics.nip98_requests_total.labels(result="malformed").inc()
        raise HTTPException(status_code=401, detail="Invalid event kind")

    if abs(time.time() - event.get("created_at", 0)) > 60:
        metrics.nip98_requests_total.labels(result="expired").inc()
        raise HTTPException(
            status_code=401, detail="Event timestamp expired"
        )

    tags = {t[0]: t[1] for t in event.get("tags", []) if len(t) >= 2}
    if tags.get("method") != "GET":
        metrics.nip98_requests_total.labels(result="malformed").inc()
        raise HTTPException(status_code=401, detail="Method mismatch")

    pubkey = event.get("pubkey", "")
    if not pubkey:
        metrics.nip98_requests_total.labels(result="malformed").inc()
        raise HTTPException(status_code=401, detail="Missing pubkey")

    try:
        if not _secp.schnorr_verify(
            bytes.fromhex(event["id"]),
            bytes.fromhex(event["sig"]),
            bytes.fromhex(pubkey),
        ):
            raise ValueError("Signature verification failed")
    except Exception as e:
        metrics.nip98_requests_total.labels(result="invalid_sig").inc()
        raise HTTPException(
            status_code=401, detail=f"Invalid signature: {e}"
        )

    token = await db.get_token_for_pubkey(pubkey)
    if not token:
        metrics.nip98_requests_total.labels(result="not_found").inc()
        raise HTTPException(
            status_code=404,
            detail="No active subscription found for this pubkey",
        )

    metrics.nip98_requests_total.labels(result="success").inc()
    return JSONResponse(
        {"feed_url": f"{FEED_BASE_URL}/rss/{token}.xml"}
    )


# ---------------------------------------------------------------------------
# Feed URL recovery page
# ---------------------------------------------------------------------------

@app.get("/recover", response_class=HTMLResponse)
async def recover_page():
    """
    Self-service feed URL recovery via NIP-07 browser signing.

    NIP-07 extensions (Alby, nos2x) inject window.nostr into the browser
    and handle key management and event signing. Well-supported on desktop.
    On mobile, standard iOS and Android browsers do not support extensions;
    mobile users should use the email fallback.
    """
    metrics.recovery_page_visits_total.inc()
    api_url = f"{FEED_BASE_URL}/api/feed-url"
    html    = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Retrieve your podcast feed URL</title>
  <style>
    body {{
      font-family: system-ui, sans-serif; max-width: 480px;
      margin: 4rem auto; padding: 0 1.5rem;
      line-height: 1.6; color: #222;
    }}
    h1   {{ font-size: 1.4rem; margin-bottom: 0.5rem; }}
    button {{
      display: block; width: 100%; padding: 0.75rem;
      font-size: 1rem; background: #f7931a; color: white;
      border: none; border-radius: 6px; cursor: pointer;
      margin-top: 1.5rem;
    }}
    button:disabled {{ background: #ccc; cursor: not-allowed; }}
    #result {{
      margin-top: 1.5rem; padding: 1rem; background: #f5f5f5;
      border-radius: 6px; word-break: break-all; display: none;
    }}
    #error  {{ margin-top: 1rem; color: #c00; display: none; }}
    .note   {{
      margin-top: 2rem; font-size: 0.9rem; color: #555;
      border-top: 1px solid #ddd; padding-top: 1rem;
    }}
  </style>
</head>
<body>
  <h1>Retrieve your podcast feed URL</h1>
  <p>
    Sign in with your Nostr key to retrieve your private members feed URL.
    This requires a NIP-07 browser extension such as
    <a href="https://getalby.com" target="_blank">Alby</a> or
    <a href="https://github.com/fiatjaf/nos2x" target="_blank">nos2x</a>.
  </p>
  <p>
    <strong>On mobile:</strong> most phone browsers do not support
    extensions. If you are on a phone or do not have a NIP-07 extension,
    use the email fallback below.
  </p>
  <button id="btn" onclick="retrieve()">
    Sign with Nostr to retrieve feed URL
  </button>
  <div id="error"></div>
  <div id="result">
    <strong>Your feed URL:</strong><br>
    <span id="url"></span><br><br>
    <button onclick="copy()" style="margin-top:0.5rem">
      Copy to clipboard
    </button>
  </div>
  <div class="note">
    <strong>No extension?</strong> Reply to your subscription confirmation
    email and we will resend your feed URL.
  </div>
  <script>
    const API = "{api_url}";
    async function retrieve() {{
      const btn = document.getElementById("btn");
      showError("");
      if (!window.nostr) {{
        showError(
          "No NIP-07 extension detected. Install Alby or nos2x on " +
          "a desktop browser, or reply to your confirmation email."
        );
        return;
      }}
      btn.disabled    = true;
      btn.textContent = "Signing\u2026";
      try {{
        const pubkey = await window.nostr.getPublicKey();
        const event  = {{
          kind: 27235,
          created_at: Math.floor(Date.now() / 1000),
          tags: [["u", API], ["method", "GET"]],
          content: "",
        }};
        const signed  = await window.nostr.signEvent(event);
        const encoded = btoa(JSON.stringify(signed));
        const resp    = await fetch(API, {{
          headers: {{"Authorization": "Nostr " + encoded}},
        }});
        if (!resp.ok) {{
          const body = await resp.json().catch(() => ({{}}));
          showError(body.detail ||
            (resp.status === 404
              ? "No active subscription found for this Nostr key."
              : "Request failed. Try again or use the email fallback."));
          return;
        }}
        const data = await resp.json();
        document.getElementById("url").textContent = data.feed_url;
        document.getElementById("result").style.display = "block";
      }} catch(e) {{
        showError("Error: " + e.message);
      }} finally {{
        btn.disabled    = false;
        btn.textContent = "Sign with Nostr to retrieve feed URL";
      }}
    }}
    function copy() {{
      navigator.clipboard
        .writeText(document.getElementById("url").textContent)
        .then(() => alert("Copied!"));
    }}
    function showError(msg) {{
      const el = document.getElementById("error");
      el.textContent   = msg;
      el.style.display = msg ? "block" : "none";
    }}
  </script>
</body>
</html>"""
    return HTMLResponse(content=html)


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------

@app.get("/metrics")
async def prometheus_metrics(request: Request):
    """
    Prometheus metrics endpoint. Listens on all interfaces since scrapes
    may come from another host. Bearer token auth required.

    Example Prometheus scrape config:
      - job_name: podcast_token_service
        bearer_token: YOUR_ADMIN_TOKEN
        static_configs:
          - targets: ["members.yourpodcast.com"]
        scheme: https
    """
    _require_admin(request)
    return Response(
        content=generate_latest(),
        media_type=CONTENT_TYPE_LATEST,
    )


# ---------------------------------------------------------------------------
# Admin endpoints (restrict to localhost via nginx)
# ---------------------------------------------------------------------------

@app.post("/admin/cleanup")
async def admin_cleanup(request: Request):
    """Remove tokens expired or revoked more than 90 days ago."""
    _require_admin(request)
    await db.cleanup_expired()
    await db.update_gauges()
    return JSONResponse({"status": "ok"})


@app.get("/health")
async def health():
    return JSONResponse({"status": "ok"})


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _pkcs7_pad(data: bytes, block_size: int) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def _event_id_bytes(event: dict) -> bytes:
    serialised = json.dumps(
        [0, event["pubkey"], event["created_at"],
         event["kind"], event["tags"], event["content"]],
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode()
    return hashlib.sha256(serialised).digest()


def _smtp_send(msg: MIMEText):
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
        server.starttls()
        server.login(SMTP_USER, SMTP_PASSWORD)
        server.send_message(msg)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="Podcast members feed token service"
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
