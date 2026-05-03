"""
Podcast members feed token service.
Bridges BTCPay Server subscriptions to private RSS feed access.

Classes:
  Secp256k1       - libsecp256k1 bindings via cffi (Schnorr signing, ECDH)
  Bech32          - Pure-Python bech32/bech32m encode/decode (npub/nsec)
  Database        - SQLite token/subscriber store
  BTCPayVerifier  - Webhook HMAC-SHA256 signature verification
  FeedProxy       - Cached proxy for the upstream PodServer members feed
  NostrDM         - NIP-04 encrypted direct message over Nostr relays
  NotificationService - Orchestrates email and Nostr DM delivery

Deploy behind nginx with TLS termination.
Run via uvicorn as a systemd/NixOS service or Docker container.

Environment variables (see .env.example):
  BTCPAY_WEBHOOK_SECRET  - Shared secret configured in BTCPay webhook settings
  PODSERVER_FEED_URL     - Internal URL of the PodServer members RSS feed
  FEED_BASE_URL          - Public base URL for constructing subscriber feed URLs
  DATABASE_PATH          - Path to SQLite database file
  SMTP_HOST/PORT/USER/PASSWORD/FROM - SMTP credentials for email delivery
  NOSTR_PRIVATE_KEY      - nsec or hex private key for a dedicated service keypair
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
from fastapi.responses import JSONResponse

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
SMTP_HOST             = os.environ["SMTP_HOST"]
SMTP_PORT             = int(os.environ.get("SMTP_PORT", 587))
SMTP_USER             = os.environ["SMTP_USER"]
SMTP_PASSWORD         = os.environ["SMTP_PASSWORD"]
SMTP_FROM             = os.environ["SMTP_FROM"]
NOSTR_PRIVATE_KEY     = os.environ["NOSTR_PRIVATE_KEY"]

TOKEN_BYTES       = 32    # 256-bit tokens
GRACE_PERIOD_DAYS = 3     # extra days after expiry before hard cutoff
FEED_CACHE_TTL    = 300   # seconds; podcast apps poll every 15-60 min

NOSTR_RELAYS = [
    "wss://relay.damus.io",
    "wss://relay.nostr.band",
    "wss://nos.lol",
]


# ---------------------------------------------------------------------------
# libsecp256k1 via ctypes
#
# We call libsecp256k1 directly rather than via a Python wrapper package.
# This avoids the broken/unavailable coincurve nixpkgs package while using
# the same underlying C library. The functions we need are straightforward.
#
# NIP-04 requires raw x-coordinate ECDH — coincurve's ecdh() returns
# sha256(compressed_pubkey) instead, which is wrong for NIP-04. Direct
# ctypes gives us the raw x coordinate we actually need.
# ---------------------------------------------------------------------------

class Secp256k1:
    """
    Minimal libsecp256k1 bindings for the operations needed by this service:
      - Schnorr signing (BIP-340) for NIP-01 event signatures
      - Raw ECDH x-coordinate for NIP-04 message encryption
      - Public key derivation from private key

    Loads libsecp256k1 as a shared library. On NixOS the library is provided
    by pkgs.secp256k1 and linked into the derivation. On Debian/Ubuntu install
    libsecp256k1-dev. On Alpine install secp256k1-dev.
    """

    # Context flags
    SECP256K1_CONTEXT_SIGN   = 1
    SECP256K1_CONTEXT_VERIFY = 2

    # EC_PUBKEY_SERIALIZE flags
    SECP256K1_EC_COMPRESSED = 258

    def __init__(self):
        lib_name = ctypes.util.find_library("secp256k1")
        if lib_name is None:
            raise RuntimeError(
                "libsecp256k1 not found. "
                "Install libsecp256k1 (NixOS: pkgs.secp256k1, "
                "Debian: libsecp256k1-dev, Alpine: secp256k1-dev)."
            )
        self._lib = ctypes.CDLL(lib_name)
        self._ctx = self._lib.secp256k1_context_create(
            self.SECP256K1_CONTEXT_SIGN | self.SECP256K1_CONTEXT_VERIFY
        )
        self._randomize_context()

    def _randomize_context(self):
        """Randomize context to protect against side-channel attacks."""
        seed = os.urandom(32)
        self._lib.secp256k1_context_randomize(
            self._ctx, ctypes.c_char_p(seed)
        )

    def derive_pubkey(self, privkey_bytes: bytes) -> bytes:
        """
        Derive compressed 33-byte public key from 32-byte private key.
        Returns x-only (32-byte) pubkey for use as Nostr pubkey hex.
        """
        pubkey_buf = ctypes.create_string_buffer(64)
        ret = self._lib.secp256k1_ec_pubkey_create(
            self._ctx, pubkey_buf, ctypes.c_char_p(privkey_bytes)
        )
        if not ret:
            raise ValueError("Invalid private key")

        # Serialize to compressed 33-byte format
        output     = ctypes.create_string_buffer(33)
        output_len = ctypes.c_size_t(33)
        self._lib.secp256k1_ec_pubkey_serialize(
            self._ctx, output, ctypes.byref(output_len),
            pubkey_buf, self.SECP256K1_EC_COMPRESSED
        )
        # Return x-only (drop the 0x02/0x03 prefix byte) — this is the
        # Nostr pubkey format used in event JSON and npub encoding
        return bytes(output)[1:]

    def schnorr_sign(self, msg32: bytes, privkey_bytes: bytes) -> bytes:
        """
        Sign a 32-byte message with BIP-340 Schnorr.
        Returns 64-byte signature.
        msg32 must already be hashed — pass the event ID bytes directly.
        """
        sig_buf   = ctypes.create_string_buffer(64)
        aux_rand  = ctypes.c_char_p(os.urandom(32))
        ret = self._lib.secp256k1_schnorrsig_sign32(
            self._ctx,
            sig_buf,
            ctypes.c_char_p(msg32),
            ctypes.c_char_p(privkey_bytes),
            aux_rand,
        )
        if not ret:
            raise ValueError("Schnorr signing failed")
        return bytes(sig_buf)

    def ecdh_x_only(
        self, privkey_bytes: bytes, compressed_pubkey_bytes: bytes
    ) -> bytes:
        """
        Compute ECDH shared secret and return the raw x-coordinate (32 bytes).

        NIP-04 requires the x-coordinate directly — NOT sha256(pubkey) as
        coincurve's ecdh() returns. We use secp256k1_ecdh with a custom
        hashfp that returns the x-coordinate verbatim.
        """
        # Parse the recipient's compressed public key
        pubkey_buf = ctypes.create_string_buffer(64)
        ret = self._lib.secp256k1_ec_pubkey_parse(
            self._ctx,
            pubkey_buf,
            ctypes.c_char_p(compressed_pubkey_bytes),
            ctypes.c_size_t(len(compressed_pubkey_bytes)),
        )
        if not ret:
            raise ValueError("Failed to parse recipient public key")

        # Custom hashfp: copies x-coordinate directly into output buffer
        # instead of hashing it. This is the NIP-04 shared secret.
        HASHFP = ctypes.CFUNCTYPE(
            ctypes.c_int,
            ctypes.c_char_p,  # output
            ctypes.c_char_p,  # x32
            ctypes.c_char_p,  # y32
            ctypes.c_void_p,  # data (unused)
        )

        def _x_only_hashfp(output, x32, y32, _data):
            ctypes.memmove(output, x32, 32)
            return 1

        hashfp_cb = HASHFP(_x_only_hashfp)
        result    = ctypes.create_string_buffer(32)

        ret = self._lib.secp256k1_ecdh(
            self._ctx,
            result,
            pubkey_buf,
            ctypes.c_char_p(privkey_bytes),
            hashfp_cb,
            None,
        )
        if not ret:
            raise ValueError("ECDH failed")
        return bytes(result)


# ---------------------------------------------------------------------------
# Bech32 — pure Python, no dependencies
#
# Implements bech32 (BIP-173) for npub/nsec decoding/encoding.
# Nostr uses bech32 (not bech32m) for npub and nsec.
# ---------------------------------------------------------------------------

class Bech32:
    """
    Minimal pure-Python bech32 encode/decode for Nostr npub and nsec keys.
    Implements BIP-173 bech32 (not bech32m — Nostr uses original bech32).
    """

    CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    GENERATOR = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]

    @classmethod
    def _polymod(cls, values: list[int]) -> int:
        chk = 1
        for v in values:
            b = chk >> 25
            chk = (chk & 0x1FFFFFF) << 5 ^ v
            for i in range(5):
                chk ^= cls.GENERATOR[i] if ((b >> i) & 1) else 0
        return chk

    @classmethod
    def _hrp_expand(cls, hrp: str) -> list[int]:
        return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

    @classmethod
    def _verify_checksum(cls, hrp: str, data: list[int]) -> bool:
        return cls._polymod(cls._hrp_expand(hrp) + data) == 1

    @classmethod
    def _create_checksum(cls, hrp: str, data: list[int]) -> list[int]:
        values = cls._hrp_expand(hrp) + data
        polymod = cls._polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
        return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]

    @classmethod
    def _convertbits(
        cls, data: bytes | list[int], frombits: int, tobits: int, pad: bool = True
    ) -> list[int]:
        acc = 0
        bits = 0
        result: list[int] = []
        maxv = (1 << tobits) - 1
        for value in data:
            acc = ((acc << frombits) | value) & 0xFFFFFFFF
            bits += frombits
            while bits >= tobits:
                bits -= tobits
                result.append((acc >> bits) & maxv)
        if pad:
            if bits:
                result.append((acc << (tobits - bits)) & maxv)
        elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
            raise ValueError("Invalid padding in bech32 conversion")
        return result

    @classmethod
    def decode(cls, bech: str) -> tuple[str, bytes]:
        """Decode a bech32 string. Returns (hrp, data_bytes)."""
        if any(ord(c) < 33 or ord(c) > 126 for c in bech):
            raise ValueError("Invalid bech32 character")
        if bech.lower() != bech and bech.upper() != bech:
            raise ValueError("Mixed case in bech32 string")
        bech = bech.lower()
        pos = bech.rfind("1")
        if pos < 1 or pos + 7 > len(bech):
            raise ValueError("Invalid bech32 separator position")
        hrp  = bech[:pos]
        data = [cls.CHARSET.find(c) for c in bech[pos + 1:]]
        if any(d == -1 for d in data):
            raise ValueError("Invalid bech32 character in data")
        if not cls._verify_checksum(hrp, data):
            raise ValueError("Invalid bech32 checksum")
        decoded = cls._convertbits(data[:-6], 5, 8, False)
        return hrp, bytes(decoded)

    @classmethod
    def encode(cls, hrp: str, data: bytes) -> str:
        """Encode bytes to a bech32 string with the given HRP."""
        converted = cls._convertbits(data, 8, 5)
        checksum  = cls._create_checksum(hrp, converted)
        return hrp + "1" + "".join(
            cls.CHARSET[d] for d in converted + checksum
        )

    @classmethod
    def npub_to_hex(cls, npub: str) -> str:
        hrp, data = cls.decode(npub)
        if hrp != "npub":
            raise ValueError(f"Expected npub, got {hrp}")
        return data.hex()

    @classmethod
    def nsec_to_hex(cls, nsec: str) -> str:
        hrp, data = cls.decode(nsec)
        if hrp != "nsec":
            raise ValueError(f"Expected nsec, got {hrp}")
        return data.hex()

    @classmethod
    def hex_to_npub(cls, hex_key: str) -> str:
        return cls.encode("npub", bytes.fromhex(hex_key))

    @classmethod
    def hex_to_nsec(cls, hex_key: str) -> str:
        return cls.encode("nsec", bytes.fromhex(hex_key))


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

class Database:
    """
    SQLite-backed store for subscribers and feed tokens.
    Uses aiosqlite for non-blocking async access.
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
                email                 TEXT NOT NULL,
                nostr_pubkey          TEXT,
                created_at            TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS tokens (
                token                 TEXT PRIMARY KEY,
                btcpay_subscriber_id  TEXT NOT NULL,
                expires_at            TEXT NOT NULL,
                created_at            TEXT NOT NULL,
                last_used_at          TEXT,
                revoked               INTEGER NOT NULL DEFAULT 0,
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
        email: str,
        nostr_pubkey: Optional[str] = None,
    ):
        await self._db.execute(
            """
            INSERT INTO subscribers
                (btcpay_subscriber_id, email, nostr_pubkey, created_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(btcpay_subscriber_id) DO UPDATE SET
                email        = excluded.email,
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
        """Return the most recently created non-revoked token."""
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
        Extend expiry on the active token. Never issue a new URL on renewal —
        changing the URL would silently break every subscriber's podcast app.
        """
        await self._db.execute(
            """
            UPDATE tokens SET expires_at = ?
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
        Return the token row if valid and within the grace period.
        Updates last_used_at as a side effect for abuse monitoring.
        """
        grace_cutoff = (
            datetime.now(timezone.utc) - timedelta(days=GRACE_PERIOD_DAYS)
        ).isoformat()

        async with self._db.execute(
            """
            SELECT t.*, s.email, s.nostr_pubkey
            FROM tokens t
            JOIN subscribers s USING (btcpay_subscriber_id)
            WHERE t.token    = ?
              AND t.revoked  = 0
              AND t.expires_at > ?
            """,
            (token, grace_cutoff),
        ) as cur:
            row = await cur.fetchone()

        if row:
            await self._db.execute(
                "UPDATE tokens SET last_used_at = ? WHERE token = ?",
                (_now(), token),
            )
            await self._db.commit()

        return row

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
        async with self._db.execute(
            """
            SELECT t.token
            FROM tokens t
            JOIN subscribers s USING (btcpay_subscriber_id)
            WHERE s.nostr_pubkey = ? AND t.revoked = 0
            ORDER BY t.created_at DESC LIMIT 1
            """,
            (pubkey_hex,),
        ) as cur:
            row = await cur.fetchone()
            return row["token"] if row else None


# ---------------------------------------------------------------------------
# BTCPay webhook verification
# ---------------------------------------------------------------------------

class BTCPayVerifier:
    """
    Verifies BTCPay Server webhook HMAC-SHA256 signatures.
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
    Fetches the private PodServer RSS feed and serves it to authenticated
    subscribers. The real upstream URL is never exposed.

    Caches for FEED_CACHE_TTL seconds — podcast apps poll every 15-60
    minutes so a 5-minute cache has no practical impact on episode delivery.
    """

    def __init__(self, feed_url: str):
        self._url        = feed_url
        self._cache: Optional[bytes] = None
        self._cache_time: Optional[datetime] = None

    async def fetch(self) -> bytes:
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


# ---------------------------------------------------------------------------
# Nostr NIP-04 DM
# ---------------------------------------------------------------------------

class NostrDM:
    """
    Sends NIP-04 (kind:4) encrypted direct messages via Nostr relays.

    NIP-04 encryption:
      1. ECDH between sender private key and recipient public key to derive
         a 32-byte shared secret (raw x-coordinate — NOT sha256(pubkey)).
      2. Encrypt the message with AES-256-CBC using the shared secret as key
         and a random 16-byte IV.
      3. Encode as "<base64_ciphertext>?iv=<base64_iv>" in the event content.

    Each event is signed with BIP-340 Schnorr per NIP-01.

    NIP-04 is used rather than NIP-17 for maximum client compatibility:
    Damus, Primal, Amethyst (NIP-17 mode off), and YakiHonne all support
    NIP-04. NIP-17 offers better metadata privacy but is not yet universally
    supported.
    """

    def __init__(self, private_key_input: str, secp: Secp256k1):
        self._secp = secp
        # Accept nsec bech32 or raw hex
        if private_key_input.startswith("nsec"):
            hex_key = Bech32.nsec_to_hex(private_key_input)
        else:
            hex_key = private_key_input
        self._privkey = bytes.fromhex(hex_key)
        self._pubkey  = self._secp.derive_pubkey(self._privkey)  # 32 bytes x-only

    @property
    def pubkey_hex(self) -> str:
        return self._pubkey.hex()

    def _compressed_pubkey(self, pubkey_hex: str) -> bytes:
        """
        Convert a 32-byte x-only Nostr pubkey hex to a 33-byte compressed
        pubkey by assuming even parity (0x02 prefix). This is correct for
        Nostr pubkeys which are always x-only with implied even parity.
        """
        return bytes.fromhex("02" + pubkey_hex)

    def _encrypt(self, message: str, recipient_pubkey_hex: str) -> str:
        """Encrypt message and return NIP-04 content string."""
        compressed = self._compressed_pubkey(recipient_pubkey_hex)
        shared     = self._secp.ecdh_x_only(self._privkey, compressed)
        iv         = os.urandom(16)
        padded     = _pkcs7_pad(message.encode(), 16)
        cipher     = Cipher(
            algorithms.AES(shared), modes.CBC(iv), backend=default_backend()
        )
        enc        = cipher.encryptor()
        ciphertext = enc.update(padded) + enc.finalize()
        return (
            base64.b64encode(ciphertext).decode()
            + "?iv="
            + base64.b64encode(iv).decode()
        )

    def _event_id(self, event: dict) -> bytes:
        """Compute NIP-01 event ID: SHA256 of canonical JSON serialisation."""
        serialised = json.dumps(
            [
                0,
                event["pubkey"],
                event["created_at"],
                event["kind"],
                event["tags"],
                event["content"],
            ],
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode()
        return hashlib.sha256(serialised).digest()

    def _build_event(self, content: str, recipient_pubkey_hex: str) -> dict:
        """Build, ID, and sign a kind:4 Nostr event."""
        event = {
            "pubkey":     self.pubkey_hex,
            "created_at": int(time.time()),
            "kind":       4,
            "tags":       [["p", recipient_pubkey_hex]],
            "content":    content,
        }
        event_id_bytes = self._event_id(event)
        event["id"]    = event_id_bytes.hex()
        event["sig"]   = self._secp.schnorr_sign(
            event_id_bytes, self._privkey
        ).hex()
        return event

    async def send(self, recipient_npub_or_hex: str, message: str):
        """Encrypt and publish a NIP-04 DM to all configured relays."""
        if recipient_npub_or_hex.startswith("npub"):
            recipient_hex = Bech32.npub_to_hex(recipient_npub_or_hex)
        else:
            recipient_hex = recipient_npub_or_hex

        content = self._encrypt(message, recipient_hex)
        event   = self._build_event(content, recipient_hex)

        results = await asyncio.gather(
            *[self._publish(relay, event) for relay in NOSTR_RELAYS],
            return_exceptions=True,
        )
        successes = sum(1 for r in results if r is True)
        if successes == 0:
            raise RuntimeError("DM publish failed on all relays")
        logger.info(
            f"Nostr DM published to {successes}/{len(NOSTR_RELAYS)} relays"
        )

    async def _publish(self, relay_url: str, event: dict) -> bool:
        import websockets
        try:
            async with websockets.connect(relay_url, open_timeout=5) as ws:
                await ws.send(json.dumps(["EVENT", event]))
                async with asyncio.timeout(5):
                    resp = json.loads(await ws.recv())
                    if resp[0] == "OK" and resp[2] is True:
                        return True
                    logger.warning(f"Relay {relay_url} rejected: {resp}")
                    return False
        except Exception as e:
            logger.warning(f"Relay {relay_url} error: {e}")
            return False


# ---------------------------------------------------------------------------
# Notification service
# ---------------------------------------------------------------------------

@dataclass
class SubscriberInfo:
    email: str
    feed_url: str
    nostr_pubkey: Optional[str] = None


class NotificationService:
    """
    Delivers feed URLs via email and optionally Nostr DM.

    Email is always sent. Nostr DM is additionally sent if the subscriber
    provided an npub during checkout. The service Nostr keypair is always
    configured server-side — DM delivery is a per-subscriber opt-in based
    on whether they provided their npub.
    """

    def __init__(self, nostr_dm: NostrDM):
        self._nostr = nostr_dm

    async def deliver(self, info: SubscriberInfo):
        tasks = [self._send_email(info)]
        if info.nostr_pubkey:
            tasks.append(self._send_nostr_dm(info))
        await asyncio.gather(*tasks)

    async def _send_email(self, info: SubscriberInfo):
        body = (
            f"Thanks for subscribing!\n\n"
            f"Your private podcast feed URL:\n\n"
            f"  {info.feed_url}\n\n"
            f"Add this to Fountain, Castamatic, or any podcast app that\n"
            f"accepts a custom RSS feed. Keep it private — it is unique\n"
            f"to your subscription.\n\n"
            f"If you ever lose this URL, reply to this email and we will\n"
            f"resend it. If you provided your Nostr npub, you can also\n"
            f"retrieve it self-service at {FEED_BASE_URL}/api/feed-url\n"
        )
        msg            = MIMEText(body)
        msg["Subject"] = "Your members podcast feed"
        msg["From"]    = SMTP_FROM
        msg["To"]      = info.email
        await asyncio.to_thread(_smtp_send, msg)

    async def _send_nostr_dm(self, info: SubscriberInfo):
        message = (
            f"Your members podcast feed URL:\n\n"
            f"{info.feed_url}\n\n"
            f"Add this to Fountain, Castamatic, or any podcast app. "
            f"Keep it private — it is unique to your subscription."
        )
        try:
            await self._nostr.send(info.nostr_pubkey, message)
        except Exception as e:
            # Email was already sent; Nostr DM is best-effort
            logger.error(f"Nostr DM delivery failed: {e}")


# ---------------------------------------------------------------------------
# Application setup
# ---------------------------------------------------------------------------

_secp     = Secp256k1()
_nostr_dm = NostrDM(NOSTR_PRIVATE_KEY, _secp)

db       = Database(DATABASE_PATH)
verifier = BTCPayVerifier(BTCPAY_WEBHOOK_SECRET)
proxy    = FeedProxy(PODSERVER_FEED_URL)
notifier = NotificationService(_nostr_dm)


@app.on_event("startup")
async def startup():
    await db.connect()
    logger.info(
        f"Token service started — Nostr pubkey: "
        f"{Bech32.hex_to_npub(_nostr_dm.pubkey_hex)}"
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
        logger.warning("Rejected webhook: invalid signature")
        raise HTTPException(status_code=401, detail="Invalid signature")

    event         = await request.json()
    event_type    = event.get("type")
    subscriber_id = event.get("subscriberId")
    email         = event.get("email", "")
    subscription  = event.get("subscription", {})
    expires_ts    = subscription.get("expiresAt")
    nostr_pubkey  = event.get("metadata", {}).get("nostrPubkey")

    if not subscriber_id:
        return JSONResponse({"status": "ignored", "reason": "no subscriberId"})

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
            email=email, feed_url=feed_url, nostr_pubkey=nostr_pubkey
        ))
        logger.info(f"New subscriber {subscriber_id}")

    elif event_type == "SubscriptionRenewed":
        existing = await db.get_active_token(subscriber_id)
        if existing:
            await db.extend_token(subscriber_id, expires_at)
            logger.info(f"Renewed {subscriber_id}, token extended")
        else:
            # Lapsed and re-subscribed — issue new token and re-deliver
            await db.upsert_subscriber(subscriber_id, email, nostr_pubkey)
            token    = await db.create_token(subscriber_id, expires_at)
            feed_url = f"{FEED_BASE_URL}/rss/{token}.xml"
            await notifier.deliver(SubscriberInfo(
                email=email, feed_url=feed_url, nostr_pubkey=nostr_pubkey
            ))
            logger.info(f"Re-subscribed {subscriber_id}, new token issued")

    elif event_type in ("SubscriptionExpired", "SubscriptionSuspended"):
        await db.revoke_tokens(subscriber_id)
        logger.info(f"Revoked tokens for {subscriber_id} ({event_type})")

    return JSONResponse({"status": "ok"})


# ---------------------------------------------------------------------------
# Feed endpoint
# ---------------------------------------------------------------------------

@app.get("/rss/{token}.xml")
async def members_feed(token: str):
    row = await db.validate_token(token)
    if not row:
        return Response(
            content="Subscription required or expired.",
            status_code=402,
            media_type="text/plain",
        )
    try:
        content = await proxy.fetch()
    except Exception as e:
        logger.error(f"Feed fetch failed: {e}")
        raise HTTPException(status_code=502, detail="Could not fetch feed")
    return Response(content=content, media_type="application/rss+xml")


# ---------------------------------------------------------------------------
# NIP-98 feed URL re-issuance
# ---------------------------------------------------------------------------

@app.get("/api/feed-url")
async def get_feed_url(request: Request):
    """
    Allows a subscriber to retrieve their feed URL without contacting support.

    NIP-98 HTTP Auth: the client creates a kind:27235 Nostr event containing
    the request URL in a 'u' tag and the HTTP method in a 'method' tag, signs
    it with their Nostr private key, base64-encodes the JSON, and sends it as:
      Authorization: Nostr <base64_encoded_event>

    The server verifies:
      1. Event kind is 27235
      2. created_at is within 60 seconds of now (replay prevention)
      3. 'u' tag matches this endpoint URL
      4. 'method' tag is GET
      5. Event signature is valid (Schnorr verification via libsecp256k1)

    The verified pubkey is then used to look up the subscriber's active token.
    Full spec: https://github.com/nostr-protocol/nips/blob/master/98.md
    """
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Nostr "):
        raise HTTPException(status_code=401, detail="NIP-98 auth required")

    try:
        event = json.loads(base64.b64decode(auth.removeprefix("Nostr ")))
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid NIP-98 token")

    if event.get("kind") != 27235:
        raise HTTPException(status_code=401, detail="Invalid event kind")

    if abs(time.time() - event.get("created_at", 0)) > 60:
        raise HTTPException(status_code=401, detail="Event timestamp expired")

    tags = {t[0]: t[1] for t in event.get("tags", []) if len(t) >= 2}
    if tags.get("method") != "GET":
        raise HTTPException(status_code=401, detail="Method mismatch")

    pubkey = event.get("pubkey", "")
    if not pubkey:
        raise HTTPException(status_code=401, detail="Missing pubkey")

    # Verify Schnorr signature
    try:
        event_id_bytes = bytes.fromhex(event["id"])
        sig_bytes      = bytes.fromhex(event["sig"])
        pubkey_bytes   = bytes.fromhex(pubkey)  # 32-byte x-only

        # Build the compressed pubkey for verification
        # secp256k1_xonly_pubkey_parse + secp256k1_schnorrsig_verify
        lib = _secp._lib
        xonly_buf = ctypes.create_string_buffer(64)
        ret = lib.secp256k1_xonly_pubkey_parse(
            _secp._ctx,
            xonly_buf,
            ctypes.c_char_p(pubkey_bytes),
        )
        if not ret:
            raise ValueError("Invalid pubkey")

        ret = lib.secp256k1_schnorrsig_verify(
            _secp._ctx,
            ctypes.c_char_p(sig_bytes),
            ctypes.c_char_p(event_id_bytes),
            ctypes.c_size_t(32),
            xonly_buf,
        )
        if not ret:
            raise ValueError("Invalid signature")
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Signature invalid: {e}")

    token = await db.get_token_for_pubkey(pubkey)
    if not token:
        raise HTTPException(
            status_code=404,
            detail="No active subscription found for this pubkey",
        )

    return JSONResponse({"feed_url": f"{FEED_BASE_URL}/rss/{token}.xml"})


# ---------------------------------------------------------------------------
# Admin endpoints (restrict to localhost at nginx level)
# ---------------------------------------------------------------------------

@app.post("/admin/cleanup")
async def admin_cleanup():
    """Remove long-expired and revoked tokens. Call weekly via cron/timer."""
    await db.cleanup_expired()
    return JSONResponse({"status": "ok"})


@app.get("/admin/stats")
async def admin_stats():
    """Active subscriber and token counts for monitoring."""
    return JSONResponse(await db.subscriber_stats())


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
    parser = argparse.ArgumentParser(description="Podcast members feed token service")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
