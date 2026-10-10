"""A04 안전 구현: 예측 불가능한 1회용 재설정 토큰."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import sqlite3
import time


def issue_token() -> str:
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def store_token(
    conn: sqlite3.Connection,
    username: str,
    token: str,
    *,
    ttl_seconds: int,
    now: float | None = None,
) -> None:
    current = time.time() if now is None else now
    conn.execute(
        "INSERT INTO reset_tokens (username, token_hash, expires_at, used) VALUES (?, ?, ?, 0)",
        (username, hash_token(token), current + ttl_seconds),
    )
    conn.commit()


def consume_token(
    conn: sqlite3.Connection,
    username: str,
    token: str,
    *,
    now: float | None = None,
) -> bool:
    current = time.time() if now is None else now
    digest = hash_token(token)
    dummy = hash_token("missing")
    row = conn.execute(
        """
        SELECT id, token_hash FROM reset_tokens
        WHERE username = ? AND used = 0 AND expires_at >= ?
        ORDER BY id DESC LIMIT 1
        """,
        (username, current),
    ).fetchone()
    if row is None:
        hmac.compare_digest(dummy, digest)
        return False
    if not hmac.compare_digest(row["token_hash"], digest):
        return False
    conn.execute("UPDATE reset_tokens SET used = 1 WHERE id = ?", (row["id"],))
    conn.commit()
    return True
