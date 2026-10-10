"""A08 안전 구현: 서버가 서명한 역할만 수용한다."""

from __future__ import annotations

import hashlib
import hmac


def issue_profile(secret: bytes, username: str) -> dict:
    role = "user"
    return {
        "username": username,
        "role": role,
        "signature": sign(secret, username, role),
    }


def sign(secret: bytes, username: str, role: str) -> str:
    message = f"{username}|{role}".encode("utf-8")
    return hmac.new(secret, message, hashlib.sha256).hexdigest()


def accept_profile(secret: bytes, payload: dict) -> dict | None:
    username = payload.get("username", "")
    role = payload.get("role", "")
    signature = payload.get("signature", "")
    if not isinstance(username, str) or not isinstance(role, str) or not isinstance(signature, str):
        return None
    expected = sign(secret, username, role)
    if not hmac.compare_digest(expected, signature):
        return None
    return {"username": username, "role": role, "verified": True}
