"""A08 취약 구현: 클라이언트가 보낸 역할을 검증 없이 수용한다."""

from __future__ import annotations


def accept_profile(payload: dict) -> dict:
    return {
        "username": payload.get("username", ""),
        "role": payload.get("role", "user"),
        "verified": False,
    }
