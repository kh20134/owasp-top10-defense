"""A07 안전 구현: 동일한 실패 메시지, 잠금, 무작위 세션."""

from __future__ import annotations

import secrets
import time

GENERIC = "아이디 또는 비밀번호가 올바르지 않습니다."
LOCKED = "로그인 시도가 일시적으로 제한되었습니다."


def failure_message() -> str:
    return GENERIC


def is_locked(lockouts: dict, username: str, *, now: float | None = None) -> bool:
    current = time.time() if now is None else now
    until = lockouts.get(username)
    return until is not None and until > current


def register_failure(
    lockouts: dict,
    failures: dict,
    username: str,
    *,
    threshold: int,
    now: float | None = None,
    lock_seconds: int = 300,
) -> None:
    current = time.time() if now is None else now
    failures[username] = failures.get(username, 0) + 1
    if failures[username] >= threshold:
        lockouts[username] = current + lock_seconds


def clear_failures(failures: dict, username: str) -> None:
    failures.pop(username, None)


def new_session_id() -> str:
    return secrets.token_urlsafe(32)
