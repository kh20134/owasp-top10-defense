"""A09 취약 구현: 비밀번호를 로그에 남기고 실패 횟수를 세지 않는다."""

from __future__ import annotations


def record_login(log: list[dict], username: str, password: str, success: bool) -> None:
    log.append(
        {
            "event": "login",
            "username": username,
            "password": password,
            "success": success,
        }
    )
