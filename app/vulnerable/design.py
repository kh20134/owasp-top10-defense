"""A04 취약 구현: 사용자 이름 자체를 재설정 토큰으로 쓴다."""

from __future__ import annotations


def issue_token(username: str) -> str:
    return username


def token_matches(username: str, token: str) -> bool:
    return token == username
