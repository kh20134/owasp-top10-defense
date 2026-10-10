"""A07 취약 구현: 계정 열거, 잠금 없음, 예측 가능한 세션."""

from __future__ import annotations

UNKNOWN = "사용자를 찾을 수 없습니다."
BAD_PASSWORD = "비밀번호가 올바르지 않습니다."


def failure_message(*, user_exists: bool) -> str:
    if user_exists:
        return BAD_PASSWORD
    return UNKNOWN


def session_cookie_value(user_id: int) -> str:
    return str(user_id)
