"""A09 안전 구현: 비밀 없는 보안 이벤트와 실패 카운터."""

from __future__ import annotations

import uuid


def record_login(log: list[dict], metrics: dict, username: str, success: bool) -> dict:
    event = {
        "event": "auth_success" if success else "auth_failure",
        "username": username,
        "request_id": uuid.uuid4().hex[:12],
    }
    log.append(event)
    if not success:
        metrics["auth_failure"] = metrics.get("auth_failure", 0) + 1
    return event
