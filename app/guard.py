"""실습 서버가 루프백 이외의 클라이언트 요청을 거부하게 한다."""

from __future__ import annotations

import ipaddress

from flask import Flask, request

from app.http import lab_json

BIND_HOST = "127.0.0.1"


def is_loopback(addr: str | None) -> bool:
    if not addr:
        return False
    try:
        return ipaddress.ip_address(addr).is_loopback
    except ValueError:
        return False


def install_localhost_guard(app: Flask) -> None:
    @app.before_request
    def _reject_nonlocal():
        if is_loopback(request.remote_addr):
            return None
        return lab_json(
            {"error": "이 실습 서버는 로컬호스트에서만 사용할 수 있습니다."},
            403,
        )
