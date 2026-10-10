"""실습 응답 헬퍼. 안전 엔드포인트가 붙이는 헤더도 여기서 정의한다."""

from __future__ import annotations

from flask import Response, jsonify

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'none'; script-src 'none'; style-src 'none'; "
        "img-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cache-Control": "no-store",
    "X-Lab-Only": "localhost-training",
}


def lab_json(payload: dict, status: int = 200) -> Response:
    body = {"lab_only": True, **payload}
    response = jsonify(body)
    response.status_code = status
    response.headers["X-Lab-Only"] = "localhost-training"
    return response


def lab_html(inner: str, status: int = 200) -> Response:
    document = (
        "<!DOCTYPE html><html lang=\"ko\"><head><meta charset=\"utf-8\">"
        "<title>로컬 실습</title></head><body>"
        "<p>로컬 실습 전용. 외부에 노출하지 마세요.</p>"
        f"{inner}</body></html>"
    )
    response = Response(document, status=status, mimetype="text/html")
    response.headers["X-Lab-Only"] = "localhost-training"
    return response


def apply_security_headers(response: Response) -> Response:
    for key, value in SECURITY_HEADERS.items():
        response.headers[key] = value
    response.headers.pop("X-Powered-By", None)
    return response
