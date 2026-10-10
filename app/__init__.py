"""로컬 전용 OWASP Top 10:2021 실습 애플리케이션."""

from __future__ import annotations

import secrets

from flask import Flask, Response

from app.db import connect, seed
from app.guard import install_localhost_guard
from app.http import apply_security_headers, lab_html
from app.secure.routes import secure_bp
from app.vulnerable.routes import vulnerable_bp

LAB_BANNER = "로컬 실습 전용. 127.0.0.1 이외에는 바인딩하지 않는다."


def create_app(config: dict | None = None) -> Flask:
    app = Flask(__name__)
    app.json.ensure_ascii = False
    app.config.update(
        SECRET_KEY=secrets.token_hex(32),
        JSON_AS_ASCII=False,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        SESSION_COOKIE_SECURE=False,
        LAB_ONLY=True,
        MAX_CONTENT_LENGTH=16 * 1024,
        AUTH_LOCKOUT_THRESHOLD=5,
        RESET_TTL_SECONDS=900,
        INTEGRITY_SECRET=secrets.token_bytes(32),
    )
    if config:
        app.config.update(config)

    conn = connect()
    seed(conn)
    app.extensions["db"] = conn
    app.extensions["security_log"] = []
    app.extensions["vuln_log"] = []
    app.extensions["metrics"] = {"auth_failure": 0}
    app.extensions["auth_failures"] = {}
    app.extensions["lockouts"] = {}
    app.extensions["sessions"] = {}
    app.extensions["reset_inbox"] = {}

    app.register_blueprint(vulnerable_bp)
    app.register_blueprint(secure_bp)
    install_localhost_guard(app)

    @app.get("/")
    def index() -> Response:
        body = """
        <h1>OWASP Top 10:2021 로컬 방어 실습</h1>
        <p>이 서버는 교육용이며 로컬호스트에서만 동작한다. 외부에 공개하지 말 것.</p>
        <p>각 항목은 <code>/lab/a0N/vuln/...</code> 와 <code>/lab/a0N/fixed/...</code> 로 나란히 있다.</p>
        <ul>
          <li>A01 접근 제어: /lab/a01/vuln/documents/&lt;id&gt;</li>
          <li>A02 암호: /lab/a02/vuln/login</li>
          <li>A03 인젝션: /lab/a03/vuln/notes, /lab/a03/vuln/echo</li>
          <li>A04 안전하지 않은 설계: /lab/a04/vuln/reset</li>
          <li>A05 보안 설정 오류: /lab/a05/vuln/profile</li>
          <li>A06 취약한 구성요소: /lab/a06/vuln/audit</li>
          <li>A07 인증 실패: /lab/a07/vuln/login</li>
          <li>A08 무결성 실패: /lab/a08/vuln/profile</li>
          <li>A09 로깅·모니터링 실패: /lab/a09/vuln/login</li>
          <li>A10 SSRF: /lab/a10/vuln/fetch</li>
        </ul>
        """
        return apply_security_headers(lab_html(body))

    @app.get("/health")
    def health() -> Response:
        return apply_security_headers(lab_html("<p>ok</p>"))

    return app
