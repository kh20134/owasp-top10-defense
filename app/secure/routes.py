"""안전 엔드포인트. 같은 실습 데이터에 방어 구현을 붙인다."""

from __future__ import annotations

import sqlite3

from flask import Blueprint, current_app, request, session

from app.advisories import read_manifest
from app.db import update_password, user_by_username
from app.http import apply_security_headers, lab_html, lab_json
from app.secure import access, authn, components, crypto, design, injection, integrity, monitoring
from app.secure.access import AuthRequired
from app.secure.ssrf import FetchBlocked, fetch

secure_bp = Blueprint("secure", __name__)


def _conn():
    return current_app.extensions["db"]


def _secured(response):
    return apply_security_headers(response)


@secure_bp.post("/lab/a01/login")
def a01_login():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", ""))
    password = str(data.get("password", ""))
    user = user_by_username(_conn(), username)
    if user is None or not crypto.verify_password(user["argon2_password"], password):
        return _secured(lab_json({"error": authn.GENERIC}, 401))
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    return _secured(lab_json({"ok": True, "username": user["username"]}))


@secure_bp.get("/lab/a01/fixed/documents/<int:doc_id>")
def a01_document(doc_id: int):
    try:
        document = access.read_document(_conn(), doc_id, session.get("user_id"))
    except AuthRequired:
        return _secured(lab_json({"error": "인증이 필요합니다."}, 401))
    if document is None:
        return _secured(lab_json({"error": "문서를 찾을 수 없습니다."}, 404))
    return _secured(lab_json({"document": document}))


@secure_bp.post("/lab/a02/fixed/login")
def a02_login():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", ""))
    password = str(data.get("password", ""))
    user = user_by_username(_conn(), username)
    if user is None or not crypto.verify_password(user["argon2_password"], password):
        return _secured(lab_json({"ok": False}, 401))
    return _secured(lab_json({"ok": True, "scheme": "argon2id"}))


@secure_bp.get("/lab/a02/fixed/stored/<username>")
def a02_stored(username: str):
    user = user_by_username(_conn(), username)
    if user is None:
        return _secured(lab_json({"error": "없음"}, 404))
    stored = user["argon2_password"]
    return _secured(
        lab_json(
            {
                "scheme": "argon2id",
                "exposed": False,
                "hash_prefix": stored.split("$", 3)[1] if stored.startswith("$") else "unknown",
            }
        )
    )


@secure_bp.get("/lab/a03/fixed/notes")
def a03_notes():
    raw_id = request.args.get("id", "")
    try:
        rows = injection.search_notes(_conn(), raw_id)
    except sqlite3.Error:
        return _secured(lab_json({"error": "조회에 실패했습니다."}, 400))
    return _secured(lab_json({"notes": rows}))


@secure_bp.post("/lab/a03/fixed/echo")
def a03_echo():
    data = request.get_json(silent=True) or {}
    text = str(data.get("text", ""))
    page = injection.render_echo(text)
    response = lab_html("")
    response.set_data(page)
    return _secured(response)


@secure_bp.post("/lab/a04/fixed/reset")
def a04_reset():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", ""))
    user = user_by_username(_conn(), username)
    if user is not None:
        token = design.issue_token()
        design.store_token(
            _conn(),
            username,
            token,
            ttl_seconds=current_app.config["RESET_TTL_SECONDS"],
        )
        current_app.extensions["reset_inbox"][username] = token
    return _secured(lab_json({"issued": True, "channel": "lab-inbox"}))


@secure_bp.get("/lab/a04/fixed/inbox")
def a04_inbox():
    username = session.get("username")
    if not username:
        return _secured(lab_json({"error": "인증이 필요합니다."}, 401))
    token = current_app.extensions["reset_inbox"].get(username)
    return _secured(lab_json({"token": token}))


@secure_bp.post("/lab/a04/fixed/confirm")
def a04_confirm():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", ""))
    token = str(data.get("token", ""))
    new_password = str(data.get("new_password", ""))
    if len(new_password) < 8:
        return _secured(lab_json({"error": "비밀번호가 너무 짧습니다."}, 400))
    if not design.consume_token(_conn(), username, token):
        return _secured(lab_json({"ok": False}, 400))
    update_password(_conn(), username, new_password)
    current_app.extensions["reset_inbox"].pop(username, None)
    return _secured(lab_json({"ok": True}))


@secure_bp.get("/lab/a05/fixed/profile")
def a05_profile():
    response = lab_json({"profile": "lab"})
    response.headers["Set-Cookie"] = "prefs=open; HttpOnly; Secure; SameSite=Strict"
    return _secured(response)


@secure_bp.get("/lab/a05/fixed/debug")
def a05_debug():
    try:
        raise ZeroDivisionError("lab-divide")
    except ZeroDivisionError:
        return _secured(lab_json({"error": "요청을 처리할 수 없습니다."}, 500))


@secure_bp.get("/lab/a06/fixed/audit")
def a06_audit():
    name = request.args.get("manifest", "runtime")
    try:
        text = read_manifest(name)
    except KeyError:
        return _secured(lab_json({"error": "알 수 없는 목록입니다."}, 400))
    result = components.audit(text)
    status = 409 if result["blocked"] else 200
    return _secured(lab_json(result, status))


@secure_bp.post("/lab/a07/fixed/login")
def a07_login():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", ""))
    password = str(data.get("password", ""))
    lockouts = current_app.extensions["lockouts"]
    failures = current_app.extensions.setdefault("auth_failures", {})
    if authn.is_locked(lockouts, username):
        return _secured(lab_json({"error": authn.LOCKED}, 429))
    user = user_by_username(_conn(), username)
    matched = user is not None and crypto.verify_password(user["argon2_password"], password)
    if not matched:
        authn.register_failure(
            lockouts,
            failures,
            username,
            threshold=current_app.config["AUTH_LOCKOUT_THRESHOLD"],
        )
        return _secured(lab_json({"error": authn.failure_message()}, 401))
    authn.clear_failures(failures, username)
    token = authn.new_session_id()
    current_app.extensions["sessions"][token] = user["id"]
    response = lab_json({"ok": True, "username": user["username"]})
    response.set_cookie(
        "session_id",
        token,
        httponly=True,
        secure=True,
        samesite="Strict",
    )
    return _secured(response)


@secure_bp.get("/lab/a07/fixed/me")
def a07_me():
    token = request.cookies.get("session_id", "")
    user_id = current_app.extensions["sessions"].get(token)
    if user_id is None:
        return _secured(lab_json({"error": "세션이 없습니다."}, 401))
    row = _conn().execute("SELECT username FROM users WHERE id = ?", (user_id,)).fetchone()
    if row is None:
        return _secured(lab_json({"error": "세션이 없습니다."}, 401))
    return _secured(lab_json({"username": row["username"]}))


@secure_bp.post("/lab/a08/fixed/issue")
def a08_issue():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", ""))
    if user_by_username(_conn(), username) is None:
        return _secured(lab_json({"error": "없음"}, 404))
    profile = integrity.issue_profile(current_app.config["INTEGRITY_SECRET"], username)
    return _secured(lab_json({"profile": profile}))


@secure_bp.post("/lab/a08/fixed/profile")
def a08_profile():
    payload = request.get_json(silent=True) or {}
    if not isinstance(payload, dict):
        return _secured(lab_json({"error": "형식이 올바르지 않습니다."}, 400))
    accepted = integrity.accept_profile(current_app.config["INTEGRITY_SECRET"], payload)
    if accepted is None:
        return _secured(lab_json({"error": "서명이 올바르지 않습니다."}, 403))
    return _secured(lab_json({"profile": accepted}))


@secure_bp.post("/lab/a09/fixed/login")
def a09_login():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", ""))
    password = str(data.get("password", ""))
    user = user_by_username(_conn(), username)
    success = user is not None and crypto.verify_password(user["argon2_password"], password)
    monitoring.record_login(
        current_app.extensions["security_log"],
        current_app.extensions["metrics"],
        username,
        success,
    )
    if not success:
        return _secured(lab_json({"ok": False}, 401))
    return _secured(lab_json({"ok": True}))


@secure_bp.get("/lab/a09/fixed/events")
def a09_events():
    return _secured(
        lab_json(
            {
                "events": current_app.extensions["security_log"],
                "auth_failure": current_app.extensions["metrics"]["auth_failure"],
            }
        )
    )


@secure_bp.post("/lab/a10/fixed/fetch")
def a10_fetch():
    data = request.get_json(silent=True) or {}
    url = str(data.get("url", ""))
    try:
        body = fetch(url)
    except FetchBlocked as exc:
        return _secured(lab_json({"error": str(exc)}, 403))
    except Exception:
        return _secured(lab_json({"error": "가져오기에 실패했습니다."}, 502))
    return _secured(lab_json({"body": body}))
