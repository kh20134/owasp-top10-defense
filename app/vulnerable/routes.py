"""취약 엔드포인트. 경로의 vuln 세그먼트와 이 패키지가 실습용임을 표시한다."""

from __future__ import annotations

import sqlite3
import traceback

from flask import Blueprint, current_app, request

from app.advisories import read_manifest
from app.db import update_password, user_by_username
from app.http import lab_json
from app.vulnerable import access, authn, components, crypto, design, injection, integrity, monitoring
from app.vulnerable.ssrf import FetchBlocked, fetch

vulnerable_bp = Blueprint("vulnerable", __name__)


def _conn():
    return current_app.extensions["db"]


@vulnerable_bp.get("/lab/a01/vuln/documents/<int:doc_id>")
def a01_document(doc_id: int):
    document = access.read_document(_conn(), doc_id)
    if document is None:
        return lab_json({"error": "문서를 찾을 수 없습니다."}, 404)
    return lab_json({"document": document})


@vulnerable_bp.post("/lab/a02/vuln/login")
def a02_login():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", ""))
    password = str(data.get("password", ""))
    user = user_by_username(_conn(), username)
    if user is None or user["md5_password"] != crypto.weak_md5(password):
        return lab_json({"ok": False}, 401)
    return lab_json({"ok": True, "scheme": "md5"})


@vulnerable_bp.get("/lab/a02/vuln/stored/<username>")
def a02_stored(username: str):
    user = user_by_username(_conn(), username)
    if user is None:
        return lab_json({"error": "없음"}, 404)
    return lab_json({"scheme": "md5", "hash": user["md5_password"]})


@vulnerable_bp.get("/lab/a03/vuln/notes")
def a03_notes():
    raw_id = request.args.get("id", "")
    try:
        rows = injection.search_notes(_conn(), raw_id)
    except sqlite3.Error:
        return lab_json({"error": "조회에 실패했습니다."}, 400)
    return lab_json({"notes": rows})


@vulnerable_bp.post("/lab/a03/vuln/echo")
def a03_echo():
    data = request.get_json(silent=True) or {}
    text = str(data.get("text", ""))
    response = current_app.response_class(injection.render_echo(text), mimetype="text/html")
    response.headers["X-Lab-Only"] = "localhost-training"
    response.headers["X-Powered-By"] = "LabDebug/0.1"
    return response


@vulnerable_bp.post("/lab/a04/vuln/reset")
def a04_reset():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", ""))
    token = design.issue_token(username)
    return lab_json({"issued": True, "token": token})


@vulnerable_bp.post("/lab/a04/vuln/confirm")
def a04_confirm():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", ""))
    token = str(data.get("token", ""))
    new_password = str(data.get("new_password", ""))
    if not design.token_matches(username, token) or user_by_username(_conn(), username) is None:
        return lab_json({"ok": False}, 400)
    if len(new_password) < 8:
        return lab_json({"error": "비밀번호가 너무 짧습니다."}, 400)
    update_password(_conn(), username, new_password)
    return lab_json({"ok": True})


@vulnerable_bp.get("/lab/a05/vuln/profile")
def a05_profile():
    response = lab_json({"profile": "lab"})
    response.headers["Set-Cookie"] = "prefs=open"
    response.headers["X-Powered-By"] = "LabDebug/0.1"
    return response


@vulnerable_bp.get("/lab/a05/vuln/debug")
def a05_debug():
    try:
        raise ZeroDivisionError("lab-divide")
    except ZeroDivisionError:
        body = traceback.format_exc()
    response = current_app.response_class(body, status=500, mimetype="text/plain")
    response.headers["X-Powered-By"] = "LabDebug/0.1"
    response.headers["X-Lab-Only"] = "localhost-training"
    return response


@vulnerable_bp.get("/lab/a06/vuln/audit")
def a06_audit():
    name = request.args.get("manifest", "demo")
    try:
        text = read_manifest(name)
    except KeyError:
        return lab_json({"error": "알 수 없는 목록입니다."}, 400)
    return lab_json(components.audit(text))


@vulnerable_bp.post("/lab/a07/vuln/login")
def a07_login():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", ""))
    password = str(data.get("password", ""))
    user = user_by_username(_conn(), username)
    matched = user is not None and user["md5_password"] == crypto.weak_md5(password)
    if not matched:
        return lab_json({"error": authn.failure_message(user_exists=user is not None)}, 401)
    response = lab_json({"ok": True, "username": user["username"]})
    response.set_cookie("session_id", authn.session_cookie_value(user["id"]))
    return response


@vulnerable_bp.get("/lab/a07/vuln/me")
def a07_me():
    raw = request.cookies.get("session_id", "")
    if not raw.isdigit():
        return lab_json({"error": "세션이 없습니다."}, 401)
    row = _conn().execute("SELECT username FROM users WHERE id = ?", (int(raw),)).fetchone()
    if row is None:
        return lab_json({"error": "세션이 없습니다."}, 401)
    return lab_json({"username": row["username"]})


@vulnerable_bp.post("/lab/a08/vuln/profile")
def a08_profile():
    payload = request.get_json(silent=True) or {}
    if not isinstance(payload, dict):
        return lab_json({"error": "형식이 올바르지 않습니다."}, 400)
    return lab_json({"profile": integrity.accept_profile(payload)})


@vulnerable_bp.post("/lab/a09/vuln/login")
def a09_login():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", ""))
    password = str(data.get("password", ""))
    user = user_by_username(_conn(), username)
    success = user is not None and user["md5_password"] == crypto.weak_md5(password)
    monitoring.record_login(current_app.extensions["vuln_log"], username, password, success)
    if not success:
        return lab_json({"ok": False}, 401)
    return lab_json({"ok": True})


@vulnerable_bp.get("/lab/a09/vuln/events")
def a09_events():
    return lab_json(
        {
            "events": current_app.extensions["vuln_log"],
            "auth_failure": current_app.extensions["metrics"]["auth_failure"],
        }
    )


@vulnerable_bp.post("/lab/a10/vuln/fetch")
def a10_fetch():
    data = request.get_json(silent=True) or {}
    url = str(data.get("url", ""))
    try:
        body = fetch(url)
    except FetchBlocked as exc:
        return lab_json({"error": str(exc)}, 400)
    except Exception:
        return lab_json({"error": "가져오기에 실패했습니다."}, 502)
    return lab_json({"body": body})
