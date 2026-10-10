"""A03 안전 구현: 바인딩 파라미터와 HTML 이스케이프."""

from __future__ import annotations

import html
import sqlite3


def search_notes(conn: sqlite3.Connection, raw_id: str) -> list[dict]:
    if not raw_id.isdigit():
        return []
    rows = conn.execute(
        "SELECT id, title, body FROM notes WHERE id = ?",
        (int(raw_id),),
    ).fetchall()
    return [{"id": row["id"], "title": row["title"], "body": row["body"]} for row in rows]


def render_echo(text: str) -> str:
    safe = html.escape(text, quote=True)
    return (
        "<!DOCTYPE html><html lang=\"ko\"><head><meta charset=\"utf-8\">"
        "<title>로컬 실습</title></head><body>"
        "<p>로컬 실습 전용</p>"
        f"<div id=\"echo\">{safe}</div>"
        "</body></html>"
    )
