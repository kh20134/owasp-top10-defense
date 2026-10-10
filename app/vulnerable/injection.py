"""A03 취약 구현: SQL 이어붙이기와 이스케이프하지 않은 HTML."""

from __future__ import annotations

import sqlite3


def search_notes(conn: sqlite3.Connection, raw_id: str) -> list[dict]:
    query = f"SELECT id, title, body FROM notes WHERE id = {raw_id}"
    rows = conn.execute(query).fetchall()
    return [{"id": row["id"], "title": row["title"], "body": row["body"]} for row in rows]


def render_echo(text: str) -> str:
    return (
        "<!DOCTYPE html><html lang=\"ko\"><head><meta charset=\"utf-8\">"
        "<title>로컬 실습</title></head><body>"
        "<p>로컬 실습 전용</p>"
        f"<div id=\"echo\">{text}</div>"
        "</body></html>"
    )
