"""A01 안전 구현: 로그인 사용자와 문서 소유자가 같을 때만 반환한다."""

from __future__ import annotations

import sqlite3

from app.db import document_by_id


class AuthRequired(Exception):
    pass


def read_document(conn: sqlite3.Connection, doc_id: int, user_id: int | None) -> dict | None:
    if user_id is None:
        raise AuthRequired
    row = document_by_id(conn, doc_id)
    if row is None or row["owner_id"] != user_id:
        return None
    return {"id": row["id"], "title": row["title"], "body": row["body"]}
