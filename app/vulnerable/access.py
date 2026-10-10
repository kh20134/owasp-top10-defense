"""A01 취약 구현: 소유자 확인 없이 문서를 반환한다."""

from __future__ import annotations

import sqlite3

from app.db import document_by_id


def read_document(conn: sqlite3.Connection, doc_id: int) -> dict | None:
    row = document_by_id(conn, doc_id)
    if row is None:
        return None
    return {"id": row["id"], "title": row["title"], "body": row["body"]}
