"""실습용 인메모리 SQLite. 계정 시드는 취약 해시와 Argon2 해시를 함께 둔다."""

from __future__ import annotations

import sqlite3

from argon2 import PasswordHasher

from app.vulnerable.crypto import weak_md5

SCHEMA = """
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    md5_password TEXT NOT NULL,
    argon2_password TEXT NOT NULL
);
CREATE TABLE documents (
    id INTEGER PRIMARY KEY,
    owner_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    body TEXT NOT NULL
);
CREATE TABLE notes (
    id INTEGER PRIMARY KEY,
    title TEXT NOT NULL,
    body TEXT NOT NULL
);
CREATE TABLE reset_tokens (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL,
    token_hash TEXT NOT NULL,
    expires_at REAL NOT NULL,
    used INTEGER NOT NULL DEFAULT 0
);
"""


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn


def seed(conn: sqlite3.Connection) -> None:
    hasher = PasswordHasher()
    accounts = (("alice", "alice-lab-pass"), ("bob", "bob-lab-pass"))
    for username, passphrase in accounts:
        conn.execute(
            "INSERT INTO users (username, md5_password, argon2_password) VALUES (?, ?, ?)",
            (username, weak_md5(passphrase), hasher.hash(passphrase)),
        )
    conn.executemany(
        "INSERT INTO documents (owner_id, title, body) VALUES (?, ?, ?)",
        (
            (1, "alice-memo", "alice-only-memo"),
            (2, "bob-memo", "bob-only-memo"),
        ),
    )
    conn.executemany(
        "INSERT INTO notes (title, body) VALUES (?, ?)",
        (
            ("공개 메모", "hello"),
            ("비밀 메모", "bob-secret-note"),
        ),
    )
    conn.commit()


def user_by_username(conn: sqlite3.Connection, username: str) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT id, username, md5_password, argon2_password FROM users WHERE username = ?",
        (username,),
    ).fetchone()


def document_by_id(conn: sqlite3.Connection, doc_id: int) -> sqlite3.Row | None:
    return conn.execute(
        "SELECT id, owner_id, title, body FROM documents WHERE id = ?",
        (doc_id,),
    ).fetchone()


def update_password(conn: sqlite3.Connection, username: str, passphrase: str) -> None:
    hasher = PasswordHasher()
    conn.execute(
        "UPDATE users SET md5_password = ?, argon2_password = ? WHERE username = ?",
        (weak_md5(passphrase), hasher.hash(passphrase), username),
    )
    conn.commit()
