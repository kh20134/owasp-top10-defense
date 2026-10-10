from app.secure.crypto import hash_password, verify_password
from app.vulnerable.crypto import weak_md5
from tests.conftest import ALICE


def test_md5_is_unsalted_and_exposed(client):
    stored = client.get("/lab/a02/vuln/stored/alice")
    body = stored.get_json()
    assert body["scheme"] == "md5"
    assert body["hash"] == weak_md5(ALICE["password"])
    assert weak_md5(ALICE["password"]) == weak_md5(ALICE["password"])

    login = client.post("/lab/a02/vuln/login", json=ALICE)
    assert login.status_code == 200
    assert login.get_json()["scheme"] == "md5"


def test_fixed_uses_argon2_and_does_not_expose_the_hash(client, app):
    first = hash_password(ALICE["password"])
    second = hash_password(ALICE["password"])
    assert first != second
    assert first.startswith("$argon2")
    assert verify_password(first, ALICE["password"])
    assert not verify_password(first, "wrong-password")

    stored = client.get("/lab/a02/fixed/stored/alice")
    payload = stored.get_json()
    assert payload["scheme"] == "argon2id"
    assert payload["exposed"] is False
    row = app.extensions["db"].execute(
        "SELECT argon2_password FROM users WHERE username = 'alice'"
    ).fetchone()
    assert row["argon2_password"] not in stored.get_data(as_text=True)

    login = client.post("/lab/a02/fixed/login", json=ALICE)
    assert login.status_code == 200
    assert login.get_json()["scheme"] == "argon2id"
    rejected = client.post(
        "/lab/a02/fixed/login",
        json={"username": "alice", "password": "wrong-password"},
    )
    assert rejected.status_code == 401
