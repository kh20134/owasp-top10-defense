from tests.conftest import ALICE


def test_vulnerable_login_enumerates_users_and_guessable_session(client, app):
    missing = client.post("/lab/a07/vuln/login", json={"username": "nobody", "password": "x"})
    wrong = client.post("/lab/a07/vuln/login", json={"username": "alice", "password": "wrong-password"})
    assert missing.get_json()["error"] != wrong.get_json()["error"]
    assert "사용자를 찾을 수 없습니다." in missing.get_json()["error"]

    for _ in range(6):
        response = client.post(
            "/lab/a07/vuln/login",
            json={"username": "alice", "password": "wrong-password"},
        )
        assert response.status_code == 401

    forged_client = app.test_client()
    forged_client.set_cookie("session_id", "2")
    forged = forged_client.get("/lab/a07/vuln/me")
    assert forged.status_code == 200
    assert forged.get_json()["username"] == "bob"


def test_fixed_login_hides_accounts_locks_out_and_rejects_guessed_session(client, app):
    app.config["AUTH_LOCKOUT_THRESHOLD"] = 3
    missing = client.post("/lab/a07/fixed/login", json={"username": "nobody", "password": "x"})
    wrong = client.post("/lab/a07/fixed/login", json={"username": "alice", "password": "wrong-password"})
    assert missing.status_code == 401
    assert missing.get_json()["error"] == wrong.get_json()["error"]

    client.post("/lab/a07/fixed/login", json={"username": "alice", "password": "wrong-password"})
    third = client.post(
        "/lab/a07/fixed/login",
        json={"username": "alice", "password": "wrong-password"},
    )
    assert third.status_code == 401

    locked = client.post("/lab/a07/fixed/login", json=ALICE)
    assert locked.status_code == 429

    guessed_client = app.test_client()
    guessed_client.set_cookie("session_id", "2")
    guessed = guessed_client.get("/lab/a07/fixed/me")
    assert guessed.status_code == 401

    app.extensions["lockouts"].pop("alice", None)
    fresh = app.test_client()
    ok = fresh.post("/lab/a07/fixed/login", json=ALICE)
    assert ok.status_code == 200
    cookie = ok.headers["Set-Cookie"]
    assert cookie.lower().count("session_id=") == 1
    assert not cookie.split(";", 1)[0].endswith("=1")
    assert "HttpOnly" in cookie
    me = fresh.get("/lab/a07/fixed/me")
    assert me.get_json()["username"] == "alice"
