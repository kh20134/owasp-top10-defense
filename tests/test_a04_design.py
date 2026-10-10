from tests.conftest import ALICE


def test_vulnerable_reset_accepts_the_username_as_token(client):
    issued = client.post("/lab/a04/vuln/reset", json={"username": "alice"})
    assert issued.get_json()["token"] == "alice"
    confirmed = client.post(
        "/lab/a04/vuln/confirm",
        json={"username": "alice", "token": "alice", "new_password": "reset-pass"},
    )
    assert confirmed.status_code == 200
    login = client.post(
        "/lab/a02/vuln/login",
        json={"username": "alice", "password": "reset-pass"},
    )
    assert login.status_code == 200


def test_fixed_reset_rejects_guessable_token_and_reuses(client):
    client.post("/lab/a01/login", json=ALICE)
    issued = client.post("/lab/a04/fixed/reset", json={"username": "alice"})
    assert issued.get_json() == {"lab_only": True, "issued": True, "channel": "lab-inbox"}
    assert "token" not in issued.get_json()

    guessed = client.post(
        "/lab/a04/fixed/confirm",
        json={"username": "alice", "token": "alice", "new_password": "reset-pass"},
    )
    assert guessed.status_code == 400

    token = client.get("/lab/a04/fixed/inbox").get_json()["token"]
    assert token != "alice"
    assert len(token) >= 32

    first = client.post(
        "/lab/a04/fixed/confirm",
        json={"username": "alice", "token": token, "new_password": "reset-pass"},
    )
    assert first.status_code == 200
    second = client.post(
        "/lab/a04/fixed/confirm",
        json={"username": "alice", "token": token, "new_password": "reset-pass"},
    )
    assert second.status_code == 400


def test_fixed_reset_rejects_expired_token(client, app):
    client.post("/lab/a01/login", json=ALICE)
    client.post("/lab/a04/fixed/reset", json={"username": "alice"})
    app.extensions["db"].execute("UPDATE reset_tokens SET expires_at = 0")
    app.extensions["db"].commit()
    token = client.get("/lab/a04/fixed/inbox").get_json()["token"]
    response = client.post(
        "/lab/a04/fixed/confirm",
        json={"username": "alice", "token": token, "new_password": "reset-pass"},
    )
    assert response.status_code == 400
