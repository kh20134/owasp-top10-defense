def test_vulnerable_log_stores_the_password_and_skips_metrics(client):
    client.post(
        "/lab/a09/vuln/login",
        json={"username": "alice", "password": "wrong-password"},
    )
    body = client.get("/lab/a09/vuln/events").get_json()
    assert body["auth_failure"] == 0
    assert body["events"][0]["password"] == "wrong-password"


def test_fixed_log_omits_secrets_and_counts_failures(client):
    client.post(
        "/lab/a09/fixed/login",
        json={"username": "alice", "password": "wrong-password"},
    )
    body = client.get("/lab/a09/fixed/events").get_json()
    assert body["auth_failure"] == 1
    event = body["events"][0]
    assert event["event"] == "auth_failure"
    assert event["username"] == "alice"
    assert event["request_id"]
    assert "password" not in event
    assert "wrong-password" not in client.get("/lab/a09/fixed/events").get_data(as_text=True)
