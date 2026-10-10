def test_vulnerable_profile_trusts_client_role(client):
    response = client.post(
        "/lab/a08/vuln/profile",
        json={"username": "alice", "role": "admin"},
    )
    assert response.status_code == 200
    assert response.get_json()["profile"]["role"] == "admin"
    assert response.get_json()["profile"]["verified"] is False


def test_fixed_profile_rejects_tampered_role(client):
    issued = client.post("/lab/a08/fixed/issue", json={"username": "alice"})
    profile = issued.get_json()["profile"]
    assert profile["role"] == "user"

    accepted = client.post("/lab/a08/fixed/profile", json=profile)
    assert accepted.status_code == 200
    assert accepted.get_json()["profile"]["verified"] is True

    tampered = dict(profile)
    tampered["role"] = "admin"
    rejected = client.post("/lab/a08/fixed/profile", json=tampered)
    assert rejected.status_code == 403
