def test_vulnerable_audit_accepts_known_bad_pins(client):
    response = client.get("/lab/a06/vuln/audit", query_string={"manifest": "demo"})
    assert response.status_code == 200
    body = response.get_json()
    assert body["enforced"] is False
    ids = {item["id"] for item in body["findings"]}
    assert "CVE-2020-14343" in ids
    assert "CVE-2021-33203" in ids


def test_fixed_audit_blocks_bad_pins_and_accepts_runtime(client):
    blocked = client.get("/lab/a06/fixed/audit", query_string={"manifest": "demo"})
    assert blocked.status_code == 409
    ids = {item["id"] for item in blocked.get_json()["findings"]}
    assert "CVE-2020-14343" in ids

    clean = client.get("/lab/a06/fixed/audit", query_string={"manifest": "runtime"})
    assert clean.status_code == 200
    assert clean.get_json()["findings"] == []
    assert clean.get_json()["blocked"] is False
