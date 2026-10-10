PAYLOAD = "1 OR 1=1"
XSS = "<script>alert(1)</script>"


def test_vulnerable_sqli_returns_every_note(client):
    response = client.get("/lab/a03/vuln/notes", query_string={"id": PAYLOAD})
    assert response.status_code == 200
    bodies = [note["body"] for note in response.get_json()["notes"]]
    assert "hello" in bodies
    assert "bob-secret-note" in bodies


def test_fixed_sqli_returns_no_rows(client):
    blocked = client.get("/lab/a03/fixed/notes", query_string={"id": PAYLOAD})
    assert blocked.status_code == 200
    assert blocked.get_json()["notes"] == []

    allowed = client.get("/lab/a03/fixed/notes", query_string={"id": "1"})
    assert [note["body"] for note in allowed.get_json()["notes"]] == ["hello"]


def test_vulnerable_xss_reflects_markup(client):
    response = client.post("/lab/a03/vuln/echo", json={"text": XSS})
    page = response.get_data(as_text=True)
    assert response.status_code == 200
    assert XSS in page
    assert "Content-Security-Policy" not in response.headers


def test_fixed_xss_escapes_and_sets_csp(client):
    response = client.post("/lab/a03/fixed/echo", json={"text": XSS})
    page = response.get_data(as_text=True)
    assert XSS not in page
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page
    policy = response.headers["Content-Security-Policy"]
    assert "script-src 'none'" in policy
