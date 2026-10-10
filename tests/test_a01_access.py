from tests.conftest import ALICE


def test_vulnerable_document_is_readable_without_owner(client):
    response = client.get("/lab/a01/vuln/documents/2")
    assert response.status_code == 200
    assert response.get_json()["document"]["body"] == "bob-only-memo"


def test_fixed_document_blocks_other_users_and_anonymous(client):
    anonymous = client.get("/lab/a01/fixed/documents/2")
    assert anonymous.status_code == 401

    login = client.post("/lab/a01/login", json=ALICE)
    assert login.status_code == 200

    denied = client.get("/lab/a01/fixed/documents/2")
    assert denied.status_code == 404
    assert "bob-only-memo" not in denied.get_data(as_text=True)

    allowed = client.get("/lab/a01/fixed/documents/1")
    assert allowed.status_code == 200
    assert allowed.get_json()["document"]["body"] == "alice-only-memo"
