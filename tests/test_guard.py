from app.guard import BIND_HOST


def test_server_bind_constant_is_loopback():
    assert BIND_HOST == "127.0.0.1"


def test_non_loopback_clients_are_rejected(client):
    response = client.get("/", environ_base={"REMOTE_ADDR": "10.1.2.3"})
    assert response.status_code == 403
    assert "로컬호스트" in response.get_data(as_text=True)


def test_index_is_marked_lab_only_and_sends_headers(client):
    response = client.get("/")
    assert response.status_code == 200
    assert "로컬 실습 전용" in response.get_data(as_text=True)
    assert response.headers["X-Lab-Only"] == "localhost-training"
    assert response.headers["Content-Security-Policy"]
