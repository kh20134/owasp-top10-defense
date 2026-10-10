import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from app.secure.ssrf import fetch as fetch_fixed


class _MarkerHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"INTERNAL-LAB-MARKER"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        return


def _start_marker():
    server = HTTPServer(("127.0.0.1", 0), _MarkerHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def test_vulnerable_fetch_reads_loopback_service(client):
    server = _start_marker()
    port = server.server_address[1]
    try:
        response = client.post(
            "/lab/a10/vuln/fetch",
            json={"url": f"http://127.0.0.1:{port}/secret"},
        )
        assert response.status_code == 200
        assert response.get_json()["body"] == "INTERNAL-LAB-MARKER"
    finally:
        server.shutdown()


def test_fixed_fetch_blocks_unlisted_and_private_targets(client):
    server = _start_marker()
    port = server.server_address[1]
    try:
        loopback = client.post(
            "/lab/a10/fixed/fetch",
            json={"url": f"http://127.0.0.1:{port}/secret"},
        )
        assert loopback.status_code == 403
        assert "INTERNAL-LAB-MARKER" not in loopback.get_data(as_text=True)

        link_local = client.post(
            "/lab/a10/fixed/fetch",
            json={"url": "http://169.254.169.254/latest"},
        )
        assert link_local.status_code == 403
    finally:
        server.shutdown()


def test_fixed_fetch_allows_listed_public_https_host():
    captured = {}

    def resolver(host, port):
        assert host == "books.example"
        assert port == 443
        return [(2, 1, 6, "", ("93.184.216.34", 443))]

    def opener(request, timeout):
        captured["url"] = request.full_url
        captured["timeout"] = timeout

        class _Response:
            def read(self, limit):
                return b"catalog"

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        return _Response()

    body = fetch_fixed(
        "https://books.example/catalog",
        opener=opener,
        resolver=resolver,
    )
    assert body == "catalog"
    assert captured["url"] == "https://books.example/catalog"
