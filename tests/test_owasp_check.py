import json
import threading

from werkzeug.serving import make_server

from app import create_app
from owasp_check.cli import main
from owasp_check.scanner import render_korean, scan


def _serve(app):
    server = make_server("127.0.0.1", 0, app, threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def test_scanner_reports_vulnerable_profile_and_passes_fixed_profile():
    app = create_app()
    server = _serve(app)
    port = server.server_address[1]
    try:
        vuln_url = f"http://127.0.0.1:{port}/lab/a05/vuln/profile"
        fixed_url = f"http://127.0.0.1:{port}/lab/a05/fixed/profile"
        vuln = scan(vuln_url)
        fixed = scan(fixed_url)
        assert vuln.ok is False
        ids = {item.check_id for item in vuln.findings}
        assert "header.content-security-policy" in ids
        assert "cookie.flags" in ids
        text = render_korean(vuln)
        assert "OWASP 설정 점검 보고서" in text
        assert "결과: 실패" in text
        assert "Content-Security-Policy 헤더가 없습니다." in text
        assert fixed.ok is True
        assert "결과: 통과" in render_korean(fixed)
    finally:
        server.shutdown()


def test_cli_json_and_exit_codes():
    app = create_app()
    server = _serve(app)
    port = server.server_address[1]
    try:
        vuln_url = f"http://127.0.0.1:{port}/lab/a05/vuln/profile"
        fixed_url = f"http://127.0.0.1:{port}/lab/a05/fixed/profile"
        assert main(["--url", fixed_url, "--json"]) == 0
        assert main(["--url", vuln_url]) == 1
        assert main(["--url", "http://127.0.0.1:1/"]) == 2
    finally:
        server.shutdown()


def test_cli_json_contains_korean_messages(capsys):
    app = create_app()
    server = _serve(app)
    port = server.server_address[1]
    try:
        code = main(
            ["--url", f"http://127.0.0.1:{port}/lab/a05/vuln/profile", "--json"]
        )
        assert code == 1
        payload = json.loads(capsys.readouterr().out)
        assert payload["ok"] is False
        messages = [item["message"] for item in payload["findings"]]
        assert any("Content-Security-Policy" in message for message in messages)
    finally:
        server.shutdown()
