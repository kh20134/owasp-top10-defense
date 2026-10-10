"""127.0.0.1 에만 바인딩하는 실습 서버 진입점."""

from __future__ import annotations

import os

from werkzeug.serving import WSGIRequestHandler, make_server

from app import create_app
from app.guard import BIND_HOST

DEFAULT_PORT = 5000


class LabRequestHandler(WSGIRequestHandler):
    """개발 서버의 버전 문자열이 응답에 실리지 않게 한다."""

    def version_string(self) -> str:
        return "owasp-lab"


def main() -> None:
    port = int(os.environ.get("PORT", str(DEFAULT_PORT)))
    app = create_app()
    server = make_server(
        BIND_HOST,
        port,
        app,
        threaded=True,
        request_handler=LabRequestHandler,
    )
    print(f"로컬 실습 전용. http://{BIND_HOST}:{port} 에서만 수신합니다.")
    server.serve_forever()


if __name__ == "__main__":
    main()
