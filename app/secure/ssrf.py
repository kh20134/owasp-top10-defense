"""A10 안전 구현: 허용 목록, https, 공인 IP, 리다이렉트 거부."""

from __future__ import annotations

import ipaddress
import socket
import urllib.request
from urllib.parse import urlparse

ALLOWED_HOSTS = frozenset({"books.example"})


class FetchBlocked(Exception):
    pass


class _RejectRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise FetchBlocked("리다이렉트를 따르지 않습니다.")


def no_redirect_opener():
    return urllib.request.build_opener(_RejectRedirect)


def fetch(url: str, opener=None, resolver=None) -> str:
    parsed = urlparse(url)
    host = parsed.hostname
    if parsed.scheme != "https" or host not in ALLOWED_HOSTS:
        raise FetchBlocked("허용 목록에 없는 대상입니다.")
    if parsed.username or parsed.password or parsed.port not in (None, 443):
        raise FetchBlocked("허용되지 않은 URL 형식입니다.")

    resolve = resolver or socket.getaddrinfo
    try:
        infos = resolve(host, 443)
    except socket.gaierror as exc:
        raise FetchBlocked("주소를 확인할 수 없습니다.") from exc

    addresses = [item[4][0] for item in infos if item[0] in (socket.AF_INET, socket.AF_INET6)]
    if not addresses:
        raise FetchBlocked("주소를 확인할 수 없습니다.")
    for raw in addresses:
        ip = ipaddress.ip_address(raw)
        if not ip.is_global:
            raise FetchBlocked("공인 주소만 허용됩니다.")

    open_url = opener or no_redirect_opener().open
    request = urllib.request.Request(url, method="GET")
    with open_url(request, timeout=2) as response:
        payload = response.read(4096)
    return payload.decode("utf-8", errors="replace")
