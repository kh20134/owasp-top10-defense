"""A10 취약 구현: 사용자가 준 http(s) URL을 그대로 가져온다.

file 스킴은 실습 범위를 넘으므로 거절한다. 타임아웃과 본문 길이만 제한한다.
"""

from __future__ import annotations

import urllib.request
from urllib.parse import urlparse


class FetchBlocked(Exception):
    pass


def fetch(url: str, opener=None) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise FetchBlocked("http와 https만 실습 대상이다.")
    open_url = opener or urllib.request.urlopen
    with open_url(url, timeout=2) as response:
        payload = response.read(4096)
    return payload.decode("utf-8", errors="replace")
