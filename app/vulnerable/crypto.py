"""A02 취약 구현: 솔트 없는 MD5."""

from __future__ import annotations

import hashlib


def weak_md5(value: str) -> str:
    return hashlib.md5(value.encode("utf-8")).hexdigest()
