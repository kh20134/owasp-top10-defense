"""A06 취약 구현: 알려진 취약 핀이 있어도 그대로 통과시킨다."""

from __future__ import annotations

from app.advisories import find_advisories, parse_pins


def audit(text: str) -> dict:
    return {
        "enforced": False,
        "pins": [{"name": name, "version": version} for name, version in parse_pins(text)],
        "findings": find_advisories(text),
    }
