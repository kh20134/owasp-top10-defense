"""A06 안전 구현: 권고에 걸린 핀이 있으면 배포를 거부한다."""

from __future__ import annotations

from app.advisories import find_advisories, parse_pins


def audit(text: str) -> dict:
    findings = find_advisories(text)
    return {
        "enforced": True,
        "pins": [{"name": name, "version": version} for name, version in parse_pins(text)],
        "findings": findings,
        "blocked": bool(findings),
    }
