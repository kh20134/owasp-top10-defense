"""런타임 구성요소 점검에 쓰는 공개 권고 스냅샷.

수치는 pip-audit(PyPI advisory)로 확인한 식별자다.
- pyyaml 5.3.1 → CVE-2020-14343, 수정 버전 5.4
- django 1.11.29 → CVE-2021-33203 (지원이 끝난 1.11 계열에 남아 있는 권고)
라이브 감사는 CI의 pip-audit 가 requirements.txt 로 수행한다.
"""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

MANIFESTS = {
    "demo": ROOT / "fixtures" / "demo-vulnerable-requirements.txt",
    "runtime": ROOT / "requirements.txt",
}

ADVISORIES = (
    {
        "name": "pyyaml",
        "version": "5.3.1",
        "id": "CVE-2020-14343",
        "fix_version": "5.4",
    },
    {
        "name": "django",
        "version": "1.11.29",
        "id": "CVE-2021-33203",
        "fix_version": "2.2.24",
    },
)


def parse_pins(text: str) -> list[tuple[str, str]]:
    pins: list[tuple[str, str]] = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if "==" not in line:
            continue
        name, version = line.split("==", 1)
        pins.append((name.strip().lower(), version.strip()))
    return pins


def find_advisories(text: str) -> list[dict[str, str]]:
    pinned = set(parse_pins(text))
    found: list[dict[str, str]] = []
    for item in ADVISORIES:
        if (item["name"], item["version"]) in pinned:
            found.append(dict(item))
    return found


def read_manifest(name: str) -> str:
    try:
        path = MANIFESTS[name]
    except KeyError as exc:
        raise KeyError(name) from exc
    return path.read_text(encoding="utf-8")
