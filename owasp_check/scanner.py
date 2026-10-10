"""응답 헤더와 Set-Cookie 플래그만 읽는다. 공격 페이로드는 보내지 않는다."""

from __future__ import annotations

import http.client
import urllib.parse
from dataclasses import dataclass, field


class ScanError(Exception):
    pass


@dataclass
class Finding:
    check_id: str
    severity: str
    message: str


@dataclass
class Report:
    target: str
    findings: list[Finding] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.findings

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "ok": self.ok,
            "finding_count": len(self.findings),
            "findings": [
                {
                    "check_id": item.check_id,
                    "severity": item.severity,
                    "message": item.message,
                }
                for item in self.findings
            ],
        }


SEVERITY_KO = {"high": "높음", "medium": "중간", "low": "낮음"}


def render_korean(report: Report) -> str:
    lines = [
        "OWASP 설정 점검 보고서",
        f"대상: {report.target}",
    ]
    if report.ok:
        lines.append("결과: 통과 (발견된 설정 문제 없음)")
    else:
        lines.append(f"결과: 실패 ({len(report.findings)}건)")
    lines.append("")
    if report.findings:
        for item in report.findings:
            label = SEVERITY_KO.get(item.severity, item.severity)
            lines.append(f"[{label}] {item.message}")
            lines.append(f"    항목: {item.check_id}")
    else:
        lines.append("보안 헤더와 쿠키 플래그가 기대값과 일치합니다.")
    lines.append("")
    lines.append("점검 범위: Content-Security-Policy, X-Content-Type-Options,")
    lines.append("X-Frame-Options, Referrer-Policy, Strict-Transport-Security,")
    lines.append("Permissions-Policy, Set-Cookie의 HttpOnly·Secure·SameSite.")
    lines.append("실습 전용 도구입니다. 공격 페이로드는 보내지 않습니다.")
    return "\n".join(lines)


def fetch_headers(url: str, timeout: float) -> tuple[int, dict[str, list[str]]]:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ScanError("http 또는 https URL만 점검합니다.")
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    port = parsed.port
    if port is None:
        port = 443 if parsed.scheme == "https" else 80
    try:
        if parsed.scheme == "https":
            connection = http.client.HTTPSConnection(parsed.hostname, port, timeout=timeout)
        else:
            connection = http.client.HTTPConnection(parsed.hostname, port, timeout=timeout)
        connection.request("GET", path, headers={"User-Agent": "owasp-check"})
        response = connection.getresponse()
        headers: dict[str, list[str]] = {}
        for key, value in response.getheaders():
            headers.setdefault(key.lower(), []).append(value)
        response.read()
        connection.close()
    except OSError as exc:
        raise ScanError(f"대상에 연결하지 못했습니다. ({exc})") from exc
    return response.status, headers


def _cookie_flags(set_cookie: str) -> set[str]:
    parts = [part.strip() for part in set_cookie.split(";")[1:]]
    flags: set[str] = set()
    for part in parts:
        name = part.split("=", 1)[0].strip().lower()
        if name:
            flags.add(name)
    return flags


def scan(url: str, timeout: float = 5.0) -> Report:
    _status, headers = fetch_headers(url, timeout)
    findings: list[Finding] = []

    def missing(header: str) -> bool:
        return header.lower() not in headers or not headers[header.lower()][0].strip()

    if missing("content-security-policy"):
        findings.append(
            Finding(
                "header.content-security-policy",
                "high",
                "Content-Security-Policy 헤더가 없습니다.",
            )
        )
    xcto = headers.get("x-content-type-options", [""])[0].strip().lower()
    if xcto != "nosniff":
        findings.append(
            Finding(
                "header.x-content-type-options",
                "high",
                "X-Content-Type-Options 헤더가 없거나 nosniff가 아닙니다.",
            )
        )
    xfo = headers.get("x-frame-options", [""])[0].strip().upper()
    if xfo not in {"DENY", "SAMEORIGIN"}:
        findings.append(
            Finding(
                "header.x-frame-options",
                "high",
                "X-Frame-Options 헤더가 없거나 DENY/SAMEORIGIN이 아닙니다.",
            )
        )
    if missing("referrer-policy"):
        findings.append(
            Finding(
                "header.referrer-policy",
                "medium",
                "Referrer-Policy 헤더가 없습니다.",
            )
        )
    hsts = headers.get("strict-transport-security", [""])[0].lower()
    if "max-age=" not in hsts:
        findings.append(
            Finding(
                "header.strict-transport-security",
                "medium",
                "Strict-Transport-Security 헤더가 없습니다. HTTPS 배포에서 필요합니다.",
            )
        )
    if missing("permissions-policy"):
        findings.append(
            Finding(
                "header.permissions-policy",
                "low",
                "Permissions-Policy 헤더가 없습니다.",
            )
        )

    for cookie in headers.get("set-cookie", []):
        flags = _cookie_flags(cookie)
        if "httponly" not in flags or "secure" not in flags or "samesite" not in flags:
            findings.append(
                Finding(
                    "cookie.flags",
                    "high",
                    "Set-Cookie에 HttpOnly, Secure, SameSite 중 빠진 플래그가 있습니다.",
                )
            )
            break

    return Report(target=url, findings=findings)
