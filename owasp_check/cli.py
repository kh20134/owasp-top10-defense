"""owasp-check 명령줄. 기본 대상은 로컬 실습 서버다."""

from __future__ import annotations

import argparse
import json
import sys

from owasp_check.scanner import ScanError, render_korean, scan

DEFAULT_URL = "http://127.0.0.1:5000/"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="owasp-check",
        description="로컬 실습 서버의 보안 헤더와 쿠키 플래그를 점검합니다.",
    )
    parser.add_argument("--url", default=DEFAULT_URL, help=f"점검할 URL (기본값: {DEFAULT_URL})")
    parser.add_argument("--json", action="store_true", help="JSON으로 출력합니다.")
    parser.add_argument("--timeout", type=float, default=5.0, help="연결 제한 시간(초)")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        report = scan(args.url, timeout=args.timeout)
    except ScanError as exc:
        print(f"점검 실패: {exc}", file=sys.stderr)
        return 2
    if args.json:
        json.dump(report.to_dict(), sys.stdout, ensure_ascii=False, indent=2)
        sys.stdout.write("\n")
    else:
        print(render_korean(report))
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
