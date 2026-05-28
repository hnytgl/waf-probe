from __future__ import annotations

import argparse
import sys

from .payloads import categories, select_payloads
from .prober import ProbeReport, WafProber


def parse_header(values: list[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for value in values:
        if ":" not in value:
            raise argparse.ArgumentTypeError(f"invalid header {value!r}, expected 'Name: value'")
        name, header_value = value.split(":", 1)
        headers[name.strip()] = header_value.strip()
    return headers


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="waf-probe",
        description="Defensively check whether a WAF is active and which rule categories appear enforced.",
    )
    parser.add_argument("url", help="Target URL you own or are authorized to test.")
    parser.add_argument("--method", default="GET", choices=["GET", "POST"], help="HTTP method to use.")
    parser.add_argument(
        "--location",
        default="query",
        choices=["query", "body", "header", "cookie", "user-agent"],
        help="Where to place probe payloads.",
    )
    parser.add_argument("--param", default="waf_probe", help="Parameter/header/cookie name for probe payloads.")
    parser.add_argument("--header", action="append", default=[], help="Extra header, e.g. 'Authorization: Bearer ...'.")
    parser.add_argument("--categories", help=f"Comma-separated categories. Available: {', '.join(categories())}.")
    parser.add_argument("--timeout", type=float, default=8.0, help="Request timeout in seconds.")
    parser.add_argument("--retries", type=int, default=1, help="Request attempts per probe.")
    parser.add_argument("--delay", type=float, default=0.0, help="Delay between probes in seconds.")
    parser.add_argument("--insecure", action="store_true", help="Disable TLS certificate verification.")
    parser.add_argument("--json", action="store_true", help="Print JSON report.")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        payloads = select_payloads(args.categories)
        headers = parse_header(args.header)
        prober = WafProber(
            url=args.url,
            method=args.method,
            location=args.location,
            param=args.param,
            headers=headers,
            timeout=args.timeout,
            retries=args.retries,
            delay=args.delay,
            verify_tls=not args.insecure,
        )
        report = prober.run(payloads)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(report.to_json())
    else:
        print_report(report)

    return 1 if report.has_findings else 0


def print_report(report: ProbeReport) -> None:
    baseline = report.baseline
    print(f"Target: {report.target}")
    print(f"Baseline: {baseline.status_code} {baseline.length} bytes {baseline.elapsed_ms} ms")
    if baseline.error:
        print(f"Baseline error: {baseline.error}")
    print()
    print(f"{'Category':<19} {'Payload':<24} {'Location':<11} {'Status':<11} {'HTTP':<6} Notes")
    print("-" * 92)
    for item in report.results:
        status = item.status_code if item.status_code is not None else "-"
        print(
            f"{item.category:<19} {item.payload:<24} {item.location:<11} "
            f"{item.verdict:<11} {status!s:<6} {item.notes}"
        )


if __name__ == "__main__":
    raise SystemExit(main())
