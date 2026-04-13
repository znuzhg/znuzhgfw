# znuzhgfw/main.py
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from znuzhgfw.core.engine import run_scan
from znuzhgfw.core.logger import Logger
from znuzhgfw.core.report import Report
from znuzhgfw.core.utils import ScanConfig, make_session
from znuzhgfw.scanners import (
    CRLFScanner,
    DrScanScanner,
    HeaderScanner,
    LFIScanner,
    MethodScanner,
    RateLmtScanner,
    RedrectScanner,
    SQLScanner,
    SSTIScanner,
    WAFScanner,
    XSSScanner,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="znuzhgfw",
        description="ZNUZHG Pentest Framework - Web Vulnerability Scanner",
    )
    parser.add_argument(
        "--url",
        required=True,
        help="Target URL to scan (e.g. https://example.com)",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=5,
        help="Number of worker threads",
    )
    parser.add_argument(
        "--depth",
        type=int,
        default=1,
        help="Crawler depth (default=1)",
    )
    parser.add_argument("--cookies", help="Cookie header")
    parser.add_argument(
        "--report-format",
        choices=["html", "json", "md", "markdown"],
        default="html",
        help="Report format",
    )
    parser.add_argument(
        "--out",
        "--report",
        dest="report_path",
        help="Report file output (default: report.html)",
    )
    parser.add_argument(
        "--include-static",
        action="store_true",
        help="Include static assets in crawl inventory without actively scanning them",
    )
    parser.add_argument(
        "--scan-assets",
        action="store_true",
        help="Actively scan static assets as part of the crawl scope",
    )
    parser.add_argument(
        "--confidence-threshold",
        choices=["low", "medium", "high"],
        default="low",
        help="Minimum confidence level to keep in the report",
    )
    parser.add_argument(
        "--proof-threshold",
        choices=["pattern", "heuristic", "reflected", "verified"],
        default="pattern",
        help="Minimum proof level to keep in the report",
    )
    parser.add_argument(
        "--dedupe",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Enable or disable finding deduplication",
    )
    parser.add_argument(
        "--max-urls",
        type=int,
        help="Maximum number of URLs to crawl",
    )
    parser.add_argument(
        "--skip-rate-limit",
        action="store_true",
        help="Disable rate limit checks",
    )
    parser.add_argument(
        "--skip-headers",
        action="store_true",
        help="Disable security header checks",
    )
    parser.add_argument(
        "--skip-dirscan",
        action="store_true",
        help="Disable common path discovery",
    )
    return parser.parse_args()


def build_scan_config(args: argparse.Namespace) -> ScanConfig:
    return ScanConfig(
        include_static=args.include_static or args.scan_assets,
        scan_assets=args.scan_assets,
        dedupe=args.dedupe,
        confidence_threshold=args.confidence_threshold.upper(),
        proof_threshold=args.proof_threshold,
        max_urls=args.max_urls,
        skip_rate_limit=args.skip_rate_limit,
        skip_headers=args.skip_headers,
        skip_dirscan=args.skip_dirscan,
    )


def build_scanner_classes(args: argparse.Namespace):
    scanner_classes = [
        SQLScanner,
        XSSScanner,
        LFIScanner,
        DrScanScanner,
        HeaderScanner,
        MethodScanner,
        RateLmtScanner,
        RedrectScanner,
        CRLFScanner,
        SSTIScanner,
        WAFScanner,
    ]

    if args.skip_headers:
        scanner_classes = [cls for cls in scanner_classes if cls is not HeaderScanner]
    if args.skip_rate_limit:
        scanner_classes = [cls for cls in scanner_classes if cls is not RateLmtScanner]
    if args.skip_dirscan:
        scanner_classes = [cls for cls in scanner_classes if cls is not DrScanScanner]

    return scanner_classes


def main() -> int:
    logger: Logger | None = None
    try:
        args = parse_args()
        config = build_scan_config(args)

        print(f"[+] Starting scan on: {args.url}")
        print(f"[+] Threads: {args.threads} | Depth: {args.depth}")
        print(
            "[+] Noise controls: "
            f"dedupe={config.dedupe} include_static={config.include_static} "
            f"scan_assets={config.scan_assets} confidence>={config.confidence_threshold} "
            f"proof>={config.proof_threshold}"
        )

        session = make_session()
        if args.cookies:
            session.headers.update({"Cookie": args.cookies})
            for part in args.cookies.split(";"):
                if "=" not in part:
                    continue
                key, value = part.strip().split("=", 1)
                session.cookies.set(key.strip(), value.strip())

        logger = Logger()
        report = Report(
            args.url,
            dedupe=config.dedupe,
            confidence_threshold=config.confidence_threshold,
            proof_threshold=config.proof_threshold,
        )
        scanner_classes = build_scanner_classes(args)

        run_scan(
            base_url=args.url,
            session=session,
            logger=logger,
            report=report,
            scanner_classes=scanner_classes,
            depth=args.depth,
            threads=args.threads,
            config=config,
        )

        report_file = Path(args.report_path) if args.report_path else Path("report.html")
        fmt = args.report_format.lower()
        if fmt == "html":
            report.write_html(report_file)
        elif fmt in ("md", "markdown"):
            report.write_markdown(report_file)
        elif fmt == "json":
            report.write_json(report_file)

        print(f"[+] Report written to: {report_file}")
        logger.close()
        return 0
    except Exception as exc:
        print(f"[!] Error: {exc}")
        if logger is not None:
            logger.close()
        return 1


def MAIN() -> int:
    return main()


if __name__ == "__main__":
    sys.exit(main())
