# znuzhgfw/main.py
import argparse
import sys
from pathlib import Path

from znuzhgfw.core.engine import run_scan
from znuzhgfw.core.utils import make_session
from znuzhgfw.core.logger import Logger
from znuzhgfw.core.report import Report
from znuzhgfw.scanners import (
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
)


def parse_args():
    parser = argparse.ArgumentParser(
        prog="znuzhgfw",
        description="ZNUZHG Pentest Framework - Web Vulnerability Scanner",
    )

    parser.add_argument("--url", required=True, help="Target URL to scan (e.g. https://example.com)")

    parser.add_argument("--threads", type=int, default=5, help="Number of worker threads")
    parser.add_argument("--depth", type=int, default=1, help="Crawler depth (default=1)")

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

    return parser.parse_args()


def main():
    try:
        args = parse_args()

        print(f"[+] Starting scan on: {args.url}")
        print(f"[+] Threads: {args.threads} | Depth: {args.depth}")

        # ---- SESSION ----
        session = make_session()
        if args.cookies:
            session.headers.update({"Cookie": args.cookies})
            for part in args.cookies.split(";"):
                if "=" in part:
                    k, v = part.strip().split("=", 1)
                    session.cookies.set(k.strip(), v.strip())

        # ---- LOGGER ----
        logger = Logger()

        # ---- REPORT OBJECT ----
        report = Report(args.url)

        # ---- SCANNER LIST ----
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

        # ---- RUN SCAN ----
        run_scan(
            base_url=args.url,
            session=session,
            logger=logger,
            report=report,
            scanner_classes=scanner_classes,
            depth=args.depth,
            threads=args.threads,
        )

        # ---- SELECT REPORT FILE ----
        if args.report_path:
            report_file = Path(args.report_path)
        else:
            report_file = Path("report.html")

        # ---- WRITE REPORT ----
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

    except Exception as e:
        print(f"[!] Error: {e}")
        try:
            logger.close()  # type: ignore[name-defined]
        except Exception:
            pass
        return 1


def MAIN():
    return main()

if __name__ == "__main__":
    sys.exit(main())
