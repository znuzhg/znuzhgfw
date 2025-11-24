import argparse

from core.logger import Logger
from core.report import Report
from core.utils import make_session
from core.engine import run_scan
from scanners.sqli import SQLiScanner
from scanners.xss import XSSScanner
from scanners.lfi import LFIScanner
from scanners.redirect import RedirectScanner
from scanners.headers import HeaderScanner
from scanners.ratelimit import RateLimitScanner
from scanners.waf import WAFScanner
from scanners.ssti import SSTIScanner
from scanners.crlf import CRLFScanner
from scanners.methods import MethodsScanner
from scanners.dirscan import DirectoryScanner


def parse_args():
    parser = argparse.ArgumentParser(
        description="ZNUZHG Pentest Framework v0.2 – ONLY FOR AUTHORIZED TESTING"
    )
    parser.add_argument("--url", required=True, help="Target URL (e.g., https://example.com/)")
    parser.add_argument("--depth", type=int, default=1, help="Crawl depth (default: 1)")
    parser.add_argument("--threads", type=int, default=5, help="Worker threads (default: 5)")
    parser.add_argument("--cookies", default="", help='Cookies string: "k1=v1; k2=v2"')
    parser.add_argument("--report-md", default="report.md", help="Markdown report path")
    parser.add_argument("--report-html", default="report.html", help="HTML report path")
    parser.add_argument(
        "--log-dir", default="logs", help="Log directory (default: logs)"
    )
    parser.add_argument(
        "--modules",
        default="all",
        help="Modules to run (comma-separated: sqli,xss,lfi,redir,headers,rate,waf,ssti,crlf,methods,dirscan or 'all')",
    )
    return parser.parse_args()


def build_scanner_class_list(modules_str: str):
    all_modules = {
        "sqli": SQLiScanner,
        "xss": XSSScanner,
        "lfi": LFIScanner,
        "redir": RedirectScanner,
        "headers": HeaderScanner,
        "rate": RateLimitScanner,
        "waf": WAFScanner,
        "ssti": SSTIScanner,
        "crlf": CRLFScanner,
        "methods": MethodsScanner,
        "dirscan": DirectoryScanner,
    }

    if modules_str == "all":
        return list(all_modules.values())

    selected = []
    for name in modules_str.split(","):
        n = name.strip().lower()
        if n in all_modules:
            selected.append(all_modules[n])
    return selected


def main():
    args = parse_args()

    session = make_session()
    if args.cookies:
        for part in args.cookies.split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                session.cookies.set(k.strip(), v.strip())

    logger = Logger(args.log_dir)
    report = Report(args.url)

    logger.log(f"[START] Target: {args.url}")
    logger.log(f"[START] Depth: {args.depth}, Threads: {args.threads}")
    logger.log(f"[START] Modules: {args.modules}")

    scanner_classes = build_scanner_class_list(args.modules)

    run_scan(
        base_url=args.url,
        session=session,
        logger=logger,
        report=report,
        scanner_classes=scanner_classes,
        depth=args.depth,
        threads=args.threads,
    )

    report.write_markdown(args.report_md)
    report.write_html(args.report_html)

    logger.log(f"[REPORT] Markdown: {args.report_md}")
    logger.log(f"[REPORT] HTML: {args.report_html}")
    logger.log(f"[LOG] Full log at {logger.log_path}")
    logger.log("[DONE] Scan completed.")
    logger.close()


if __name__ == "__main__":
    main()
