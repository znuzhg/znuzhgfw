import concurrent.futures
from typing import List, Type

import requests
import urllib3

from .crawler import Crawler
from .logger import Logger
from .report import Report
from .scanner_base import ScannerBase

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def scan_url(url: str, session: requests.Session, scanners: List[ScannerBase], logger: Logger):
    """
    Tek bir URL üzerinde tüm scanner modüllerini çalıştırır.
    HTML'i bir kere çekip scanner'lara geçirir (performans).
    """
    logger.log(f"[CORE] Fetching {url} for scanners")
    html = ""
    try:
        resp = session.get(url, verify=False, timeout=10)
        html = resp.text
    except Exception as e:
        logger.log(f"[CORE] Error fetching {url}: {e}")
        return

    for scanner in scanners:
        try:
            scanner.scan(url, html=html)
        except Exception as e:
            logger.log(
                f"[CORE] Error in scanner {scanner.__class__.__name__} "
                f"for {url}: {e}"
            )


def run_scan(
    base_url: str,
    session: requests.Session,
    logger: Logger,
    report: Report,
    scanner_classes: List[Type[ScannerBase]],
    depth: int = 1,
    threads: int = 5,
):
    crawler = Crawler(session, base_url, logger, max_depth=depth)
    urls = crawler.crawl()

    scanners = [cls(session, logger, report) for cls in scanner_classes]

    logger.log(f"[CORE] Starting scan on {len(urls)} URLs with {threads} threads")

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as exe:
        futures = [
            exe.submit(scan_url, url, session, scanners, logger) for url in urls
        ]
        for f in concurrent.futures.as_completed(futures):
            _ = f.result()

    logger.log("[CORE] Scan finished")
