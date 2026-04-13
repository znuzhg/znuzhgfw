from __future__ import annotations

import concurrent.futures
from typing import Iterable, Type

import requests
import urllib3

from .crawler import Crawler
from .logger import Logger
from .report import Report
from .scanner_base import ScannerBase
from .utils import ScanConfig, build_context, should_scan_target

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def scan_target(
    target,
    session: requests.Session,
    scanners: list[ScannerBase],
    logger: Logger,
    report: Report,
    config: ScanConfig,
) -> None:
    logger.log(
        f"[CORE] Fetching {target.normalized_url} for scanners (category={target.category})"
    )
    try:
        response = session.get(target.url, verify=False, timeout=10)
    except Exception as exc:
        logger.log(f"[CORE] Error fetching {target.url}: {exc}")
        return

    context = build_context(
        target.url,
        response,
        depth=target.depth,
        strip_tracking=config.strip_tracking_params,
    )
    report.record_discovered(context.target)
    report.record_scanned_target(context.target.normalized_url)

    if not should_scan_target(context.target, config):
        logger.log(
            f"[CORE] Skipping active scanners for {context.target.normalized_url} "
            f"(category={context.target.category})"
        )
        return

    for scanner in scanners:
        try:
            if not scanner.can_scan_context(context):
                continue
            if not scanner.should_scan(context):
                continue
            scanner.scan(context.target.url, html=context.html, context=context)
        except Exception as exc:
            logger.log(
                f"[CORE] Error in scanner {scanner.__class__.__name__} "
                f"for {context.target.normalized_url}: {exc}"
            )


def _record_discovered(report: Report, targets: Iterable) -> None:
    for target in targets:
        report.record_discovered(target)


def run_scan(
    base_url: str,
    session: requests.Session,
    logger: Logger,
    report: Report,
    scanner_classes: list[Type[ScannerBase]],
    depth: int = 1,
    threads: int = 5,
    *,
    config: ScanConfig | None = None,
) -> None:
    scan_config = config or ScanConfig()
    crawler = Crawler(
        session,
        base_url,
        logger,
        max_depth=depth,
        config=scan_config,
    )
    targets = crawler.crawl()
    _record_discovered(report, crawler.discovered.values())

    scanners = [cls(session, logger, report, scan_config) for cls in scanner_classes]

    logger.log(
        f"[CORE] Starting scan on {len(targets)} URLs with {threads} threads"
    )

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [
            executor.submit(
                scan_target,
                target,
                session,
                scanners,
                logger,
                report,
                scan_config,
            )
            for target in targets
        ]
        for future in concurrent.futures.as_completed(futures):
            future.result()

    logger.log("[CORE] Scan finished")
