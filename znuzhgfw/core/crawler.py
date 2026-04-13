from __future__ import annotations

from collections import deque
from urllib.parse import urljoin, urlsplit

import requests
from bs4 import BeautifulSoup

from .logger import Logger
from .utils import (
    ScanConfig,
    URLInfo,
    classify_url,
    is_placeholder_url,
    normalize_url,
    response_is_html,
    should_enqueue_url,
)


class Crawler:
    def __init__(
        self,
        session: requests.Session,
        base_url: str,
        logger: Logger,
        max_depth: int = 1,
        *,
        config: ScanConfig | None = None,
    ):
        self.session = session
        self.base_url = base_url
        self.logger = logger
        self.max_depth = max_depth
        self.config = config or ScanConfig()
        self.base_normalized = normalize_url(
            base_url,
            strip_tracking=self.config.strip_tracking_params,
        )
        self.base_host = urlsplit(self.base_normalized).netloc
        self.visited: set[str] = set()
        self.queued: set[str] = set()
        self.discovered: dict[str, URLInfo] = {}
        self.targets: list[URLInfo] = []

    def same_domain(self, url: str) -> bool:
        return urlsplit(normalize_url(url, strip_tracking=self.config.strip_tracking_params)).netloc == self.base_host

    def _store_discovered(self, target: URLInfo) -> None:
        self.discovered.setdefault(target.normalized_url, target)

    def extract_links(self, html: str, current_url: str, depth: int) -> list[URLInfo]:
        soup = BeautifulSoup(html or "", "html.parser")
        out: list[URLInfo] = []
        seen: set[str] = set()
        selectors = (
            ("a", "href"),
            ("form", "action"),
            ("iframe", "src"),
            ("img", "src"),
            ("link", "href"),
            ("script", "src"),
            ("source", "src"),
        )

        for tag_name, attr in selectors:
            for tag in soup.find_all(tag_name):
                raw_link = (tag.get(attr) or "").strip()
                if is_placeholder_url(raw_link):
                    continue

                full_url = urljoin(current_url, raw_link)
                if not self.same_domain(full_url):
                    continue

                target = classify_url(
                    full_url,
                    depth=depth + 1,
                    strip_tracking=self.config.strip_tracking_params,
                )
                if target.normalized_url in seen:
                    continue
                seen.add(target.normalized_url)
                out.append(target)

        return out

    def _enqueue(self, queue: deque[tuple[URLInfo, int]], target: URLInfo, depth: int, *, is_base_target: bool = False) -> None:
        if target.normalized_url in self.queued:
            return
        if self.config.max_urls is not None and len(self.queued) >= self.config.max_urls:
            return
        if not should_enqueue_url(target, self.config, is_base_target=is_base_target):
            self._store_discovered(target)
            return

        self.queued.add(target.normalized_url)
        self._store_discovered(target)
        queue.append((target, depth))

    def crawl(self) -> list[URLInfo]:
        self.logger.log(
            f"[CRAWLER] Starting crawl from {self.base_url}, depth={self.max_depth}"
        )
        queue: deque[tuple[URLInfo, int]] = deque()
        base_target = classify_url(
            self.base_url,
            depth=0,
            strip_tracking=self.config.strip_tracking_params,
        )
        self._enqueue(queue, base_target, 0, is_base_target=True)

        while queue:
            target, depth = queue.popleft()
            if target.normalized_url in self.visited:
                continue

            self.visited.add(target.normalized_url)
            self.targets.append(target)
            self.logger.log(
                f"[CRAWLER] Fetching {target.normalized_url} (depth {depth}, category={target.category})"
            )

            try:
                response = self.session.get(
                    target.url,
                    verify=False,
                    timeout=10,
                )
            except Exception as exc:
                self.logger.log(f"[CRAWLER] Error fetching {target.url}: {exc}")
                continue

            enriched_target = classify_url(
                target.url,
                content_type=response.headers.get("Content-Type", ""),
                depth=depth,
                strip_tracking=self.config.strip_tracking_params,
            )
            self.targets[-1] = enriched_target
            self.discovered[enriched_target.normalized_url] = enriched_target

            if depth >= self.max_depth or not response_is_html(response.headers.get("Content-Type", "")):
                continue

            for child in self.extract_links(response.text, target.url, depth):
                self._store_discovered(child)
                if child.normalized_url in self.visited:
                    continue
                self._enqueue(queue, child, depth + 1)

        self.logger.log(
            "[CRAWLER] Finished. "
            f"Scannable URLs collected: {len(self.targets)} | Discovered URLs: {len(self.discovered)}"
        )
        return self.targets
