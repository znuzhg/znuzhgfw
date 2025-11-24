import re
from urllib.parse import urljoin, urlparse

import requests

from .logger import Logger


class Crawler:
    def __init__(self, session: requests.Session, base_url: str, logger: Logger, max_depth: int = 1):
        self.session = session
        self.base_url = base_url
        self.logger = logger
        self.max_depth = max_depth
        self.visited = set()
        self.urls = []

    def same_domain(self, url: str) -> bool:
        return urlparse(url).netloc == urlparse(self.base_url).netloc

    def extract_links(self, html: str, current_url: str):
        links = re.findall(r'href=["\'](.*?)["\']', html, re.IGNORECASE)
        out = []
        for link in links:
            if link.startswith("#") or link.lower().startswith("javascript:"):
                continue
            full = urljoin(current_url, link)
            if self.same_domain(full):
                out.append(full.split("#")[0])
        return out

    def crawl(self):
        self.logger.log(f"[CRAWLER] Starting crawl from {self.base_url}, depth={self.max_depth}")
        queue = [(self.base_url, 0)]
        self.visited.add(self.base_url)

        while queue:
            url, depth = queue.pop(0)
            self.logger.log(f"[CRAWLER] Fetching {url} (depth {depth})")
            try:
                resp = self.session.get(url, verify=False, timeout=10)
            except Exception as e:
                self.logger.log(f"[CRAWLER] Error fetching {url}: {e}")
                continue

            self.urls.append(url)

            if depth >= self.max_depth:
                continue

            if "text/html" in resp.headers.get("Content-Type", ""):
                links = self.extract_links(resp.text, url)
                for link in links:
                    if link not in self.visited:
                        self.visited.add(link)
                        queue.append((link, depth + 1))

        self.logger.log(f"[CRAWLER] Finished. Total URLs collected: {len(self.urls)}")
        return self.urls
