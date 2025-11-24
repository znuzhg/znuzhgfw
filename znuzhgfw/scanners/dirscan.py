from urllib.parse import urljoin, urlparse

from znuzhgfw.core.payloads import COMMON_PATHS
from znuzhgfw.core.scanner_base import ScannerBase


class DirectoryScanner(ScannerBase):
    def scan(self, url: str, html: str | None = None):
        base = url
        parsed = urlparse(url)
        if parsed.path and parsed.path != "/":
            base = f"{parsed.scheme}://{parsed.netloc}"
        self.logger.log(f"[DIR] Scanning common paths at {base}")
        for path in COMMON_PATHS:
            target = urljoin(base, path)
            try:
                r = self.session.get(target, verify=False, timeout=10)
            except Exception as e:
                self.logger.log(f"[DIR] Error {target}: {e}")
                continue

            if r.status_code < 400:
                detail = f"Found accessible path: {target} (status {r.status_code})"
                self.report.add(
                    severity="low",
                    title="Interesting directory / file",
                    url=target,
                    detail=detail,
                    category="Content Discovery",
                    scanner="DirectoryScanner",
                )
DrScanScanner = DirectoryScanner
