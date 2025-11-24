import time

from znuzhgfw.core.scanner_base import ScannerBase


class RateLimitScanner(ScannerBase):
    def __init__(self, session, logger, report, attempts: int = 8):
        super().__init__(session, logger, report)
        self.attempts = attempts

    def scan(self, url: str, html: str | None = None):
        self.logger.log(f"[RATE] Testing rate limit for {url}")
        codes = []
        for _ in range(self.attempts):
            try:
                r = self.session.get(url, verify=False, timeout=10)
                codes.append(r.status_code)
            except Exception as e:
                self.logger.log(f"[RATE] Error {url}: {e}")
            time.sleep(0.1)

        if 429 in codes or 403 in codes:
            detail = f"Status codes: {codes}"
            self.report.add(
                severity="low",
                title="Rate limiting / throttling present",
                url=url,
                detail=detail,
                category="Rate Limiting",
                scanner="RateLimitScanner",
            )
        else:
            detail = f"No clear rate limiting detected. Status codes: {codes}"
            self.report.add(
                severity="info",
                title="No rate limiting detected",
                url=url,
                detail=detail,
                category="Rate Limiting",
                scanner="RateLimitScanner",
            )
RateLmtScanner = RateLimitScanner
