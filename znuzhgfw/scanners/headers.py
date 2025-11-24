from znuzhgfw.core.scanner_base import ScannerBase


class HeaderScanner(ScannerBase):
    SECURITY_HEADERS = [
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "Strict-Transport-Security",
    ]

    def scan(self, url: str, html: str | None = None):
        self.logger.log(f"[HEADERS] Checking security headers for {url}")
        try:
            r = self.session.get(url, verify=False, timeout=10)
        except Exception as e:
            self.logger.log(f"[HEADERS] Error {url}: {e}")
            return

        for h in self.SECURITY_HEADERS:
            if h not in r.headers:
                detail = f"Missing security header: {h}"
                self.report.add(
                    severity="low",
                    title="Missing Security Header",
                    url=url,
                    detail=detail,
                    category="Security Headers",
                    scanner="HeaderScanner",
                )
