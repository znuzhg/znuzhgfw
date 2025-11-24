from znuzhgfw.core.scanner_base import ScannerBase


class MethodsScanner(ScannerBase):
    def scan(self, url: str, html: str | None = None):
        self.logger.log(f"[METHODS] Checking HTTP methods for {url}")
        try:
            r = self.session.options(url, verify=False, timeout=10)
        except Exception as e:
            self.logger.log(f"[METHODS] OPTIONS error {url}: {e}")
            return

        allow = r.headers.get("Allow", "")
        if allow:
            detail = f"Allow header: {allow}"
            self.report.add(
                severity="info",
                title="HTTP Methods",
                url=url,
                detail=detail,
                category="HTTP Methods",
                scanner="MethodsScanner",
            )

        # TRACE denemesi
        try:
            r_trace = self.session.request("TRACE", url, verify=False, timeout=10)
            if r_trace.status_code < 400:
                detail = f"TRACE method allowed. Status: {r_trace.status_code}"
                self.report.add(
                    severity="low",
                    title="TRACE method enabled",
                    url=url,
                    detail=detail,
                    category="HTTP Methods",
                    scanner="MethodsScanner",
                )
        except Exception:
            pass
MethodScanner = MethodsScanner
