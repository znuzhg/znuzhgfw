import re
from urllib.parse import urlparse, parse_qs, urlencode

from znuzhgfw.core.payloads import XSS_PAYLOADS, DOM_XSS_PATTERNS
from znuzhgfw.core.scanner_base import ScannerBase


class XSSScanner(ScannerBase):
    def _inject(self, url: str, param: str, payload: str) -> str:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        if not qs:
            return url
        qs[param] = [payload]
        new_q = urlencode(qs, doseq=True)
        return parsed._replace(query=new_q).geturl()

    def _test_get_xss(self, url: str):
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        if not qs:
            return
        self.logger.log(f"[XSS] Testing GET params for {url}")
        for param in qs.keys():
            for payload in XSS_PAYLOADS:
                try:
                    inj_url = self._inject(url, param, payload)
                    r = self.session.get(inj_url, verify=False, timeout=10)
                except Exception as e:
                    self.logger.log(f"[XSS] Error {url}: {e}")
                    continue

                if payload in r.text:
                    detail = f"Param: {param}\nPayload reflected in response.\nPayload: {payload}"
                    self.report.add(
                        severity="medium",
                        title="Reflected XSS suspicion",
                        url=inj_url,
                        detail=detail,
                        category="Cross-Site Scripting",
                        scanner="XSSScanner",
                    )

    def _test_dom_xss(self, url: str, html: str):
        for pattern in DOM_XSS_PATTERNS:
            if re.search(pattern, html):
                detail = f"Pattern: {pattern}\nThis may indicate DOM-based XSS sinks."
                self.report.add(
                    severity="low",
                    title="DOM XSS sink present",
                    url=url,
                    detail=detail,
                    category="Cross-Site Scripting",
                    scanner="XSSScanner",
                )

    def scan(self, url: str, html: str | None = None):
        self._test_get_xss(url)
        if html:
            self._test_dom_xss(url, html)
