from urllib.parse import urlparse, parse_qs, urlencode

from znuzhgfw.core.payloads import CRLF_PAYLOADS
from znuzhgfw.core.scanner_base import ScannerBase


class CRLFScanner(ScannerBase):
    def _inject(self, url: str, param: str, payload: str) -> str:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        if not qs:
            return url
        qs[param] = [payload]
        new_q = urlencode(qs, doseq=True)
        return parsed._replace(query=new_q).geturl()

    def scan(self, url: str, html: str | None = None):
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        if not qs:
            return
        self.logger.log(f"[CRLF] Testing {url}")
        for param in qs.keys():
            for payload in CRLF_PAYLOADS:
                try:
                    inj_url = self._inject(url, param, payload)
                    r = self.session.get(
                        inj_url, verify=False, timeout=10, allow_redirects=False
                    )
                except Exception as e:
                    self.logger.log(f"[CRLF] Error {url}: {e}")
                    continue

                # Header injection tespiti için kaba kontrol:
                headers_text = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
                if "X-Evil:1" in headers_text or "crlf=1" in headers_text:
                    detail = f"Param: {param}\nPayload: {payload}\nInjected header pattern seen."
                    self.report.add(
                        severity="medium",
                        title="CRLF Injection suspicion",
                        url=inj_url,
                        detail=detail,
                        category="CRLF Injection",
                        scanner="CRLFScanner",
                    )
