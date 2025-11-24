from urllib.parse import urlparse, parse_qs, urlencode

from znuzhgfw.core.payloads import SSTI_PAYLOADS
from znuzhgfw.core.scanner_base import ScannerBase


class SSTIScanner(ScannerBase):
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
        self.logger.log(f"[SSTI] Testing {url}")
        for param in qs.keys():
            for payload in SSTI_PAYLOADS:
                try:
                    inj_url = self._inject(url, param, payload)
                    r = self.session.get(inj_url, verify=False, timeout=10)
                except Exception as e:
                    self.logger.log(f"[SSTI] Error {url}: {e}")
                    continue

                if "49" in r.text or "34359738368" in r.text or "49.0" in r.text:
                    detail = f"Param: {param}\nPayload: {payload}\nPossible SSTI pattern found."
                    self.report.add(
                        severity="medium",
                        title="SSTI suspicion",
                        url=inj_url,
                        detail=detail,
                        category="Server-Side Template Injection",
                        scanner="SSTIScanner",
                    )
