from urllib.parse import urlparse, parse_qs, urlencode

from znuzhgfw.core.payloads import LFI_PAYLOADS
from znuzhgfw.core.scanner_base import ScannerBase


class LFIScanner(ScannerBase):
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
        self.logger.log(f"[LFI] Testing {url}")
        for param in qs.keys():
            for payload in LFI_PAYLOADS:
                try:
                    inj_url = self._inject(url, param, payload)
                    r = self.session.get(inj_url, verify=False, timeout=10)
                except Exception as e:
                    self.logger.log(f"[LFI] Error {url}: {e}")
                    continue

                text = r.text.lower()
                if "root:x:0:0" in text or "[extensions]" in text:
                    detail = f"Param: {param}\nPayload: {payload}\nSuspicious file content pattern found."
                    self.report.add(
                        severity="high",
                        title="LFI / Path Traversal",
                        url=inj_url,
                        detail=detail,
                        category="File Inclusion",
                        scanner="LFIScanner",
                    )
