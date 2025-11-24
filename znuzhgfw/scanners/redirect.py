from urllib.parse import urlparse, parse_qs, urlencode

from znuzhgfw.core.payloads import REDIRECT_PAYLOADS
from znuzhgfw.core.scanner_base import ScannerBase


class RedirectScanner(ScannerBase):
    def _inject(self, url: str, param: str, payload: str) -> str:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        qs[param] = [payload]
        new_q = urlencode(qs, doseq=True)
        return parsed._replace(query=new_q).geturl()

    def scan(self, url: str, html: str | None = None):
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        if not qs:
            return
        self.logger.log(f"[REDIR] Testing {url}")
        for param in qs.keys():
            for payload in REDIRECT_PAYLOADS:
                try:
                    inj_url = self._inject(url, param, payload)
                    r = self.session.get(
                        inj_url, verify=False, timeout=10, allow_redirects=False
                    )
                except Exception as e:
                    self.logger.log(f"[REDIR] Error {url}: {e}")
                    continue
                loc = r.headers.get("Location", "")
                if "example.com" in loc:
                    detail = f"Param: {param}\nPayload: {payload}\nLocation: {loc}"
                    self.report.add(
                        severity="medium",
                        title="Open Redirect suspicion",
                        url=inj_url,
                        detail=detail,
                        category="Open Redirect",
                        scanner="RedirectScanner",
                    )
RedrectScanner = RedirectScanner
