from znuzhgfw.core.scanner_base import ScannerBase


class WAFScanner(ScannerBase):
    WAF_PATTERNS = {
        "cloudflare": ["cloudflare", "cf-ray", "__cf_bm"],
        "sucuri": ["sucuri", "x-sucuri-id"],
        "mod_security": ["mod_security"],
        "akamai": ["akamai-ghost", "akamai"],
    }

    def scan(self, url: str, html: str | None = None):
        self.logger.log(f"[WAF] Probing {url}")
        if html is None:
            try:
                r = self.session.get(url, verify=False, timeout=10)
                html = r.text
                headers = r.headers
            except Exception as e:
                self.logger.log(f"[WAF] Error {url}: {e}")
                return
        else:
            try:
                r = self.session.get(url, verify=False, timeout=10)
                headers = r.headers
            except Exception:
                headers = {}

        text_lower = html.lower()
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        detected = []

        for waf, patterns in self.WAF_PATTERNS.items():
            for p in patterns:
                if p in text_lower:
                    detected.append(waf)
                    break
                if any(p in k or p in v for k, v in headers_lower.items()):
                    detected.append(waf)
                    break

        if detected:
            detail = f"Possible WAF detected: {', '.join(set(detected))}"
            self.report.add(
                severity="info",
                title="WAF detection",
                url=url,
                detail=detail,
                category="WAF Detection",
                scanner="WAFScanner",
            )
