from __future__ import annotations

from threading import Lock

from znuzhgfw.core.scanner_base import ScannerBase
from znuzhgfw.core.utils import ScanContext


class WAFScanner(ScannerBase):
    WAF_PATTERNS = {
        "akamai": ["akamai", "akamai-ghost"],
        "cloudflare": ["cloudflare", "cf-ray", "__cf_bm"],
        "mod_security": ["mod_security"],
        "sucuri": ["sucuri", "x-sucuri-id"],
    }

    def __init__(self, session, logger, report, config=None):
        super().__init__(session, logger, report, config)
        self._scanned_hosts: set[str] = set()
        self._lock = Lock()

    def should_scan(self, context: ScanContext) -> bool:
        return context.is_document

    def _mark_host(self, host_url: str) -> bool:
        with self._lock:
            if host_url in self._scanned_hosts:
                return False
            self._scanned_hosts.add(host_url)
            return True

    def scan(
        self,
        url: str,
        html: str | None = None,
        context: ScanContext | None = None,
    ) -> None:
        if context is None or not self._mark_host(context.target.host_url):
            return

        self.logger.log(f"[WAF] Probing {context.target.host_url}")
        text = (context.text or "").lower()
        headers = (
            {key.lower(): value.lower() for key, value in context.response.headers.items()}
            if context.response is not None
            else {}
        )
        detected: list[str] = []

        for waf_name, patterns in self.WAF_PATTERNS.items():
            if any(pattern in text for pattern in patterns):
                detected.append(waf_name)
                continue
            if any(
                pattern in header_key or pattern in header_value
                for pattern in patterns
                for header_key, header_value in headers.items()
            ):
                detected.append(waf_name)

        if not detected:
            return

        self.report.add(
            severity="INFO",
            title="WAF detection",
            url=context.target.host_url,
            normalized_url=context.target.host_url,
            detail="Headers or response content match known WAF fingerprints.",
            category="WAF Detection",
            scanner="WAFScanner",
            evidence={"detected": sorted(set(detected))},
            confidence="MEDIUM",
            proof_level="heuristic",
            tags=["host-summary", "waf"],
            fingerprint=f"waf:{context.target.host}",
        )
