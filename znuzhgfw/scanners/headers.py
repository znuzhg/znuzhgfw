from __future__ import annotations

from znuzhgfw.core.scanner_base import ScannerBase
from znuzhgfw.core.utils import ScanContext


class HeaderScanner(ScannerBase):
    asset_scan_enabled = True

    SECURITY_HEADERS = (
        "Content-Security-Policy",
        "Referrer-Policy",
        "Strict-Transport-Security",
        "X-Content-Type-Options",
        "X-Frame-Options",
    )

    def should_scan(self, context: ScanContext) -> bool:
        return not self.config.skip_headers and (
            context.is_document or (context.is_static and self.config.scan_assets)
        )

    def scan(
        self,
        url: str,
        html: str | None = None,
        context: ScanContext | None = None,
    ) -> None:
        if context is None or context.response is None:
            return

        response = context.response
        host_url = context.target.host_url
        scheme = context.target.scheme
        scope = "asset" if context.is_static else "document"
        self.logger.log(
            f"[HEADERS] Checking security headers for {context.target.normalized_url}"
        )

        for header_name in self.SECURITY_HEADERS:
            if header_name == "Strict-Transport-Security" and scheme != "https":
                continue
            if header_name in response.headers:
                continue

            self.report.add(
                severity="INFO" if scope == "asset" else "LOW",
                title="Missing Security Header",
                url=host_url if scope == "document" else context.target.normalized_url,
                normalized_url=host_url if scope == "document" else context.target.normalized_url,
                detail=(
                    f"{header_name} is missing on {scope} responses from {context.target.host}. "
                    "Document responses remain the primary security signal."
                ),
                category="Security Headers",
                scanner="HeaderScanner",
                evidence={
                    "header": header_name,
                    "host": context.target.host,
                    "example_url": context.target.normalized_url,
                    "scope": scope,
                },
                confidence="HIGH",
                proof_level="verified",
                tags=[f"{scope}-response", "host-summary"],
                fingerprint=f"header:{context.target.host}:{header_name}:{scope}",
                example_urls=[context.target.normalized_url],
            )
