from __future__ import annotations

from urllib.parse import urlsplit

from znuzhgfw.core.payloads import REDIRECT_PAYLOADS
from znuzhgfw.core.scanner_base import ScannerBase
from znuzhgfw.core.utils import (
    ScanContext,
    get_query_params,
    inject_param_to_url,
    is_candidate_param,
    normalize_url,
)


class RedirectScanner(ScannerBase):
    def should_scan(self, context: ScanContext) -> bool:
        return bool(context.target.query) and not context.is_static

    def scan(
        self,
        url: str,
        html: str | None = None,
        context: ScanContext | None = None,
    ) -> None:
        params = get_query_params(url)
        if not params:
            return

        baseline_location = (
            (context.response.headers.get("Location", "") if context and context.response else "")
        )
        baseline_host = urlsplit(baseline_location).netloc.lower()
        self.logger.log(f"[REDIR] Testing {normalize_url(url)}")
        for param in params:
            if not is_candidate_param(param, "redirect"):
                continue
            for payload in REDIRECT_PAYLOADS:
                injected_url = inject_param_to_url(url, param, payload)
                try:
                    response = self.session.get(
                        injected_url,
                        verify=False,
                        timeout=10,
                        allow_redirects=False,
                    )
                except Exception as exc:
                    self.logger.log(f"[REDIR] Error {url}: {exc}")
                    continue

                location = response.headers.get("Location", "")
                location_host = urlsplit(location).netloc.lower()
                if location_host != "example.com":
                    continue
                if baseline_host == location_host:
                    continue

                self.report.add(
                    severity="MEDIUM",
                    title="Open redirect likely",
                    url=injected_url,
                    normalized_url=normalize_url(url),
                    detail=(
                        "An external redirect target was introduced after injecting the redirect parameter."
                    ),
                    category="Open Redirect",
                    scanner="RedirectScanner",
                    evidence={
                        "param": param,
                        "payload": payload,
                        "baseline_location": baseline_location,
                        "location": location,
                        "status_code": response.status_code,
                    },
                    confidence="HIGH",
                    proof_level="verified",
                    tags=["redirect", "verified"],
                    param=param,
                    payload=payload,
                )
                break


RedrectScanner = RedirectScanner
