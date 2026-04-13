from __future__ import annotations

from znuzhgfw.core.payloads import CRLF_PAYLOADS
from znuzhgfw.core.scanner_base import ScannerBase
from znuzhgfw.core.utils import (
    ScanContext,
    get_query_params,
    inject_param_to_url,
    is_candidate_param,
    normalize_url,
)


class CRLFScanner(ScannerBase):
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

        baseline_headers = (
            {key.lower(): value for key, value in context.response.headers.items()}
            if context is not None and context.response is not None
            else {}
        )
        self.logger.log(f"[CRLF] Testing {normalize_url(url)}")
        for param in params:
            if not is_candidate_param(param):
                continue
            for payload in CRLF_PAYLOADS:
                injected_url = inject_param_to_url(url, param, payload)
                try:
                    response = self.session.get(
                        injected_url,
                        verify=False,
                        timeout=10,
                        allow_redirects=False,
                    )
                except Exception as exc:
                    self.logger.log(f"[CRLF] Error {url}: {exc}")
                    continue

                candidate_headers = {
                    key.lower(): value for key, value in response.headers.items()
                }
                new_headers: list[str] = []
                for header_name in ("x-evil", "set-cookie"):
                    baseline_value = baseline_headers.get(header_name, "")
                    candidate_value = candidate_headers.get(header_name, "")
                    if candidate_value and candidate_value != baseline_value:
                        new_headers.append(f"{header_name}: {candidate_value}")

                if not new_headers:
                    continue

                self.report.add(
                    severity="MEDIUM",
                    title="CRLF injection likely",
                    url=injected_url,
                    normalized_url=normalize_url(url),
                    detail="Injected header markers were introduced after the CRLF payload.",
                    category="CRLF Injection",
                    scanner="CRLFScanner",
                    evidence={
                        "param": param,
                        "payload": payload,
                        "new_headers": new_headers,
                        "status_code": response.status_code,
                    },
                    confidence="HIGH",
                    proof_level="verified",
                    tags=["crlf", "verified"],
                    param=param,
                    payload=payload,
                )
                break
