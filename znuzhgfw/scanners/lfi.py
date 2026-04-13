from __future__ import annotations

from znuzhgfw.core.payloads import LFI_PAYLOADS
from znuzhgfw.core.scanner_base import ScannerBase
from znuzhgfw.core.utils import (
    ScanContext,
    get_query_params,
    inject_param_to_url,
    is_candidate_param,
    normalize_url,
)


PRIMARY_PATTERNS = ("root:x:0:0", "[extensions]")
SECONDARY_PATTERNS = ("daemon:", "/bin/", "[fonts]", "[mci extensions]")


class LFIScanner(ScannerBase):
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

        baseline_text = (context.text or "").lower() if context else ""
        self.logger.log(f"[LFI] Testing {normalize_url(url)}")

        for param in params:
            if not is_candidate_param(param, "lfi"):
                continue
            for payload in LFI_PAYLOADS:
                injected_url = inject_param_to_url(url, param, payload)
                try:
                    response = self.session.get(injected_url, verify=False, timeout=10)
                except Exception as exc:
                    self.logger.log(f"[LFI] Error {url}: {exc}")
                    continue

                body = response.text.lower()
                if body == baseline_text:
                    continue

                primary_hits = [
                    marker
                    for marker in PRIMARY_PATTERNS
                    if marker in body and marker not in baseline_text
                ]
                if not primary_hits:
                    continue

                secondary_hits = [
                    marker
                    for marker in SECONDARY_PATTERNS
                    if marker in body and marker not in baseline_text
                ]
                verified = bool(secondary_hits)

                self.report.add(
                    severity="HIGH" if verified else "MEDIUM",
                    title="LFI / path traversal likely" if verified else "LFI / path traversal suspicion",
                    url=injected_url,
                    normalized_url=normalize_url(url),
                    detail=(
                        "Response contains file disclosure markers that were absent from the baseline response."
                    ),
                    category="File Inclusion",
                    scanner="LFIScanner",
                    evidence={
                        "param": param,
                        "payload": payload,
                        "primary_hits": primary_hits,
                        "secondary_hits": secondary_hits,
                        "status_code": response.status_code,
                    },
                    confidence="HIGH" if verified else "MEDIUM",
                    proof_level="verified" if verified else "reflected",
                    tags=["lfi", "path-traversal"],
                    param=param,
                    payload=payload,
                )
                break
