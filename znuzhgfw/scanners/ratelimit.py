from __future__ import annotations

import time
from hashlib import sha1

from znuzhgfw.core.scanner_base import ScannerBase
from znuzhgfw.core.utils import ScanContext, is_rate_limit_candidate, response_is_text_like


THROTTLE_KEYWORDS = ("rate limit", "too many requests", "throttl")


class RateLimitScanner(ScannerBase):
    def __init__(self, session, logger, report, config=None, attempts: int = 10):
        super().__init__(session, logger, report, config)
        self.attempts = attempts

    def should_scan(self, context: ScanContext) -> bool:
        return not self.config.skip_rate_limit and is_rate_limit_candidate(context.target)

    def _body_signature(self, response) -> str:
        content_type = response.headers.get("Content-Type", "")
        if not response_is_text_like(content_type):
            return ""
        try:
            body = response.text[:2048]
        except Exception:
            return ""
        return sha1(body.encode("utf-8", errors="ignore")).hexdigest()

    def scan(
        self,
        url: str,
        html: str | None = None,
        context: ScanContext | None = None,
    ) -> None:
        if context is None:
            return

        self.logger.log(f"[RATE] Testing rate limit for {context.target.normalized_url}")
        status_codes: list[int] = []
        body_signatures: list[str] = []
        header_signal = False
        throttle_keyword_seen = False

        for attempt in range(self.attempts):
            try:
                response = (
                    context.response
                    if attempt == 0 and context.response is not None
                    else self.session.get(url, verify=False, timeout=10)
                )
            except Exception as exc:
                self.logger.log(f"[RATE] Error {url}: {exc}")
                continue

            status_codes.append(response.status_code)
            header_signal = header_signal or (
                "Retry-After" in response.headers
                or any(header.lower().startswith("x-ratelimit") for header in response.headers)
            )
            body_signature = self._body_signature(response)
            if body_signature:
                body_signatures.append(body_signature)

            try:
                body_lower = response.text.lower()[:2048]
            except Exception:
                body_lower = ""
            throttle_keyword_seen = throttle_keyword_seen or any(
                keyword in body_lower for keyword in THROTTLE_KEYWORDS
            )
            time.sleep(0.05)

        if not status_codes:
            return

        status_change = len(set(status_codes)) > 1
        body_variants = len(set(body_signatures)) if body_signatures else 0
        behavior_throttle = (
            429 in status_codes
            or throttle_keyword_seen
            or (
                status_change
                and any(code in {403, 429, 503} for code in status_codes[1:])
            )
        )

        if behavior_throttle:
            self.report.add(
                severity="INFO",
                title="Rate limiting enforced",
                url=context.target.normalized_url,
                normalized_url=context.target.normalized_url,
                detail=(
                    "Repeated requests triggered observable throttling behavior."
                ),
                category="Rate Limiting",
                scanner="RateLimitScanner",
                evidence={
                    "status_codes": status_codes,
                    "header_signal": header_signal,
                    "throttle_keyword_seen": throttle_keyword_seen,
                    "body_variants": body_variants,
                    "requests_sent": len(status_codes),
                },
                confidence="HIGH",
                proof_level="verified",
                tags=["rate-limit", "observed"],
            )
            return

        if header_signal:
            self.report.add(
                severity="INFO",
                title="Rate limiting headers advertised",
                url=context.target.normalized_url,
                normalized_url=context.target.normalized_url,
                detail=(
                    "Rate limiting headers were observed, but request bursts did not trigger throttling behavior."
                ),
                category="Rate Limiting",
                scanner="RateLimitScanner",
                evidence={
                    "status_codes": status_codes,
                    "header_signal": header_signal,
                    "body_variants": body_variants,
                    "requests_sent": len(status_codes),
                },
                confidence="MEDIUM",
                proof_level="heuristic",
                tags=["rate-limit", "headers-only"],
            )
            return

        severity = "LOW" if "auth-endpoint" in context.target.tags else "INFO"
        confidence = "MEDIUM" if "auth-endpoint" in context.target.tags else "LOW"
        self.report.add(
            severity=severity,
            title="No rate limiting detected on meaningful endpoint",
            url=context.target.normalized_url,
            normalized_url=context.target.normalized_url,
            detail=(
                "Repeated requests to a meaningful endpoint did not trigger throttling headers or observable throttling behavior."
            ),
            category="Rate Limiting",
            scanner="RateLimitScanner",
            evidence={
                "status_codes": status_codes,
                "header_signal": header_signal,
                "body_variants": body_variants,
                "requests_sent": len(status_codes),
            },
            confidence=confidence,
            proof_level="heuristic",
            tags=["rate-limit", "meaningful-endpoint"],
        )


RateLmtScanner = RateLimitScanner
